#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::UnixdConfig;
use kanidm_unix_common::unix_passwd::{parse_etc_group, parse_etc_passwd, parse_etc_shadow, EtcDb};
use kanidm_unix_common::unix_proto::{
    HomeDirectoryInfo, TaskRequest, TaskRequestFrame, TaskResponse,
};
use kanidm_utils_users::{get_effective_gid, get_effective_uid};
use libc::{lchown, umask};
use notify_debouncer_full::notify::RecommendedWatcher;
use notify_debouncer_full::Debouncer;
use notify_debouncer_full::RecommendedCache;
use notify_debouncer_full::{new_debouncer, notify::RecursiveMode, DebouncedEvent};
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use std::{fs, io};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::sync::watch;
use tokio::time;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::instrument;
use walkdir::WalkDir;

#[cfg(all(target_family = "unix", feature = "selinux"))]
use kanidm_unix_common::selinux_util;

struct TaskCodec;

impl Decoder for TaskCodec {
    type Error = io::Error;
    type Item = TaskRequestFrame;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<TaskRequestFrame>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<TaskResponse> for TaskCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TaskResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send request -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

impl TaskCodec {
    fn new() -> Self {
        TaskCodec
    }
}

fn chown(path: &Path, gid: u32) -> Result<(), String> {
    let path_os = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "Unable to create c-string".to_string())?;

    // Change the owner to the gid - remember, kanidm ONLY has gid's, the uid is implied.
    if unsafe { lchown(path_os.as_ptr(), gid, gid) } != 0 {
        return Err("Unable to set ownership".to_string());
    }
    Ok(())
}

fn create_home_directory(
    info: &HomeDirectoryInfo,
    home_prefix_path: &Path,
    home_mount_prefix_path: Option<&PathBuf>,
    use_etc_skel: bool,
    use_selinux: bool,
) -> Result<(), String> {
    // Final sanity check to prevent certain classes of attacks. This should *never*
    // be possible, but we assert this to be sure.
    let name = info.name.trim_start_matches('.').replace(['/', '\\'], "");

    debug!(?home_prefix_path, ?home_mount_prefix_path, ?info);

    // This is where the users home dir "is" and aliases from here go to the true storage
    // mounts
    let home_prefix_path = home_prefix_path
        .canonicalize()
        .map_err(|e| format!("{:?}", e))?;

    // This is where the storage is *mounted*. If not set, falls back to the home_prefix.
    let home_mount_prefix_path = home_mount_prefix_path
        .unwrap_or(&home_prefix_path)
        .canonicalize()
        .map_err(|e| format!("{:?}", e))?;

    // Does our home_prefix actually exist?
    if !home_prefix_path.exists() || !home_prefix_path.is_dir() || !home_prefix_path.is_absolute() {
        return Err("Invalid home_prefix from configuration - home_prefix path must exist, must be a directory, and must be absolute (not relative)".to_string());
    }

    if !home_mount_prefix_path.exists()
        || !home_mount_prefix_path.is_dir()
        || !home_mount_prefix_path.is_absolute()
    {
        return Err("Invalid home_mount_prefix from configuration - home_prefix path must exist, must be a directory, and must be absolute (not relative)".to_string());
    }

    // This is now creating the actual home directory in the home_mount path.
    // First we want to validate that the path is legitimate and hasn't tried
    // to escape the home_mount prefix.
    let hd_mount_path = Path::join(&home_mount_prefix_path, &name);

    debug!(?hd_mount_path);

    if let Some(pp) = hd_mount_path.parent() {
        if pp != home_mount_prefix_path {
            return Err("Invalid home directory name - not within home_mount_prefix".to_string());
        }
    } else {
        return Err("Invalid/Corrupt home directory path - no prefix found".to_string());
    }

    // Get a handle to the SELinux labeling interface
    debug!(?use_selinux, "selinux for home dir labeling");
    #[cfg(all(target_family = "unix", feature = "selinux"))]
    let labeler = if use_selinux {
        selinux_util::SelinuxLabeler::new(info.gid, &home_mount_prefix_path)?
    } else {
        selinux_util::SelinuxLabeler::new_noop()
    };

    // Does the home directory exist? This is checking the *true* home mount storage.
    if !hd_mount_path.exists() {
        // Set the SELinux security context for file creation
        #[cfg(all(target_family = "unix", feature = "selinux"))]
        labeler.do_setfscreatecon_for_path()?;

        // Set a umask
        let before = unsafe { umask(0o0027) };

        // Create the dir
        if let Err(e) = fs::create_dir_all(&hd_mount_path) {
            let _ = unsafe { umask(before) };
            error!(err = ?e, ?hd_mount_path, "Unable to create directory");
            return Err(format!("{:?}", e));
        }
        let _ = unsafe { umask(before) };

        chown(&hd_mount_path, info.gid)?;

        // Copy in structure from /etc/skel/ if present
        let skel_dir = Path::new("/etc/skel/");
        if use_etc_skel && skel_dir.exists() {
            info!("preparing homedir using /etc/skel");
            for entry in WalkDir::new(skel_dir).into_iter().filter_map(|e| e.ok()) {
                let dest = &hd_mount_path.join(
                    entry
                        .path()
                        .strip_prefix(skel_dir)
                        .map_err(|e| e.to_string())?,
                );

                #[cfg(all(target_family = "unix", feature = "selinux"))]
                {
                    let p = entry
                        .path()
                        .strip_prefix(skel_dir)
                        .map_err(|e| e.to_string())?;
                    labeler.label_path(p)?;
                }

                if entry.path().is_dir() {
                    fs::create_dir_all(dest).map_err(|e| {
                        error!(err = ?e, ?dest, "Unable to create directory from /etc/skel");
                        e.to_string()
                    })?;
                } else {
                    fs::copy(entry.path(), dest).map_err(|e| {
                        error!(err = ?e, ?dest, "Unable to copy from /etc/skel");
                        e.to_string()
                    })?;
                }
                chown(dest, info.gid)?;

                // Create equivalence rule in the SELinux policy
                #[cfg(all(target_family = "unix", feature = "selinux"))]
                labeler.setup_equivalence_rule(&hd_mount_path)?;
            }
        }
    }

    // Reset object creation SELinux context to default
    #[cfg(all(target_family = "unix", feature = "selinux"))]
    labeler.set_default_context_for_fs_objects()?;

    // Do the aliases exist?
    for alias in info.aliases.iter() {
        // Sanity check the alias.
        // let alias = alias.replace(".", "").replace("/", "").replace("\\", "");
        let alias = alias.trim_start_matches('.').replace(['/', '\\'], "");

        let alias_path = Path::join(&home_prefix_path, &alias);

        // Assert the resulting alias path is consistent and correct within the home_prefix.
        if let Some(pp) = alias_path.parent() {
            if pp != home_prefix_path {
                return Err("Invalid home directory alias - not within home_prefix".to_string());
            }
        } else {
            return Err("Invalid/Corrupt alias directory path - no prefix found".to_string());
        }

        if alias_path.exists() {
            debug!("checking symlink {:?} -> {:?}", alias_path, hd_mount_path);
            let attr = match fs::symlink_metadata(&alias_path) {
                Ok(a) => a,
                Err(e) => {
                    error!(err = ?e, ?alias_path, "Unable to read alias path metadata");
                    return Err(format!("{:?}", e));
                }
            };

            if attr.file_type().is_symlink() {
                // Probably need to update it.
                if let Err(e) = fs::remove_file(&alias_path) {
                    error!(err = ?e, ?alias_path, "Unable to remove existing alias path");
                    return Err(format!("{:?}", e));
                }

                debug!("updating symlink {:?} -> {:?}", alias_path, hd_mount_path);
                if let Err(e) = symlink(&hd_mount_path, &alias_path) {
                    error!(err = ?e, ?alias_path, "Unable to update alias path");
                    return Err(format!("{:?}", e));
                }
            } else {
                warn!(
                    ?alias_path,
                    ?hd_mount_path,
                    "home directory alias path is not a symlink, unable to update"
                );
            }
        } else {
            // Does not exist. Create.
            debug!("creating symlink {:?} -> {:?}", alias_path, hd_mount_path);
            if let Err(e) = symlink(&hd_mount_path, &alias_path) {
                error!(err = ?e, ?alias_path, "Unable to create alias path");
                return Err(format!("{:?}", e));
            }
        }
    }
    Ok(())
}

async fn shadow_reload_task(
    shadow_data_watch_tx: watch::Sender<EtcDb>,
    mut shadow_broadcast_rx: broadcast::Receiver<bool>,
) {
    debug!("shadow reload task has started ...");

    while shadow_broadcast_rx.recv().await.is_ok() {
        match process_etc_passwd_group().await {
            Ok(etc_db) => {
                shadow_data_watch_tx.send_replace(etc_db);
                debug!("shadow reload task sent");
            }
            Err(()) => {
                error!("Unable to process etc db");
                continue;
            }
        }
    }

    debug!("shadow reload task has stopped");
}

async fn handle_tasks(
    stream: UnixStream,
    ctl_broadcast_rx: &mut broadcast::Receiver<bool>,
    shadow_data_watch_rx: &mut watch::Receiver<EtcDb>,
    cfg: &UnixdConfig,
) {
    let mut reqs = Framed::new(stream, TaskCodec::new());

    debug!("task handler has started ...");

    // Immediately trigger that we should reload the shadow files for the new connected handler
    shadow_data_watch_rx.mark_changed();

    loop {
        tokio::select! {
            _ = ctl_broadcast_rx.recv() => {
                break;
            }
            request = reqs.next() => {
                match request {
                    Some(Ok(TaskRequestFrame {
                        id,
                        req: TaskRequest::HomeDirectory(info),
                    })) => {
                        debug!("Received task -> HomeDirectory({:?})", info);

                        let resp = match create_home_directory(
                            &info,
                            cfg.home_prefix.as_ref(),
                            cfg.home_mount_prefix.as_ref(),
                            cfg.use_etc_skel,
                            cfg.selinux,
                        ) {
                            Ok(()) => TaskResponse::Success(id),
                            Err(msg) => TaskResponse::Error(msg),
                        };

                        // Now send a result.
                        if let Err(err) = reqs.send(resp).await {
                            error!(?err, "Unable to communicate to kanidm unixd");
                            break;
                        }
                        // All good, loop.
                    }
                    other => {
                        error!("Error -> {:?}", other);
                        break;
                    }
                }
            }
            Ok(_) = shadow_data_watch_rx.changed() => {
                debug!("Received shadow reload event.");
                let etc_db: EtcDb = {
                    let etc_db_ref = shadow_data_watch_rx.borrow_and_update();
                    (*etc_db_ref).clone()
                };
                // process etc shadow and send it here.
                let resp = TaskResponse::NotifyShadowChange(etc_db);
                if let Err(err) = reqs.send(resp).await {
                    error!(?err, "Unable to communicate to kanidm unixd");
                    break;
                }
                debug!("Shadow reload OK!");
            }
        }
    }

    info!("Disconnected from kanidm_unixd ...");
}

#[instrument(level = "debug", skip_all)]
async fn process_etc_passwd_group() -> Result<EtcDb, ()> {
    let mut file = File::open("/etc/passwd").await.map_err(|err| {
        error!(?err);
    })?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await.map_err(|err| {
        error!(?err);
    })?;

    let users = parse_etc_passwd(contents.as_slice())
        .map_err(|_| "Invalid passwd content")
        .map_err(|err| {
            error!(?err);
        })?;

    let mut file = File::open("/etc/shadow").await.map_err(|err| {
        error!(?err);
    })?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await.map_err(|err| {
        error!(?err);
    })?;

    let shadow = parse_etc_shadow(contents.as_slice())
        .map_err(|_| "Invalid passwd content")
        .map_err(|err| {
            error!(?err);
        })?;

    let mut file = File::open("/etc/group").await.map_err(|err| {
        error!(?err);
    })?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await.map_err(|err| {
        error!(?err);
    })?;

    let groups = parse_etc_group(contents.as_slice())
        .map_err(|_| "Invalid group content")
        .map_err(|err| {
            error!(?err);
        })?;

    Ok(EtcDb {
        users,
        shadow,
        groups,
    })
}

fn setup_shadow_inotify_watcher(
    shadow_broadcast_tx: broadcast::Sender<bool>,
) -> Result<Debouncer<RecommendedWatcher, RecommendedCache>, ExitCode> {
    let watcher = new_debouncer(
        Duration::from_secs(5),
        None,
        move |event: Result<Vec<DebouncedEvent>, _>| {
            let array_of_events = match event {
                Ok(events) => events,
                Err(array_errors) => {
                    for err in array_errors {
                        error!(?err, "inotify debounce error");
                    }
                    return;
                }
            };

            let mut path_of_interest_was_changed = false;

            for inode_event in array_of_events.iter() {
                if !inode_event.kind.is_access()
                    && inode_event.paths.iter().any(|path| {
                        path == Path::new("/etc/group")
                            || path == Path::new("/etc/passwd")
                            || path == Path::new("/etc/shadow")
                    })
                {
                    debug!(?inode_event, "Handling inotify modification event");

                    path_of_interest_was_changed = true
                }
            }

            if path_of_interest_was_changed {
                let _ = shadow_broadcast_tx.send(true);
            } else {
                debug!(?array_of_events, "IGNORED");
            }
        },
    )
    .and_then(|mut debouncer| {
        debouncer
            .watch(Path::new("/etc"), RecursiveMode::Recursive)
            .map(|()| debouncer)
    });

    watcher.map_err(|err| {
        error!(?err, "Failed to setup inotify");
        ExitCode::FAILURE
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // On linux when debug assertions are disabled, prevent ptrace
    // from attaching to us.
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    if let Err(code) = prctl::set_dumpable(false) {
        error!(?code, "CRITICAL: Unable to set prctl flags");
        return ExitCode::FAILURE;
    }
    // let cuid = get_current_uid();
    // let cgid = get_current_gid();
    // We only need to check effective id
    let ceuid = get_effective_uid();
    let cegid = get_effective_gid();

    for arg in std::env::args() {
        if arg.contains("--version") {
            println!("kanidm_unixd_tasks {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        } else if arg.contains("--help") {
            println!("kanidm_unixd_tasks {}", env!("CARGO_PKG_VERSION"));
            println!("Usage: kanidm_unixd_tasks");
            println!("  --version");
            println!("  --help");
            return ExitCode::SUCCESS;
        }
    }

    #[allow(clippy::expect_used)]
    tracing_forest::worker_task()
        .set_global(true)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| {
            subscriber.with(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("info"))
                    .expect("Failed to init envfilter"),
            )
        })
        .on(async {
            if ceuid != 0 || cegid != 0 {
                error!("Refusing to run - this process *MUST* operate as root.");
                return ExitCode::FAILURE;
            }

            let unixd_path = Path::new(DEFAULT_CONFIG_PATH);
            let unixd_path_str = match unixd_path.to_str() {
                Some(cps) => cps,
                None => {
                    error!("Unable to turn unixd_path to str");
                    return ExitCode::FAILURE;
                }
            };

            let cfg = match UnixdConfig::new().read_options_from_optional_config(unixd_path) {
                Ok(v) => v,
                Err(_) => {
                    error!("Failed to parse {}", unixd_path_str);
                    return ExitCode::FAILURE;
                }
            };

            let task_sock_path = cfg.task_sock_path.clone();
            debug!("Attempting to use {} ...", task_sock_path);

            // This is the startup/shutdown control channel
            let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);
            let mut d_broadcast_rx = broadcast_tx.subscribe();

            // This is to broadcast when we need to reload the shadow
            // files.
            let (shadow_broadcast_tx, shadow_broadcast_rx) = broadcast::channel(4);

            let watcher = match setup_shadow_inotify_watcher(shadow_broadcast_tx.clone()) {
                Ok(w) => w,
                Err(exit) => return exit,
            };

            // Setup the etcdb watch
            let etc_db = match process_etc_passwd_group().await {
                Ok(etc_db) => etc_db,
                Err(err) => {
                    warn!(?err, "unable to process /etc/passwd and related files.");
                    // Return an empty set instead.
                    EtcDb::default()
                }
            };

            let (shadow_data_watch_tx, mut shadow_data_watch_rx) = watch::channel(etc_db);

            let _shadow_task = tokio::spawn(async move {
                shadow_reload_task(
                    shadow_data_watch_tx, shadow_broadcast_rx
                ).await
            });

            let server = tokio::spawn(async move {
                loop {
                    info!("Attempting to connect to kanidm_unixd ...");

                    tokio::select! {
                        _ = broadcast_rx.recv() => {
                            break;
                        }
                        connect_res = UnixStream::connect(&task_sock_path) => {
                            match connect_res {
                                Ok(stream) => {
                                    info!("Found kanidm_unixd, waiting for tasks ...");

                                    // Yep! Now let the main handler do it's job.
                                    // If it returns (dc, etc, then we loop and try again).
                                    handle_tasks(stream, &mut d_broadcast_rx, &mut shadow_data_watch_rx, &cfg).await;
                                    continue;
                                }
                                Err(e) => {
                                    debug!("\\---> {:?}", e);
                                    error!("Unable to find kanidm_unixd, sleeping ...");
                                    // Back off.
                                    time::sleep(Duration::from_millis(5000)).await;
                                }
                            }
                        }
                    } // select
                } // loop
            });

            info!("Server started ...");

            // On linux, notify systemd.
            #[cfg(target_os = "linux")]
            let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

            loop {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::alarm();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::hangup();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }

                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                }
            }
            info!("Signal received, shutting down");
            // Send a broadcast that we are done.
            if let Err(e) = broadcast_tx.send(true) {
                error!("Unable to shutdown workers {:?}", e);
            }

            debug!("Dropping inotify watcher ...");
            drop(watcher);

            let _ = server.await;
            ExitCode::SUCCESS
        })
        .await
}
