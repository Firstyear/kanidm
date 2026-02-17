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

use futures::{SinkExt, StreamExt};
use kanidm_unix_common::constants::{
    DEFAULT_CONFIG_PATH, SYSTEM_GROUP_PATH, SYSTEM_PASSWD_PATH, SYSTEM_SHADOW_PATH,
};
use kanidm_unix_common::json_codec::JsonCodec;
use kanidm_unix_common::unix_config::{HomeStrategy, UnixdConfig};
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
use tokio_util::codec::Framed;
use tracing::instrument;
use walkdir::WalkDir;

#[cfg(target_os = "linux")]
use nix::mount::MsFlags;
#[cfg(target_os = "linux")]
use procfs::process::Process;
#[cfg(target_os = "linux")]
use std::fs::{create_dir, remove_file};

#[cfg(all(target_family = "unix", feature = "selinux"))]
use kanidm_unix_common::selinux_util;

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
    home_strategy: &HomeStrategy,
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
        .map_err(|e| format!("{e:?}"))?;

    // This is where the storage is *mounted*. If not set, falls back to the home_prefix.
    let home_mount_prefix_path = home_mount_prefix_path
        .unwrap_or(&home_prefix_path)
        .canonicalize()
        .map_err(|e| format!("{e:?}"))?;

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

    // In the ZFS strategy, we will need to check if the filesystem
    // exists, rather than the location it's mounted to.
    let hd_mount_path_exists = match home_strategy {
        HomeStrategy::Symlink => hd_mount_path.exists(),
        #[cfg(target_os = "linux")]
        HomeStrategy::BindMount => hd_mount_path.exists(),
    };

    // Does the home directory exist? This is checking the *true* home mount storage.
    if !hd_mount_path_exists {
        // Set the SELinux security context for file creation
        #[cfg(all(target_family = "unix", feature = "selinux"))]
        labeler.do_setfscreatecon_for_path()?;

        // This is affected by the mount strategy
        // because in a future ZFS home dir setup, we'll need to be able to make
        // the zfs volume for the user in this step.
        match home_strategy {
            HomeStrategy::Symlink => create_dir_path(&hd_mount_path, info)?,
            #[cfg(target_os = "linux")]
            HomeStrategy::BindMount => create_dir_path(&hd_mount_path, info)?,
        }

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

    let Some(alias) = info.alias.as_ref() else {
        // No alias for the home dir, lets go.
        debug!("No home directory alias present, success.");
        return Ok(());
    };

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

    match home_strategy {
        HomeStrategy::Symlink => home_alias_update_symlink(&alias_path, &hd_mount_path),
        #[cfg(target_os = "linux")]
        HomeStrategy::BindMount => home_alias_update_bind_mount(&alias_path, &hd_mount_path),
    }
}

fn create_dir_path(hd_mount_path: &Path, info: &HomeDirectoryInfo) -> Result<(), String> {
    // Set a umask
    let before = unsafe { umask(0o0027) };

    // Create the home directory.
    if let Err(e) = fs::create_dir_all(hd_mount_path) {
        let _ = unsafe { umask(before) };
        error!(err = ?e, ?hd_mount_path, "Unable to create directory");
        return Err(format!("{e:?}"));
    }
    let _ = unsafe { umask(before) };

    chown(hd_mount_path, info.gid)
}

#[cfg(target_os = "linux")]
fn home_alias_update_bind_mount(alias_path: &Path, hd_mount_path: &Path) -> Result<(), String> {
    if alias_path.exists() {
        if alias_path.is_symlink() {
            // If the alias_path is a symlink, remove it
            if let Err(e) = remove_file(alias_path) {
                error!("Unable to remove existing symlink at {alias_path:?}");
                return Err(format!("{e:?}"));
            }
        } else if !alias_path.is_dir() {
            // If it's anything other than a directory, we don't proceed.
            error!("A non-directory item already exists at {alias_path:?}");
            return Err(format!(
                "A non-directory item already exists at {alias_path:?}"
            ));
        }
    }

    // Create mount point if it doesn't exist
    if !alias_path.exists() {
        if let Err(e) = create_dir(alias_path) {
            error!("Unable to create bind mount target at {alias_path:?}");
            return Err(format!("{e:?}"));
        }
    }

    let current_mounts = Process::myself()
        .map_err(|e| format!("While updating home directory bind mount, could not get reference to current process: {e}"))?
        .mountinfo()
        .map_err(|e| format!("While updating home directory bind mount, could not get mount info: {e}"))?;

    // Remove conflicting mount if it exists:
    let mismatching_mount = current_mounts.iter().find(|m| {
        m.mount_point == alias_path && m.mount_source.as_ref().map(Path::new) != Some(hd_mount_path)
    });

    if let Some(m) = mismatching_mount {
        nix::mount::umount(&m.mount_point).map_err(|e| {
            format!(
                "Unable to remove conflicting mount at {:?}: {e}",
                &m.mount_point
            )
        })?;
    }

    // If mount point exists and is already correctly mounted, we are done
    if current_mounts.iter().any(|m| {
        m.mount_point == alias_path && m.mount_source.as_ref().map(Path::new) != Some(hd_mount_path)
    }) {
        return Ok(());
    }

    // Finally, try to create the bind mount
    nix::mount::mount::<Path, Path, str, str>(
        Some(hd_mount_path),
        alias_path,
        None,
        MsFlags::MS_BIND,
        None,
    )
    .map_err(|e| {
        format!("Unable to bind mount home directory {hd_mount_path:?} to {alias_path:?}: {e}")
    })?;

    Ok(())
}

fn home_alias_update_symlink(alias_path: &Path, hd_mount_path: &Path) -> Result<(), String> {
    if !alias_path.exists() {
        // Does not exist. Create.
        debug!("creating symlink {:?} -> {:?}", alias_path, hd_mount_path);
        if let Err(e) = symlink(hd_mount_path, alias_path) {
            error!(err = ?e, ?alias_path, "Unable to create alias path");
            return Err(format!("{e:?}"));
        }
        return Ok(());
    }

    debug!("checking symlink {:?} -> {:?}", alias_path, hd_mount_path);
    let attr = match fs::symlink_metadata(alias_path) {
        Ok(a) => a,
        Err(e) => {
            error!(err = ?e, ?alias_path, "Unable to read alias path metadata");
            return Err(format!("{e:?}"));
        }
    };

    if !attr.file_type().is_symlink() {
        warn!(
            ?alias_path,
            ?hd_mount_path,
            "home directory alias path is not a symlink, unable to update"
        );
        return Ok(());
    }

    // If already correct, skip churn.
    match fs::read_link(alias_path) {
        Ok(current_target) if current_target == hd_mount_path => {
            debug!(
                ?alias_path,
                ?current_target,
                "alias symlink already correct, skipping update"
            );
            return Ok(());
        }
        Ok(current_target) => {
            debug!(
                ?alias_path,
                ?current_target,
                ?hd_mount_path,
                "alias symlink target differs, updating atomically"
            );
        }
        Err(e) => {
            warn!(
                err=?e, ?alias_path,
                "unable to read existing symlink target, will replace atomically"
            );
        }
    }

    // Atomic replace: create temp symlink in same dir, then rename over existing.
    let alias_path_tmp = alias_path.with_extension("tmp");

    if alias_path_tmp.exists() {
        debug!("checking symlink temp {:?}", alias_path_tmp);
        let attr = match fs::symlink_metadata(&alias_path_tmp) {
            Ok(a) => a,
            Err(e) => {
                error!(err = ?e, ?alias_path_tmp, "Unable to read alias path temp metadata");
                return Err(format!("{e:?}"));
            }
        };

        if !attr.file_type().is_symlink() {
            warn!(
                ?alias_path,
                ?alias_path_tmp,
                ?hd_mount_path,
                "home directory alias path temporary update location already exists, and is not a symlink, unable to update"
            );
            return Ok(());
        }
    }

    // Best-effort cleanup of any stale tmp.
    let _ = fs::remove_file(&alias_path_tmp);

    if let Err(e) = symlink(hd_mount_path, &alias_path_tmp) {
        error!(err=?e, ?alias_path_tmp, "Unable to create temporary alias symlink");
        return Err(format!("{e:?}"));
    }

    // Rename is atomic within the same directory; no disappearance window.
    if let Err(e) = fs::rename(&alias_path_tmp, alias_path) {
        error!(err=?e, from=?alias_path_tmp, to=?alias_path, "Unable to atomically replace alias symlink");
        // Cleanup temp on failure.
        let _ = fs::remove_file(&alias_path_tmp);
        return Err(format!("{e:?}"));
    }

    debug!(
        "alias symlink updated atomically {:?} -> {:?}",
        alias_path, hd_mount_path
    );

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

async fn handle_shadow_reload(shadow_data_watch_rx: &mut watch::Receiver<EtcDb>) -> TaskResponse {
    debug!("Received shadow reload event.");
    let etc_db: EtcDb = {
        let etc_db_ref = shadow_data_watch_rx.borrow_and_update();
        (*etc_db_ref).clone()
    };
    // process etc shadow and send it here.
    TaskResponse::NotifyShadowChange(etc_db)
}

async fn handle_unixd_request(
    request: Option<Result<TaskRequestFrame, io::Error>>,
    cfg: &UnixdConfig,
) -> Result<TaskResponse, ()> {
    debug!("Received unixd event.");
    match request {
        Some(Ok(TaskRequestFrame {
            id,
            req: TaskRequest::HomeDirectory(info),
        })) => {
            debug!("Received task -> HomeDirectory({:?})", info);

            match create_home_directory(
                &info,
                cfg.home_prefix.as_ref(),
                cfg.home_mount_prefix.as_ref(),
                &cfg.home_strategy,
                cfg.use_etc_skel,
                cfg.selinux,
            ) {
                Ok(()) => Ok(TaskResponse::Success(id)),
                Err(msg) => Ok(TaskResponse::Error(msg)),
            }
        }
        other => {
            error!("Error -> got un-handled Request Frame {other:?}");
            Err(())
        }
    }
}

async fn handle_tasks(
    stream: UnixStream,
    ctl_broadcast_rx: &mut broadcast::Receiver<bool>,
    shadow_data_watch_rx: &mut watch::Receiver<EtcDb>,
    cfg: &UnixdConfig,
) {
    let codec: JsonCodec<TaskRequestFrame, TaskResponse> = JsonCodec::default();

    let mut reqs = Framed::new(stream, codec);

    // Immediately trigger that we should reload the shadow files for the new connected handler
    shadow_data_watch_rx.mark_changed();

    debug!("Task handler loop has started ...");

    loop {
        let msg = tokio::select! {
            biased; // tell tokio to poll these in order
            _ = ctl_broadcast_rx.recv() => {
                // We received a shutdown signal.
                debug!("Received shutdown signal, breaking task handler loop ...");
                return
            }
            // We bias to *sending* messages in tasks.
            Ok(_) = shadow_data_watch_rx.changed() => {
                handle_shadow_reload(shadow_data_watch_rx).await
            }
            request = reqs.next() => {
                match handle_unixd_request(request,  cfg).await {
                    Ok(response) => {
                       response
                    }
                    Err(_) => {
                        error!("Error handling request, exiting task handler loop ...");
                        return;
                    }
                }
            }
        };

        if let Err(e) = reqs.send(msg).await {
            error!(?e, "Error sending response to kanidm_unixd");
            return;
        }
    }
}

#[instrument(level = "debug", skip_all)]
async fn process_etc_passwd_group() -> Result<EtcDb, ()> {
    let mut file = File::open(SYSTEM_PASSWD_PATH).await.map_err(|err| {
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

    let mut file = File::open(SYSTEM_SHADOW_PATH).await.map_err(|err| {
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

    let mut file = File::open(SYSTEM_GROUP_PATH).await.map_err(|err| {
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
                        path == Path::new(SYSTEM_GROUP_PATH)
                            || path == Path::new(SYSTEM_PASSWD_PATH)
                            || path == Path::new(SYSTEM_SHADOW_PATH)
                    })
                {
                    debug!(?inode_event, "Handling inotify modification event");

                    path_of_interest_was_changed = true
                }
            }

            if path_of_interest_was_changed {
                let _ = shadow_broadcast_tx.send(true);
            } else {
                trace!(?array_of_events, "IGNORED");
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
                    warn!(?err, "unable to process {SYSTEM_PASSWD_PATH} and related files.");
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

                                    // Yep! Now let the main handler do its job.
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
