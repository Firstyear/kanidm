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
use clap::{Arg, ArgAction, Command};
use futures::{SinkExt, StreamExt};
use kanidm_client::KanidmClientBuilder;
use kanidm_hsm_crypto::{soft::SoftTpm, AuthValue, BoxedDynTpm, Tpm};
use kanidm_proto::constants::DEFAULT_CLIENT_CONFIG_PATH;
use kanidm_proto::internal::OperationError;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::{HsmType, UnixdConfig};
use kanidm_unix_common::unix_passwd::EtcDb;
use kanidm_unix_common::unix_proto::{
    ClientRequest, ClientResponse, TaskRequest, TaskRequestFrame, TaskResponse,
};
use kanidm_unix_resolver::db::{Cache, Db};
use kanidm_unix_resolver::idprovider::interface::IdProvider;
use kanidm_unix_resolver::idprovider::kanidm::KanidmProvider;
use kanidm_unix_resolver::idprovider::system::SystemProvider;
use kanidm_unix_resolver::resolver::Resolver;
use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use libc::umask;
use sketching::tracing::span;
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::metadata;
use std::io;
use std::io::Error as IoError;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tokio::fs::File;
use tokio::io::AsyncReadExt; // for read_to_end()
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio_util::codec::{Decoder, Encoder, Framed};

#[cfg(not(target_os = "illumos"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

//=== the codec

struct AsyncTaskRequest {
    task_req: TaskRequest,
    task_chan: oneshot::Sender<()>,
}

#[derive(Default)]
struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = ClientRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<ClientRequest>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<ClientResponse> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ClientResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

#[derive(Default)]
struct TaskCodec;

impl Decoder for TaskCodec {
    type Error = io::Error;
    type Item = TaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<TaskResponse>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<TaskRequestFrame> for TaskCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: TaskRequestFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Attempting to send request -> {:?} ...", msg.id);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

/// Pass this a file path and it'll look for the file and remove it if it's there.
fn rm_if_exist(p: &str) {
    if Path::new(p).exists() {
        debug!("Removing requested file {:?}", p);
        let _ = std::fs::remove_file(p).map_err(|e| {
            error!(
                "Failure while attempting to attempting to remove {:?} -> {:?}",
                p, e
            );
        });
    } else {
        debug!("Path {:?} doesn't exist, not attempting to remove.", p);
    }
}

async fn handle_task_client(
    stream: UnixStream,
    notify_shadow_change_tx: &Sender<EtcDb>,
    task_channel_rx: &mut Receiver<AsyncTaskRequest>,
    broadcast_rx: &mut broadcast::Receiver<bool>,
) -> Result<(), Box<dyn Error>> {
    // setup the codec, this is to the unix socket which the task daemon
    // connected to us with.
    let mut last_task_id: u64 = 0;
    let mut task_handles = BTreeMap::new();

    let mut framed_stream = Framed::new(stream, TaskCodec);

    loop {
        tokio::select! {
            // We have been commanded to stop operation.
            _ = broadcast_rx.recv() => {
                return Ok(())
            }
            task_request = task_channel_rx.recv() => {
                let Some(AsyncTaskRequest {
                    task_req,
                    task_chan
                }) = task_request else {
                    // Task channel has died, cease operation.
                    return Ok(())
                };

                debug!("Sending Task -> {:?}", task_req);

                last_task_id += 1;
                let task_id = last_task_id;

                // Setup the task handle so we know who to get back to.
                task_handles.insert(task_id, task_chan);

                let task_frame = TaskRequestFrame {
                    id: task_id,
                    req: task_req,
                };

                if let Err(err) = framed_stream.send(task_frame).await {
                    warn!("Unable to queue task for completion");
                    return Err(Box::new(err));
                }
                // Task sent
            }

            response = framed_stream.next() => {
                // Process incoming messages. They may be out of order.
                match response {
                    Some(Ok(TaskResponse::Success(task_id))) => {
                        debug!("Task was acknowledged and completed.");

                        if let Some(handle) = task_handles.remove(&task_id) {
                            // Send a result back via the one-shot
                            // Ignore if it fails.
                            let _ = handle.send(());
                        }
                        // If the ID was unregistered, ignore.
                    }
                    Some(Ok(TaskResponse::NotifyShadowChange(etc_db))) => {
                        let _ = notify_shadow_change_tx.send(etc_db).await;
                    }
                    // Other things ....
                    // Some(Ok(TaskResponse::ReloadSystemIds))

                    other => {
                        error!("Error -> {:?}", other);
                        return Err(Box::new(IoError::other("oh no!")));
                    }
                }

            }

        }
    }
}

async fn handle_client(
    sock: UnixStream,
    cachelayer: Arc<Resolver>,
    task_channel_tx: &Sender<AsyncTaskRequest>,
) -> Result<(), Box<dyn Error>> {
    let conn_id = uuid::Uuid::new_v4();

    let span = span!(Level::DEBUG, "accepted connection", uuid = %conn_id);
    let _enter = span.enter();

    let Ok(ucred) = sock.peer_cred() else {
        return Err(Box::new(IoError::other(
            "Unable to verify peer credentials.",
        )));
    };

    debug!(uid = ?ucred.uid(), gid = ?ucred.gid(), pid = ?ucred.pid());

    let mut reqs = Framed::new(sock, ClientCodec);
    let mut pam_auth_session_state = None;

    // Setup a broadcast channel so that if we have an unexpected disconnection, we can
    // tell consumers to stop work.
    let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);

    debug!("Waiting for requests ...");
    // Drop the span here so that there are no parent spans during the request loop.
    drop(_enter);

    while let Some(Ok(req)) = reqs.next().await {
        let span = span!(Level::INFO, "client request", uuid = %conn_id);
        let _enter = span.enter();

        let resp = match req {
            ClientRequest::SshKey(account_id) => cachelayer
                .get_sshkeys(account_id.as_str())
                .await
                .map(ClientResponse::SshKeys)
                .unwrap_or_else(|_| {
                    error!("unable to load keys, returning empty set.");
                    ClientResponse::SshKeys(vec![])
                }),
            ClientRequest::NssAccounts => cachelayer
                .get_nssaccounts()
                .await
                .map(ClientResponse::NssAccounts)
                .unwrap_or_else(|_| {
                    error!("unable to enum accounts");
                    ClientResponse::NssAccounts(Vec::new())
                }),
            ClientRequest::NssAccountByUid(gid) => cachelayer
                .get_nssaccount_gid(gid)
                .await
                .map(ClientResponse::NssAccount)
                .unwrap_or_else(|_| {
                    error!("unable to load account, returning empty.");
                    ClientResponse::NssAccount(None)
                }),
            ClientRequest::NssAccountByName(account_id) => cachelayer
                .get_nssaccount_name(account_id.as_str())
                .await
                .map(ClientResponse::NssAccount)
                .unwrap_or_else(|_| {
                    error!("unable to load account, returning empty.");
                    ClientResponse::NssAccount(None)
                }),
            ClientRequest::NssGroups => cachelayer
                .get_nssgroups()
                .await
                .map(ClientResponse::NssGroups)
                .unwrap_or_else(|_| {
                    error!("unable to enum groups");
                    ClientResponse::NssGroups(Vec::new())
                }),
            ClientRequest::NssGroupByGid(gid) => cachelayer
                .get_nssgroup_gid(gid)
                .await
                .map(ClientResponse::NssGroup)
                .unwrap_or_else(|_| {
                    error!("unable to load group, returning empty.");
                    ClientResponse::NssGroup(None)
                }),
            ClientRequest::NssGroupByName(grp_id) => cachelayer
                .get_nssgroup_name(grp_id.as_str())
                .await
                .map(ClientResponse::NssGroup)
                .unwrap_or_else(|_| {
                    error!("unable to load group, returning empty.");
                    ClientResponse::NssGroup(None)
                }),
            ClientRequest::PamAuthenticateInit { account_id, info } => {
                match &pam_auth_session_state {
                    Some(_auth_session) => {
                        // Invalid to init a request twice.
                        warn!("Attempt to init auth session while current session is active");
                        // Clean the former session, something is wrong.
                        pam_auth_session_state = None;
                        ClientResponse::Error(OperationError::KU001InitWhileSessionActive)
                    }
                    None => {
                        let current_time = OffsetDateTime::now_utc();

                        match cachelayer
                            .pam_account_authenticate_init(
                                account_id.as_str(),
                                &info,
                                current_time,
                                shutdown_tx.subscribe(),
                            )
                            .await
                        {
                            Ok((auth_session, pam_auth_response)) => {
                                pam_auth_session_state = Some(auth_session);
                                pam_auth_response.into()
                            }
                            Err(_) => ClientResponse::Error(OperationError::KU004PamInitFailed),
                        }
                    }
                }
            }
            ClientRequest::PamAuthenticateStep(pam_next_req) => match &mut pam_auth_session_state {
                Some(auth_session) => cachelayer
                    .pam_account_authenticate_step(auth_session, pam_next_req)
                    .await
                    .map(|pam_auth_response| pam_auth_response.into())
                    .unwrap_or(ClientResponse::Error(OperationError::KU003PamAuthFailed)),
                None => {
                    warn!("Attempt to continue auth session while current session is inactive");
                    ClientResponse::Error(OperationError::KU002ContinueWhileSessionInActive)
                }
            },
            ClientRequest::PamAccountAllowed(account_id) => cachelayer
                .pam_account_allowed(account_id.as_str())
                .await
                .map(ClientResponse::PamStatus)
                .unwrap_or(ClientResponse::Error(
                    OperationError::KU005ErrorCheckingAccount,
                )),
            ClientRequest::PamAccountBeginSession(account_id) => {
                match cachelayer
                    .pam_account_beginsession(account_id.as_str())
                    .await
                {
                    Ok(Some(info)) => {
                        let (tx, rx) = oneshot::channel();

                        match task_channel_tx
                            .send_timeout(
                                AsyncTaskRequest {
                                    task_req: TaskRequest::HomeDirectory(info),
                                    task_chan: tx,
                                },
                                Duration::from_millis(100),
                            )
                            .await
                        {
                            Ok(()) => {
                                // Now wait for the other end OR timeout.
                                match tokio::time::timeout_at(
                                    tokio::time::Instant::now() + Duration::from_millis(1000),
                                    rx,
                                )
                                .await
                                {
                                    Ok(Ok(_)) => {
                                        debug!("Task completed, returning to pam ...");
                                        ClientResponse::Ok
                                    }
                                    _ => {
                                        // Timeout or other error.
                                        ClientResponse::Error(OperationError::KG001TaskTimeout)
                                    }
                                }
                            }
                            Err(_) => {
                                // We could not submit the req. Move on!
                                ClientResponse::Error(OperationError::KG002TaskCommFailure)
                            }
                        }
                    }
                    Ok(None) => {
                        // The session can begin, but we do not need to create the home dir.
                        ClientResponse::Ok
                    }
                    Err(_) => ClientResponse::Error(OperationError::KU005ErrorCheckingAccount),
                }
            }
            ClientRequest::InvalidateCache => cachelayer
                .invalidate()
                .await
                .map(|_| ClientResponse::Ok)
                .unwrap_or(ClientResponse::Error(OperationError::KG003CacheClearFailed)),
            ClientRequest::ClearCache => {
                if ucred.uid() == 0 {
                    cachelayer
                        .clear_cache()
                        .await
                        .map(|_| ClientResponse::Ok)
                        .unwrap_or(ClientResponse::Error(OperationError::KG003CacheClearFailed))
                } else {
                    error!("{}", OperationError::KU006OnlyRootAllowed);
                    ClientResponse::Error(OperationError::KU006OnlyRootAllowed)
                }
            }
            ClientRequest::Status => {
                let status = cachelayer.provider_status().await;
                ClientResponse::ProviderStatus(status)
            }
        };
        reqs.send(resp).await?;
        reqs.flush().await?;
        trace!("flushed response!");
    }

    // Signal any tasks that they need to stop.
    if let Err(shutdown_err) = shutdown_tx.send(()) {
        warn!(
            ?shutdown_err,
            "Unable to signal tasks to stop, they will naturally timeout instead."
        )
    }

    // Disconnect them
    let span = span!(Level::DEBUG, "disconnecting client", uuid = %conn_id);
    let _enter = span.enter();
    debug!(uid = ?ucred.uid(), gid = ?ucred.gid(), pid = ?ucred.pid());

    Ok(())
}

async fn read_hsm_pin(hsm_pin_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !PathBuf::from_str(hsm_pin_path)?.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("HSM PIN file '{}' not found", hsm_pin_path),
        )
        .into());
    }

    let mut file = File::open(hsm_pin_path).await?;
    let mut contents = vec![];
    file.read_to_end(&mut contents).await?;
    Ok(contents)
}

async fn write_hsm_pin(hsm_pin_path: &str) -> Result<(), Box<dyn Error>> {
    if !PathBuf::from_str(hsm_pin_path)?.exists() {
        let new_pin = AuthValue::generate().map_err(|hsm_err| {
            error!(?hsm_err, "Unable to generate new pin");
            std::io::Error::other("Unable to generate new pin")
        })?;

        std::fs::write(hsm_pin_path, new_pin)?;

        info!("Generated new HSM pin");
    }

    Ok(())
}

#[cfg(feature = "tpm")]
fn open_tpm(tcti_name: &str) -> Option<BoxedDynTpm> {
    use kanidm_hsm_crypto::tpm::TpmTss;
    match TpmTss::new(tcti_name) {
        Ok(tpm) => {
            debug!("opened hw tpm");
            Some(BoxedDynTpm::new(tpm))
        }
        Err(tpm_err) => {
            error!(?tpm_err, "Unable to open requested tpm device");
            None
        }
    }
}

#[cfg(not(feature = "tpm"))]
fn open_tpm(_tcti_name: &str) -> Option<BoxedDynTpm> {
    error!("Hardware TPM supported was not enabled in this build. Unable to proceed");
    None
}

#[cfg(feature = "tpm")]
fn open_tpm_if_possible(tcti_name: &str) -> BoxedDynTpm {
    use kanidm_hsm_crypto::tpm::TpmTss;
    match TpmTss::new(tcti_name) {
        Ok(tpm) => {
            debug!("opened hw tpm");
            BoxedDynTpm::new(tpm)
        }
        Err(tpm_err) => {
            warn!(
                ?tpm_err,
                "Unable to open requested tpm device, falling back to soft tpm"
            );
            BoxedDynTpm::new(SoftTpm::new())
        }
    }
}

#[cfg(not(feature = "tpm"))]
fn open_tpm_if_possible(_tcti_name: &str) -> BoxedDynTpm {
    debug!("opened soft tpm");
    BoxedDynTpm::new(SoftTpm::new())
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

    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    let clap_args = Command::new("kanidm_unixd")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Kanidm Unix daemon")
        .arg(
            Arg::new("skip-root-check")
                .help("Allow running as root. Don't use this in production as it is risky!")
                .short('r')
                .long("skip-root-check")
                .env("KANIDM_SKIP_ROOT_CHECK")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("debug")
                .help("Show extra debug information")
                .short('d')
                .long("debug")
                .env("KANIDM_DEBUG")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("configtest")
                .help("Display the configuration and exit")
                .short('t')
                .long("configtest")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("unixd-config")
                .help("Set the unixd config file path")
                .short('u')
                .long("unixd-config")
                .default_value(DEFAULT_CONFIG_PATH)
                .env("KANIDM_UNIX_CONFIG")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("client-config")
                .help("Set the client config file path")
                .short('c')
                .long("client-config")
                .default_value(DEFAULT_CLIENT_CONFIG_PATH)
                .env("KANIDM_CLIENT_CONFIG")
                .action(ArgAction::Set),
        )
        .get_matches();

    if clap_args.get_flag("debug") {
        std::env::set_var("RUST_LOG", "debug");
    }

    #[allow(clippy::expect_used)]
    tracing_forest::worker_task()
        .set_global(true)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| subscriber
            .with(EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .expect("Failed to init envfilter")
            )
        )
        .on(async {
            let span = span!(Level::DEBUG, "starting resolver");
            let _enter = span.enter();

            if clap_args.get_flag("skip-root-check") {
                warn!("Skipping root user check, if you're running this for testing, ensure you clean up temporary files.")
                // TODO: this wording is not great m'kay.
            } else if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
                error!("Refusing to run - this process must not operate as root.");
                return ExitCode::FAILURE
            };

            debug!("Profile -> {}", env!("KANIDM_PROFILE_NAME"));
            debug!("CPU Flags -> {}", env!("KANIDM_CPU_FLAGS"));

            let Some(cfg_path_str) = clap_args.get_one::<String>("client-config") else {
                error!("Failed to pull the client config path");
                return ExitCode::FAILURE
            };
            let cfg_path: PathBuf =  PathBuf::from(cfg_path_str);

            if !cfg_path.exists() {
                // there's no point trying to start up if we can't read a usable config!
                error!(
                    "Client config missing from {} - cannot start up. Quitting.",
                    cfg_path_str
                );
                let diag = kanidm_lib_file_permissions::diagnose_path(cfg_path.as_ref());
                info!(%diag);
                return ExitCode::FAILURE
            } else {
                let cfg_meta = match metadata(&cfg_path) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Unable to read metadata for {} - {:?}", cfg_path_str, e);
                        let diag = kanidm_lib_file_permissions::diagnose_path(cfg_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    }
                };
                if !kanidm_lib_file_permissions::readonly(&cfg_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                        cfg_path_str
                        );
                }

                if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
                    warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                        cfg_path_str
                    );
                }
            }

            let Some(unixd_path_str) = clap_args.get_one::<String>("unixd-config") else {
                error!("Failed to pull the unixd config path");
                return ExitCode::FAILURE
            };
            let unixd_path = PathBuf::from(unixd_path_str);

            if !unixd_path.exists() {
                // there's no point trying to start up if we can't read a usable config!
                error!(
                    "unixd config missing from {} - cannot start up. Quitting.",
                    unixd_path_str
                );
                let diag = kanidm_lib_file_permissions::diagnose_path(unixd_path.as_ref());
                info!(%diag);
                return ExitCode::FAILURE
            } else {
                let unixd_meta = match metadata(&unixd_path) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Unable to read metadata for {} - {:?}", unixd_path_str, e);
                        let diag = kanidm_lib_file_permissions::diagnose_path(unixd_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    }
                };
                if !kanidm_lib_file_permissions::readonly(&unixd_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                        unixd_path_str);
                }

                if unixd_meta.uid() == cuid || unixd_meta.uid() == ceuid {
                    warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                        unixd_path_str
                    );
                }
            }

            let cfg = match UnixdConfig::new().read_options_from_optional_config(&unixd_path) {
                Ok(v) => v,
                Err(_) => {
                    error!("Failed to parse {}", unixd_path_str);
                    return ExitCode::FAILURE
                }
            };

            let client_builder = if let Some(kconfig) = &cfg.kanidm_config {
                // setup
                let cb = match KanidmClientBuilder::new().read_options_from_optional_config(&cfg_path) {
                    Ok(v) => v,
                    Err(_) => {
                        error!("Failed to parse {}", cfg_path_str);
                        return ExitCode::FAILURE
                    }
                };

                Some((cb, kconfig))
            } else { None };

            if clap_args.get_flag("configtest") {
                eprintln!("###################################");
                eprintln!("Dumping configs:\n###################################");
                eprintln!("kanidm_unixd config (from {:#?})", &unixd_path);
                eprintln!("{}", cfg);
                eprintln!("###################################");
                if let Some((cb, _)) = client_builder.as_ref() {
                    eprintln!("kanidm client config (from {:#?})", &cfg_path);
                    eprintln!("{}", cb);
                }  else {
                    eprintln!("kanidm client: disabled");
                }
                return ExitCode::SUCCESS;
            }

            debug!("🧹 Cleaning up sockets from previous invocations");
            rm_if_exist(cfg.sock_path.as_str());
            rm_if_exist(cfg.task_sock_path.as_str());

            // Check the db path will be okay.
            if !cfg.cache_db_path.is_empty() {
                let cache_db_path = PathBuf::from(cfg.cache_db_path.as_str());
                // We only need to check the parent folder path permissions as the db itself may not exist yet.
                if let Some(db_parent_path) = cache_db_path.parent() {
                    if !db_parent_path.exists() {
                        error!(
                            "Refusing to run, DB folder {} does not exist",
                            db_parent_path
                                .to_str()
                                .unwrap_or("<db_parent_path invalid>")
                        );
                        let diag = kanidm_lib_file_permissions::diagnose_path(cache_db_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    }

                    let db_par_path_buf = db_parent_path.to_path_buf();

                    let i_meta = match metadata(&db_par_path_buf) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for {} - {:?}",
                                db_par_path_buf
                                    .to_str()
                                    .unwrap_or("<db_par_path_buf invalid>"),
                                e
                            );
                            return ExitCode::FAILURE
                        }
                    };

                    if !i_meta.is_dir() {
                        error!(
                            "Refusing to run - DB folder {} may not be a directory",
                            db_par_path_buf
                                .to_str()
                                .unwrap_or("<db_par_path_buf invalid>")
                        );
                        return ExitCode::FAILURE
                    }
                    if kanidm_lib_file_permissions::readonly(&i_meta) {
                        warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                        );
                    }

                    if i_meta.mode() & 0o007 != 0 {
                        warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str()
                        .unwrap_or("<db_par_path_buf invalid>")
                        );
                    }
                }

                // check to see if the db's already there
                if cache_db_path.exists() {
                    if !cache_db_path.is_file() {
                        error!(
                            "Refusing to run - DB path {} already exists and is not a file.",
                            cache_db_path.to_str().unwrap_or("<cache_db_path invalid>")
                        );
                        let diag = kanidm_lib_file_permissions::diagnose_path(cache_db_path.as_ref());
                        info!(%diag);
                        return ExitCode::FAILURE
                    };

                    match metadata(&cache_db_path) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "Unable to read metadata for {} - {:?}",
                                cache_db_path.to_str().unwrap_or("<cache_db_path invalid>"),
                                e
                            );
                            let diag = kanidm_lib_file_permissions::diagnose_path(cache_db_path.as_ref());
                            info!(%diag);
                            return ExitCode::FAILURE
                        }
                    };
                    // TODO: permissions dance to enumerate the user's ability to write to the file? ref #456 - r2d2 will happily keep trying to do things without bailing.
                };
            }

            let db = match Db::new(cfg.cache_db_path.as_str()) {
                Ok(db) => db,
                Err(_e) => {
                    error!("Failed to create database");
                    return ExitCode::FAILURE
                }
            };

            // perform any db migrations.
            let mut dbtxn = db.write().await;
            if dbtxn.migrate()
                .and_then(|_| {
                    dbtxn.commit()
                }).is_err() {
                    error!("Failed to migrate database");
                    return ExitCode::FAILURE
                }

            // Check for and create the hsm pin if required.
            if let Err(err) = write_hsm_pin(cfg.hsm_pin_path.as_str()).await {
                let diag = kanidm_lib_file_permissions::diagnose_path(cfg.hsm_pin_path.as_ref());
                info!(%diag);
                error!(?err, "Failed to create HSM PIN into {}", cfg.hsm_pin_path.as_str());
                return ExitCode::FAILURE
            };

            // read the hsm pin
            let hsm_pin = match read_hsm_pin(cfg.hsm_pin_path.as_str()).await {
                Ok(hp) => hp,
                Err(err) => {
                    let diag = kanidm_lib_file_permissions::diagnose_path(cfg.hsm_pin_path.as_ref());
                    info!(%diag);
                    error!(?err, "Failed to read HSM PIN from {}", cfg.hsm_pin_path.as_str());
                    return ExitCode::FAILURE
                }
            };

            let auth_value = match AuthValue::try_from(hsm_pin.as_slice()) {
                Ok(av) => av,
                Err(err) => {
                    error!(?err, "invalid hsm pin");
                    return ExitCode::FAILURE
                }
            };

            let mut hsm: BoxedDynTpm = match cfg.hsm_type {
                HsmType::Soft => {
                    BoxedDynTpm::new(SoftTpm::new())
                }
                HsmType::TpmIfPossible => {
                    open_tpm_if_possible(&cfg.tpm_tcti_name)
                }
                HsmType::Tpm => {
                    match open_tpm(&cfg.tpm_tcti_name) {
                        Some(hsm) => hsm,
                        None => return ExitCode::FAILURE,
                    }
                }
            };

            // With the assistance of the DB, setup the HSM and its machine key.
            let mut db_txn = db.write().await;

            let loadable_machine_key = match db_txn.get_hsm_machine_key() {
                Ok(Some(lmk)) => lmk,
                Ok(None) => {
                    // No machine key found - create one, and store it.
                    let loadable_machine_key = match hsm.machine_key_create(&auth_value) {
                        Ok(lmk) => lmk,
                        Err(err) => {
                            error!(?err, "Unable to create hsm loadable machine key");
                            return ExitCode::FAILURE
                        }
                    };

                    if let Err(err) = db_txn.insert_hsm_machine_key(&loadable_machine_key) {
                        error!(?err, "Unable to persist hsm loadable machine key");
                        return ExitCode::FAILURE
                    }

                    loadable_machine_key
                }
                Err(err) => {
                    error!(?err, "Unable to access hsm loadable machine key");
                    return ExitCode::FAILURE
                }
            };

            let machine_key = match hsm.machine_key_load(&auth_value, &loadable_machine_key) {
                Ok(mk) => mk,
                Err(err) => {
                    error!(?err, "Unable to load machine root key - This can occur if you have changed your HSM pin");
                    error!("To proceed you must remove the content of the cache db ({}) to reset all keys", cfg.cache_db_path.as_str());
                    return ExitCode::FAILURE
                }
            };

            let Ok(system_provider) = SystemProvider::new(
            ) else {
                error!("Failed to configure System Provider");
                return ExitCode::FAILURE
            };

            info!("Started system provider");

            let mut clients: Vec<Arc<dyn IdProvider + Send + Sync>> = Vec::with_capacity(1);

            // Setup Kanidm provider if the configuration requests it.
            if let Some((cb, kconfig)) = client_builder {
                let cb = cb.connect_timeout(kconfig.conn_timeout);
                let cb = cb.request_timeout(kconfig.request_timeout);

                let rsclient = match cb.build() {
                    Ok(rsc) => rsc,
                    Err(_e) => {
                        error!("Failed to build async client");
                        return ExitCode::FAILURE
                    }
                };

                let Ok(idprovider) = KanidmProvider::new(
                    rsclient,
                    kconfig,
                    SystemTime::now(),
                    &mut (&mut db_txn).into(),
                    &mut hsm,
                    &machine_key
                ) else {
                    error!("Failed to configure Kanidm Provider");
                    return ExitCode::FAILURE
                };

                // Now stacked for the resolver.
                clients.push(Arc::new(idprovider));
                info!("Started kanidm provider");
            }

            drop(machine_key);

            if let Err(err) = db_txn.commit() {
                error!(?err, "Failed to commit database transaction, unable to proceed");
                return ExitCode::FAILURE
            }

            if !cfg.default_shell.is_empty() {
                let shell_path = PathBuf::from_str(&cfg.default_shell).expect("Failed to build a representation of your default_shell path!");
                if !shell_path.exists() {
                    error!("Cannot find configured default shell at {}, this could cause login issues!", shell_path.display())
                }
            }

            // Okay, the hsm is now loaded and ready to go.
            let cl_inner = match Resolver::new(
                db,
                Arc::new(system_provider),
                clients,
                hsm,
                cfg.cache_timeout,
                cfg.default_shell.clone(),
                cfg.home_prefix.clone(),
                cfg.home_attr,
                cfg.home_alias,
                cfg.uid_attr_map,
                cfg.gid_attr_map,
            )
            .await
            {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to build cache layer.");
                    return ExitCode::FAILURE
                }
            };

            let cachelayer = Arc::new(cl_inner);

            // Setup the root-only tasks socket. Take away all other access bits.
            let before = unsafe { umask(0o0077) };
            let task_listener = match UnixListener::bind(cfg.task_sock_path.as_str()) {
                Ok(l) => l,
                Err(_e) => {
                    let diag = kanidm_lib_file_permissions::diagnose_path(cfg.task_sock_path.as_ref());
                    info!(%diag);
                    error!("Failed to bind UNIX socket {}", cfg.task_sock_path.as_str());
                    return ExitCode::FAILURE
                }
            };
            // Undo umask changes.
            let _ = unsafe { umask(before) };

            // The tasks ... well task. Tasks-task. Anyway, the tasks-task is bidirectional
            // in its communication to the tasks-daemon. We submit tasks to the tasks-daemon
            // via this channel here -\
            //                        |
            //                        v
            let (task_channel_tx, mut task_channel_rx) = channel(16);
            let task_channel_tx = Arc::new(task_channel_tx);
            let task_channel_tx_cln = task_channel_tx.clone();
            // Each submitted task contains a oneshot channel allowing the tasks-task to
            // notify the submitter of the task that the task is completed.

            // This channel is for the second case - the tasks-daemon can send us
            // unsolicited dm's about system state, and when these occure we need to
            // response to these notifications. Because each potential dm that the
            // daemon can send us has a specific intent, we need a channel for each
            // type of notification that we could get. This channel is for when
            // the tasks daemon has a reloaded shadow database for us to process
            // and cache:
            let (notify_shadow_channel_tx, mut notify_shadow_channel_rx) = channel(16);
            let notify_shadow_channel_tx = Arc::new(notify_shadow_channel_tx);

            // Broadcast receivers so that the tasks-task can be shut down when we get
            // signals etc.
            let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);
            let mut c_broadcast_rx = broadcast_tx.subscribe();
            let mut d_broadcast_rx = broadcast_tx.subscribe();

            let task_b = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // Wait on the broadcast to see if we need to close down.
                        _ = c_broadcast_rx.recv() => {
                            break;
                        }
                        accept_res = task_listener.accept() => {
                            match accept_res {
                                Ok((socket, _addr)) => {
                                    // Did it come from root? If not, they don't have the needed
                                    // permissions to actually be a task handler, and we wouldn't
                                    // want to leak to anyone else anyway.
                                    if let Ok(ucred) = socket.peer_cred() {
                                        if ucred.uid() != 0 {
                                            // move along.
                                            warn!("Task handler not running as root, ignoring ...");
                                            continue;
                                        }
                                    } else {
                                        // move along.
                                        warn!("Unable to determine socked peer cred, ignoring ...");
                                        continue;
                                    };
                                    debug!("A task handler has connected.");
                                    // It did? Great, now we can wait and spin on that one
                                    // client.

                                    // We have to check for signals here else this tasks waits forever.
                                    if let Err(err) = handle_task_client(socket, &notify_shadow_channel_tx, &mut task_channel_rx, &mut d_broadcast_rx).await {
                                        error!(?err, "Task client error occurred");
                                    }
                                    // If they disconnect we go back to accept.
                                }
                                Err(err) => {
                                    error!("Task Accept error -> {:?}", err);
                                }
                            }
                        }
                    }
                    // done
                }
                info!("Stopped task connector");
            });

            // ====== Listen for shadow change notification from tasks ======

            let shadow_notify_cachelayer = cachelayer.clone();
            let mut c_broadcast_rx = broadcast_tx.subscribe();

            let task_c = tokio::spawn(async move {
                debug!("Spawned shadow reload task handler");
                loop {
                    tokio::select! {
                        _ = c_broadcast_rx.recv() => {
                            break;
                        }
                        Some(EtcDb {
                            users, shadow, groups
                        }) = notify_shadow_channel_rx.recv() => {
                            shadow_notify_cachelayer
                                .reload_system_identities(users, shadow, groups)
                                .await;
                        }
                    }
                }
                info!("Stopped shadow reload task handler");
            });

            // TODO: Setup a task that handles pre-fetching here.

            // Set the umask while we open the path for most clients.
            let before = unsafe { umask(0) };
            let listener = match UnixListener::bind(cfg.sock_path.as_str()) {
                Ok(l) => l,
                Err(_e) => {
                    error!("Failed to bind UNIX socket at {}", cfg.sock_path.as_str());
                    return ExitCode::FAILURE
                }
            };
            // Undo umask changes.
            let _ = unsafe { umask(before) };

            let task_a = tokio::spawn(async move {
                loop {
                    let tc_tx = task_channel_tx_cln.clone();

                    tokio::select! {
                        _ = broadcast_rx.recv() => {
                            break;
                        }
                        accept_res = listener.accept() => {
                            match accept_res {
                                Ok((socket, _addr)) => {
                                    let cachelayer_ref = cachelayer.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_client(socket, cachelayer_ref.clone(), &tc_tx).await
                                        {
                                            error!("handle_client error occurred; error = {:?}", e);
                                        }
                                    });
                                }
                                Err(err) => {
                                    error!("Error while handling connection -> {:?}", err);
                                }
                            }
                        }
                    }

                }
                info!("Stopped resolver");
            });

            info!("Server started ...");

            // End the startup span, we can now proceed.
            drop(_enter);

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
            info!("Signal received, sending down signal to tasks");
            // Send a broadcast that we are done.
            if let Err(e) = broadcast_tx.send(true) {
                error!("Unable to shutdown workers {:?}", e);
            }

            let _ = task_a.await;
            let _ = task_b.await;
            let _ = task_c.await;

            ExitCode::SUCCESS
    })
    .await
    // TODO: can we catch signals to clean up sockets etc, especially handy when running as root
}
