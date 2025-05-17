use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use crate::repl::ReplCtrl;
use crate::CoreAction;
use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use kanidm_lib_crypto::serialise::x509b64;
use kanidm_utils_users::get_current_uid;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{span, Instrument, Level};
use uuid::Uuid;

pub use kanidm_proto::internal::{
    DomainInfo as ProtoDomainInfo, DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport,
    DomainUpgradeCheckStatus as ProtoDomainUpgradeCheckStatus,
};

#[derive(Serialize, Deserialize, Debug)]
pub enum AdminTaskRequest {
    RecoverAccount { name: String },
    ShowReplicationCertificate,
    RenewReplicationCertificate,
    RefreshReplicationConsumer,
    DomainShow,
    DomainUpgradeCheck,
    DomainRaise,
    DomainRemigrate { level: Option<u32> },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AdminTaskResponse {
    RecoverAccount {
        password: String,
    },
    ShowReplicationCertificate {
        cert: String,
    },
    DomainUpgradeCheck {
        report: ProtoDomainUpgradeCheckReport,
    },
    DomainRaise {
        level: u32,
    },
    DomainShow {
        domain_info: ProtoDomainInfo,
    },
    Success,
    Error,
}

#[derive(Default)]
pub struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = io::Error;
    type Item = AdminTaskResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<AdminTaskResponse>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<AdminTaskRequest> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: AdminTaskRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
struct ServerCodec;

impl Decoder for ServerCodec {
    type Error = io::Error;
    type Item = AdminTaskRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!("Attempting to decode request ...");
        match serde_json::from_slice::<AdminTaskRequest>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<AdminTaskResponse> for ServerCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: AdminTaskResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!("Attempting to send response -> {:?} ...", msg);
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            io::Error::other("JSON encode error")
        })?;
        dst.put(data.as_slice());
        Ok(())
    }
}

pub(crate) struct AdminActor;

impl AdminActor {
    pub async fn create_admin_sock(
        sock_path: &str,
        server_rw: &'static QueryServerWriteV1,
        server_ro: &'static QueryServerReadV1,
        mut broadcast_rx: broadcast::Receiver<CoreAction>,
        repl_ctrl_tx: Option<mpsc::Sender<ReplCtrl>>,
    ) -> Result<tokio::task::JoinHandle<()>, ()> {
        debug!("🧹 Cleaning up sockets from previous invocations");
        rm_if_exist(sock_path);

        // Setup the unix socket.
        let listener = match UnixListener::bind(sock_path) {
            Ok(l) => l,
            Err(e) => {
                error!(err = ?e, "Failed to bind UNIX socket {}", sock_path);
                return Err(());
            }
        };

        // what is the uid we are running as?
        let cuid = get_current_uid();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(action) = broadcast_rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                        }
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((socket, _addr)) => {
                                // Assert that the incoming connection is from root or
                                // our own uid.
                                // ⚠️  This underpins the security of this socket ⚠️
                                if let Ok(ucred) = socket.peer_cred() {
                                    let incoming_uid = ucred.uid();
                                    if incoming_uid == 0 || incoming_uid == cuid {
                                        // all good!
                                        info!(pid = ?ucred.pid(), "Allowing admin socket access");
                                    } else {
                                        warn!(%incoming_uid, "unauthorised user");
                                        continue;
                                    }
                                } else {
                                    error!("unable to determine peer credentials");
                                    continue;
                                };

                                // spawn the worker.
                                let task_repl_ctrl_tx = repl_ctrl_tx.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(socket, server_rw, server_ro, task_repl_ctrl_tx).await {
                                        error!(err = ?e, "admin client error");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(err = ?e, "admin socket accept error");
                            }
                        }
                    }
                }
            }
            info!("Stopped {}", super::TaskName::AdminSocket);
        });
        Ok(handle)
    }
}

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

async fn show_replication_certificate(ctrl_tx: &mut mpsc::Sender<ReplCtrl>) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::GetCertificate { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        return AdminTaskResponse::Error;
    }

    match rx.await {
        Ok(cert) => x509b64::cert_to_string(&cert)
            .map(|cert| AdminTaskResponse::ShowReplicationCertificate { cert })
            .unwrap_or(AdminTaskResponse::Error),
        Err(_) => {
            error!("replication control channel did not respond with certificate.");
            AdminTaskResponse::Error
        }
    }
}

async fn renew_replication_certificate(ctrl_tx: &mut mpsc::Sender<ReplCtrl>) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::RenewCertificate { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        return AdminTaskResponse::Error;
    }

    match rx.await {
        Ok(success) => {
            if success {
                show_replication_certificate(ctrl_tx).await
            } else {
                error!("replication control channel indicated that certificate renewal failed.");
                AdminTaskResponse::Error
            }
        }
        Err(_) => {
            error!("replication control channel did not respond with renewal status.");
            AdminTaskResponse::Error
        }
    }
}

async fn replication_consumer_refresh(ctrl_tx: &mut mpsc::Sender<ReplCtrl>) -> AdminTaskResponse {
    let (tx, rx) = oneshot::channel();

    if ctrl_tx
        .send(ReplCtrl::RefreshConsumer { respond: tx })
        .await
        .is_err()
    {
        error!("replication control channel has shutdown");
        return AdminTaskResponse::Error;
    }

    match rx.await {
        Ok(mut refresh_rx) => {
            if let Some(()) = refresh_rx.recv().await {
                info!("Replication refresh success");
                AdminTaskResponse::Success
            } else {
                error!("Replication refresh failed. Please inspect the logs.");
                AdminTaskResponse::Error
            }
        }
        Err(_) => {
            error!("replication control channel did not respond with refresh status.");
            AdminTaskResponse::Error
        }
    }
}

async fn handle_client(
    sock: UnixStream,
    server_rw: &'static QueryServerWriteV1,
    server_ro: &'static QueryServerReadV1,
    mut repl_ctrl_tx: Option<mpsc::Sender<ReplCtrl>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Accepted admin socket connection");

    let mut reqs = Framed::new(sock, ServerCodec);

    trace!("Waiting for requests ...");
    while let Some(Ok(req)) = reqs.next().await {
        // Setup the logging span
        let eventid = Uuid::new_v4();
        let nspan = span!(Level::INFO, "handle_admin_client_request", uuid = ?eventid);

        let resp = async {
            match req {
                AdminTaskRequest::RecoverAccount { name } => {
                    match server_rw.handle_admin_recover_account(name, eventid).await {
                        Ok(password) => AdminTaskResponse::RecoverAccount { password },
                        Err(e) => {
                            error!(err = ?e, "error during recover-account");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::ShowReplicationCertificate => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => show_replication_certificate(ctrl_tx).await,
                    None => {
                        error!("replication not configured, unable to display certificate.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::RenewReplicationCertificate => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => renew_replication_certificate(ctrl_tx).await,
                    None => {
                        error!("replication not configured, unable to renew certificate.");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::RefreshReplicationConsumer => match repl_ctrl_tx.as_mut() {
                    Some(ctrl_tx) => replication_consumer_refresh(ctrl_tx).await,
                    None => {
                        error!("replication not configured, unable to refresh consumer.");
                        AdminTaskResponse::Error
                    }
                },

                AdminTaskRequest::DomainShow => match server_ro.handle_domain_show(eventid).await {
                    Ok(domain_info) => AdminTaskResponse::DomainShow { domain_info },
                    Err(e) => {
                        error!(err = ?e, "error during domain show");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::DomainUpgradeCheck => {
                    match server_ro.handle_domain_upgrade_check(eventid).await {
                        Ok(report) => AdminTaskResponse::DomainUpgradeCheck { report },
                        Err(e) => {
                            error!(err = ?e, "error during domain upgrade checkr");
                            AdminTaskResponse::Error
                        }
                    }
                }
                AdminTaskRequest::DomainRaise => match server_rw.handle_domain_raise(eventid).await
                {
                    Ok(level) => AdminTaskResponse::DomainRaise { level },
                    Err(e) => {
                        error!(err = ?e, "error during domain raise");
                        AdminTaskResponse::Error
                    }
                },
                AdminTaskRequest::DomainRemigrate { level } => {
                    match server_rw.handle_domain_remigrate(level, eventid).await {
                        Ok(()) => AdminTaskResponse::Success,
                        Err(e) => {
                            error!(err = ?e, "error during domain remigrate");
                            AdminTaskResponse::Error
                        }
                    }
                }
            }
        }
        .instrument(nspan)
        .await;

        reqs.send(resp).await?;
        reqs.flush().await?;
    }

    debug!("Disconnecting client ...");
    Ok(())
}
