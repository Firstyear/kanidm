use self::codec::{ConsumerRequest, SupplierResponse};
use crate::CoreAction;
use config::{RepNodeConfig, ReplicationConfiguration};
use crypto_glue::{traits::EncodeDer, x509::Certificate};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use kanidmd_lib::prelude::duration_from_epoch_now;
use kanidmd_lib::prelude::IdmServer;
use kanidmd_lib::repl::proto::ConsumerState;
use kanidmd_lib::server::QueryServerTransaction;
use rustls::{
    client::ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::{ServerConfig, WebPkiClientVerifier},
    RootCertStore,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::{interval, sleep, timeout};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::{client::TlsStream, TlsAcceptor, TlsConnector};
use tokio_util::codec::{Framed, FramedRead, FramedWrite};
use tracing::{error, Instrument};
use url::Url;
use uuid::Uuid;

mod codec;
pub(crate) mod config;

pub(crate) enum ReplCtrl {
    GetCertificate {
        respond: oneshot::Sender<Certificate>,
    },
    RenewCertificate {
        respond: oneshot::Sender<bool>,
    },
    RefreshConsumer {
        respond: oneshot::Sender<mpsc::Receiver<()>>,
    },
}

#[derive(Debug, Clone)]
enum ReplConsumerCtrl {
    Stop,
    Refresh(Arc<Mutex<(bool, mpsc::Sender<()>)>>),
}

pub(crate) struct ReplicationServerHandles {
    pub repl_handle: tokio::task::JoinHandle<()>,
    pub ctrl_tx: mpsc::Sender<ReplCtrl>,
}

pub(crate) async fn create_repl_server(
    idms: Arc<IdmServer>,
    repl_config: &ReplicationConfiguration,
    rx: broadcast::Receiver<CoreAction>,
) -> Result<ReplicationServerHandles, ()> {
    // We need to start the tcp listener. This will persist over ssl reloads!
    let listener = TcpListener::bind(&repl_config.bindaddress)
        .await
        .map_err(|e| {
            error!(
                "Could not bind to replication address {} -> {:?}",
                repl_config.bindaddress, e
            );
        })?;

    // Create the control channel. Use a low msg count, there won't be that much going on.
    let (ctrl_tx, ctrl_rx) = mpsc::channel(4);

    // We need to start the tcp listener. This will persist over ssl reloads!
    info!(
        "Starting replication interface https://{} ...",
        repl_config.bindaddress
    );
    let repl_handle: JoinHandle<()> = tokio::spawn(repl_acceptor(
        listener,
        idms,
        repl_config.clone(),
        rx,
        ctrl_rx,
    ));

    info!("Created replication interface");
    Ok(ReplicationServerHandles {
        repl_handle,
        ctrl_tx,
    })
}

#[instrument(level = "debug", skip_all)]
/// This returns the remote address that worked, so you can try that first next time
async fn repl_consumer_connect_supplier(
    server_name: &ServerName<'static>,
    sock_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    consumer_conn_settings: &ConsumerConnSettings,
) -> Option<(
    SocketAddr,
    Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
)> {
    // This is pretty gnarly, but we need to loop to try out each socket addr.
    for sock_addr in sock_addrs {
        debug!(
            "Attempting to connect to {} replica via {}",
            server_name.to_str(),
            sock_addr
        );

        let tcpstream = match timeout(
            consumer_conn_settings.replica_connect_timeout,
            TcpStream::connect(sock_addr),
        )
        .await
        {
            Ok(Ok(tc)) => {
                trace!("Connection established to peer on {:?}", sock_addr);
                tc
            }
            Ok(Err(err)) => {
                debug!(?err, "Failed to connect to {}", sock_addr);
                continue;
            }
            Err(_) => {
                debug!("Timeout connecting to {}", sock_addr);
                continue;
            }
        };

        let tlsstream = match timeout(
            consumer_conn_settings.replica_connect_timeout,
            tls_connector.connect(server_name.to_owned(), tcpstream),
        )
        .await
        {
            Ok(Ok(ta)) => ta,
            Ok(Err(e)) => {
                error!("Replication client TLS setup error, continuing -> {:?}", e);
                continue;
            }
            Err(_) => {
                debug!("Timeout establishing TLS to {}", sock_addr);
                continue;
            }
        };

        let supplier_conn = Framed::new(
            tlsstream,
            codec::ConsumerCodec::new(consumer_conn_settings.max_frame_bytes),
        );
        // "hey this one worked, try it first next time!"
        return Some((sock_addr.to_owned(), supplier_conn));
    }

    error!(
        "Unable to connect to supplier, tried to connect to {:?}",
        sock_addrs
    );
    None
}

async fn repl_consumer_disconnect_supplier(
    supplier_conn: Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
    consumer_conn_settings: &ConsumerConnSettings,
) {
    let mut tls_stream = supplier_conn.into_inner();

    match timeout(
        consumer_conn_settings.replica_connect_timeout,
        tls_stream.shutdown(),
    )
    .await
    {
        Ok(Ok(_)) => debug!("Connection closed successfully"),
        Ok(Err(tls_err)) => warn!(?tls_err, "Unable to cleanly shutdown TLS client connection"),
        Err(_) => error!("Timeout attempting to close connection"),
    }
}

/// This returns the socket address that worked, so you can try that first next time
#[instrument(
    level="info",
    skip(refresh_coord, tls_connector, idms, consumer_conn_settings),
    fields(eventid = Uuid::new_v4().to_string(), server_name = %server_name.to_str())
)]
async fn repl_run_consumer_refresh(
    refresh_coord: Arc<Mutex<(bool, mpsc::Sender<()>)>>,
    server_name: &ServerName<'static>,
    sock_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    idms: &IdmServer,
    consumer_conn_settings: &ConsumerConnSettings,
) -> Result<Option<SocketAddr>, ()> {
    // Take the refresh lock. Note that every replication consumer *should* end up here
    // behind this lock, but only one can proceed. This is what we want!

    let refresh_coord_guard = refresh_coord.lock().await;

    // Simple case - task is already done.
    if refresh_coord_guard.0 {
        trace!("Refresh already completed by another task, return.");
        return Ok(None);
    }

    // Okay, we need to proceed. Open the connection.
    let (addr, mut supplier_conn) = repl_consumer_connect_supplier(
        server_name,
        sock_addrs,
        tls_connector,
        consumer_conn_settings,
    )
    .await
    .ok_or(())?;

    let result = repl_run_consumer_refresh_inner(
        addr,
        &mut supplier_conn,
        refresh_coord_guard,
        idms,
        consumer_conn_settings,
    )
    .await;

    // disconnect the connection if possible.
    repl_consumer_disconnect_supplier(supplier_conn, consumer_conn_settings).await;

    result
}

async fn repl_run_consumer_refresh_inner(
    addr: SocketAddr,
    supplier_conn: &mut Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
    mut refresh_coord_guard: MutexGuard<'_, (bool, mpsc::Sender<()>)>,
    idms: &IdmServer,
    consumer_conn_settings: &ConsumerConnSettings,
) -> Result<Option<SocketAddr>, ()> {
    // If we fail at any point, just RETURN because this leaves the next task to attempt, or
    // the channel drops and that tells the caller this failed.

    match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.send(ConsumerRequest::Refresh),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!(?err, "consumer encode error, unable to continue.");
            return Err(());
        }
        Err(_) => {
            error!("consumer request timeout error, unable to continue.");
            return Err(());
        }
    };

    let refresh = match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.next(),
    )
    .await
    {
        Ok(Some(Ok(SupplierResponse::Refresh(changes)))) => {
            // Success - return to bypass the error message.
            changes
        }
        Ok(Some(Ok(SupplierResponse::Pong))) | Ok(Some(Ok(SupplierResponse::Incremental(_)))) => {
            error!("Supplier Response contains invalid State");
            return Err(());
        }
        Ok(Some(Err(codec_err))) => {
            error!(?codec_err, "Consumer decode error, unable to continue.");
            return Err(());
        }
        Ok(None) => {
            error!("Connection closed");
            return Err(());
        }
        Err(_) => {
            error!("consumer response timeout error, unable to continue.");
            return Err(());
        }
    };

    // Now apply the refresh if possible
    {
        // Scope the transaction.
        let ct = duration_from_epoch_now();
        idms.proxy_write(ct)
            .await
            .and_then(|mut write_txn| {
                write_txn
                    .qs_write
                    .consumer_apply_refresh(refresh)
                    .and_then(|cs| write_txn.commit().map(|()| cs))
            })
            .map_err(|err| error!(?err, "Consumer was not able to apply refresh."))?;
    }

    // Now mark the refresh as complete AND indicate it to the channel.
    refresh_coord_guard.0 = true;
    if refresh_coord_guard.1.send(()).await.is_err() {
        warn!("Unable to signal to caller that refresh has completed.");
    }

    // Here the coord guard will drop and every other task proceeds.

    info!("Replication refresh was successful.");
    Ok(Some(addr))
}

#[instrument(
    level="info",
    skip(tls_connector, idms, consumer_conn_settings, server_name),
    fields(eventid = Uuid::new_v4().to_string(), server_name = %server_name.to_str())
)]
async fn repl_run_consumer(
    server_name: &ServerName<'static>,
    sock_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    automatic_refresh: bool,
    idms: &IdmServer,
    consumer_conn_settings: &ConsumerConnSettings,
    task_tx: &mut broadcast::Sender<ReplConsumerCtrl>,
) -> Option<SocketAddr> {
    let (socket_addr, mut supplier_conn) = repl_consumer_connect_supplier(
        server_name,
        sock_addrs,
        tls_connector,
        consumer_conn_settings,
    )
    .await?;

    let result = repl_run_consumer_inner(
        socket_addr,
        &mut supplier_conn,
        idms,
        automatic_refresh,
        consumer_conn_settings,
        task_tx,
    )
    .await;

    repl_consumer_disconnect_supplier(supplier_conn, consumer_conn_settings).await;

    result
}

async fn repl_run_consumer_inner(
    socket_addr: SocketAddr,
    supplier_conn: &mut Framed<TlsStream<TcpStream>, codec::ConsumerCodec>,
    idms: &IdmServer,
    automatic_refresh: bool,
    consumer_conn_settings: &ConsumerConnSettings,
    task_tx: &mut broadcast::Sender<ReplConsumerCtrl>,
) -> Option<SocketAddr> {
    // Perform incremental.
    let consumer_ruv_range = {
        let consumer_state = idms
            .proxy_read()
            .await
            .and_then(|mut read_txn| read_txn.qs_read.consumer_get_state());
        match consumer_state {
            Ok(ruv_range) => ruv_range,
            Err(err) => {
                error!(
                    ?err,
                    "consumer ruv range could not be accessed, unable to continue."
                );
                return None;
            }
        }
    };

    match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.send(ConsumerRequest::Incremental(consumer_ruv_range)),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!(?err, "consumer encode error, unable to continue.");
            return None;
        }
        Err(_) => {
            error!("consumer request timeout, unable to continue");
            return None;
        }
    };

    let changes = match timeout(
        consumer_conn_settings.replica_connect_timeout,
        supplier_conn.next(),
    )
    .await
    {
        Ok(Some(Ok(SupplierResponse::Incremental(changes)))) => changes,
        Ok(Some(Ok(SupplierResponse::Pong))) | Ok(Some(Ok(SupplierResponse::Refresh(_)))) => {
            error!("Supplier Response contains invalid state");
            return None;
        }
        Ok(Some(Err(err))) => {
            error!(?err, "Consumer decode error, unable to continue.");
            return None;
        }
        Ok(None) => {
            error!("Consumer connection closed, unable to continue.");
            return None;
        }

        Err(_) => {
            error!("consumer response timeout, unable to continue");
            return None;
        }
    };

    // Now apply the changes if possible
    let consumer_state = {
        let ct = duration_from_epoch_now();
        match idms.proxy_write(ct).await.and_then(|mut write_txn| {
            write_txn
                .qs_write
                .consumer_apply_changes(changes)
                .and_then(|cs| write_txn.commit().map(|()| cs))
        }) {
            Ok(state) => state,
            Err(err) => {
                error!(?err, "Consumer was not able to apply changes.");
                return None;
            }
        }
    };

    match consumer_state {
        ConsumerState::Ok => {
            info!("Incremental Replication Success");
            // return to bypass the failure message.
            Some(socket_addr)
        }
        ConsumerState::RefreshRequired => {
            if automatic_refresh {
                warn!("Consumer is out of date and must be refreshed. This will happen *now*.");

                let (tx, mut rx) = mpsc::channel(1);

                let refresh_coord = Arc::new(Mutex::new((false, tx)));

                if task_tx
                    .send(ReplConsumerCtrl::Refresh(refresh_coord))
                    .is_err()
                {
                    error!("Unable to begin replication consumer refresh, tasks are unable to be notified.");
                } else {
                    tokio::spawn(async move {
                        match rx.recv().await {
                            Some(()) => {
                                info!("replication consumer refresh complete!")
                            }
                            None => {
                                warn!("refresh task was lost with no response!")
                            }
                        }
                    });
                }

                None
            } else {
                error!("Consumer is out of date and must be refreshed. You must manually resolve this situation.");
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ConsumerConnSettings {
    max_frame_bytes: usize,
    task_poll_interval: Duration,
    replica_connect_timeout: Duration,
}

#[allow(clippy::too_many_arguments)]
async fn repl_task(
    origin: Url,

    client_key: PrivateKeyDer<'static>,
    client_cert: CertificateDer<'static>,
    supplier_cert: CertificateDer<'static>,

    consumer_conn_settings: ConsumerConnSettings,
    mut task_rx: broadcast::Receiver<ReplConsumerCtrl>,
    mut task_tx: broadcast::Sender<ReplConsumerCtrl>,
    automatic_refresh: bool,
    idms: Arc<IdmServer>,
) {
    if origin.scheme() != "repl" {
        error!("Replica origin is not repl:// - refusing to proceed.");
        return;
    }

    let domain = match origin.domain() {
        Some(d) => d,
        None => {
            error!("Replica origin does not have a valid domain name, unable to proceed. Perhaps you tried to use an ip address?");
            return;
        }
    };

    let Ok(server_name) = ServerName::try_from(domain.to_owned()) else {
        error!("Replica origin does not have a valid domain name, unable to proceed. Perhaps you tried to use an ip address?");
        return;
    };

    // Add the supplier cert.
    // ⚠️  note that here we need to build a new cert store. This is because
    // we want to pin a single certificate!
    let mut root_cert_store = RootCertStore::empty();
    if let Err(err) = root_cert_store.add(supplier_cert) {
        error!(?err, "Replica supplier cert invalid.");
        return;
    };

    let provider = rustls::crypto::aws_lc_rs::default_provider().into();

    let tls_client_config = match ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| {
            builder
                .with_root_certificates(root_cert_store)
                .with_client_auth_cert(vec![client_cert], client_key)
        }) {
        Ok(ccb) => ccb,
        Err(err) => {
            error!(?err, "Unable to build TLS client configuration");
            return;
        }
    };

    let tls_connector = TlsConnector::from(Arc::new(tls_client_config));

    let mut repl_interval = interval(consumer_conn_settings.task_poll_interval);

    info!("Replica task for {} has started.", origin);

    // we keep track of the "last known good" socketaddr so we can try that first next time.
    let mut last_working_address: Option<SocketAddr> = None;

    // Okay, all the parameters are set up. Now we replicate on our interval.
    loop {
        // we resolve the DNS entry to the ip:port each time we attempt a connection to avoid stale
        // DNS issues, ref #3188. If we are unable to resolve the address, we backoff and try again
        // as in something like docker the address may change frequently.
        //
        // Note, if DNS isn't available, we can proceed with the last used working address too. This
        // prevents DNS (or lack thereof) from causing a replication outage.
        let mut sorted_socket_addrs = vec![];

        // If the target address worked last time, then let's use it this time!
        if let Some(addr) = last_working_address {
            debug!(?last_working_address);
            sorted_socket_addrs.push(addr);
        };

        // Default to port 443 if not set in the origin
        match origin.socket_addrs(|| Some(443)) {
            Ok(mut socket_addrs) => {
                // Make every address unique.
                socket_addrs.sort_unstable();
                socket_addrs.dedup();

                // The only possible conflict is with the last working address,
                // so lets just check that.
                socket_addrs.into_iter().for_each(|addr| {
                    if Some(&addr) != last_working_address.as_ref() {
                        // Not already present, append
                        sorted_socket_addrs.push(addr);
                    }
                });
            }
            Err(err) => {
                if let Some(addr) = last_working_address {
                    warn!(
                        ?err,
                        "Unable to resolve '{origin}' to ip:port, using last known working address '{addr}'"
                    );
                } else {
                    warn!(?err, "Unable to resolve '{origin}' to ip:port.");
                }
            }
        };

        if sorted_socket_addrs.is_empty() {
            warn!(
                "No replication addresses available, delaying replication operation for '{origin}'"
            );
            repl_interval.tick().await;
            continue;
        }

        tokio::select! {
            Ok(task) = task_rx.recv() => {
                match task {
                    ReplConsumerCtrl::Stop => break,
                    ReplConsumerCtrl::Refresh ( refresh_coord ) => {
                        last_working_address = (repl_run_consumer_refresh(
                            refresh_coord,
                            &server_name,
                            &sorted_socket_addrs,
                            &tls_connector,
                            &idms,
                            &consumer_conn_settings
                        )
                        .await).unwrap_or_default();
                    }
                }
            }
            _ = repl_interval.tick() => {
                // Interval passed, attempt a replication run.
                repl_run_consumer(
                    &server_name,
                    &sorted_socket_addrs,
                    &tls_connector,
                    automatic_refresh,
                    &idms,
                    &consumer_conn_settings,
                    &mut task_tx
                )
                .await;
            }
        }
    }

    info!("Replica task for {} has stopped.", origin);
}

#[instrument(level = "debug", skip_all)]
async fn handle_repl_conn(
    max_frame_bytes: usize,
    tcpstream: TcpStream,
    client_address: SocketAddr,
    tls_acceptor: TlsAcceptor,
    idms: Arc<IdmServer>,
) {
    debug!(?client_address, "replication client connected 🛫");

    let tlsstream = match tls_acceptor.accept(tcpstream).await {
        Ok(ta) => ta,
        Err(err) => {
            error!(?err, "Replication TLS setup error, disconnecting client");
            return;
        }
    };

    let (r, w) = tokio::io::split(tlsstream);
    let mut r = FramedRead::new(r, codec::SupplierCodec::new(max_frame_bytes));
    let mut w = FramedWrite::new(w, codec::SupplierCodec::new(max_frame_bytes));

    while let Some(codec_msg) = r.next().await {
        match codec_msg {
            Ok(ConsumerRequest::Ping) => {
                debug!("consumer requested ping");
                if let Err(err) = w.send(SupplierResponse::Pong).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Ok(ConsumerRequest::Incremental(consumer_ruv_range)) => {
                let changes = match idms.proxy_read().await.and_then(|mut read_txn| {
                    read_txn
                        .qs_read
                        .supplier_provide_changes(consumer_ruv_range)
                }) {
                    Ok(changes) => changes,
                    Err(err) => {
                        error!(?err, "supplier provide changes failed.");
                        break;
                    }
                };

                if let Err(err) = w.send(SupplierResponse::Incremental(changes)).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Ok(ConsumerRequest::Refresh) => {
                let changes = match idms
                    .proxy_read()
                    .await
                    .and_then(|mut read_txn| read_txn.qs_read.supplier_provide_refresh())
                {
                    Ok(changes) => changes,
                    Err(err) => {
                        error!(?err, "supplier provide refresh failed.");
                        break;
                    }
                };

                if let Err(err) = w.send(SupplierResponse::Refresh(changes)).await {
                    error!(?err, "supplier encode error, unable to continue.");
                    break;
                }
            }
            Err(err) => {
                error!(?err, "supplier decode error, unable to continue.");
                break;
            }
        }
    }

    debug!(?client_address, "replication client disconnected 🛬");
}

/// This is the main acceptor for the replication server.
async fn repl_acceptor(
    listener: TcpListener,
    idms: Arc<IdmServer>,
    repl_config: ReplicationConfiguration,
    mut rx: broadcast::Receiver<CoreAction>,
    mut ctrl_rx: mpsc::Receiver<ReplCtrl>,
) {
    info!("Starting Replication Acceptor ...");
    // Persistent parts
    // These all probably need changes later ...
    let replica_connect_timeout = Duration::from_secs(5);
    let mut retry_timeout = Duration::from_secs(1);
    let max_frame_bytes = 268435456;

    let consumer_conn_settings = ConsumerConnSettings {
        max_frame_bytes,
        task_poll_interval: repl_config.get_task_poll_interval(),
        replica_connect_timeout,
    };

    // Setup a broadcast to control our tasks.
    let (task_tx, task_rx1) = broadcast::channel(1);
    // Note, we drop this task here since each task will re-subscribe. That way the
    // broadcast doesn't jam up because we aren't draining this task.
    drop(task_rx1);
    let mut task_handles = VecDeque::new();

    // Create another broadcast to control the replication tasks and their need to reload.

    // Spawn a KRC communication task?

    // In future we need to update this from the KRC if configured, and we default this
    // to "empty". But if this map exists in the config, we have to always use that.
    let replication_node_map = repl_config.manual.clone();
    let domain_name = match repl_config.origin.domain() {
        Some(n) => n.to_string(),
        None => {
            error!("Unable to start replication, replication origin does not contain a valid domain name. Perhaps you tried to use an ip address?");
            return;
        }
    };

    // This needs to have an event loop that can respond to changes.
    // For now we just design it to reload ssl if the map changes internally.
    'event: loop {
        // Don't block shutdowns while we are waiting here.
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => break 'event,
                    CoreAction::Reload => {}
                }
            }
            _ = sleep(retry_timeout) => {}
        }

        // The timeout is initially small, we increase it here to prevent spinning too much.
        retry_timeout = Duration::from_secs(60);

        info!("Starting replication reload ...");
        // Tell existing tasks to shutdown.
        // Note: We ignore the result here since an err can occur *if* there are
        // no tasks currently listening on the channel.
        info!("Stopping {} Replication Tasks ...", task_handles.len());
        debug_assert!(task_handles.len() >= task_tx.receiver_count());
        let _ = task_tx.send(ReplConsumerCtrl::Stop);
        for task_handle in task_handles.drain(..) {
            // Let each task join.
            let res: Result<(), _> = task_handle.await;
            if res.is_err() {
                warn!("Failed to join replication task, continuing ...");
            }
        }

        // Now we can start to re-load configurations and setup our client tasks
        // as well.

        // Get our private key / cert.
        let res = {
            let ct = duration_from_epoch_now();
            idms.proxy_write(ct).await.and_then(|mut idms_prox_write| {
                idms_prox_write
                    .qs_write
                    .supplier_get_key_cert(&domain_name)
                    .and_then(|res| idms_prox_write.commit().map(|()| res))
            })
        };

        let (server_key, server_cert) = match res {
            Ok(r) => r,
            Err(err) => {
                error!(?err, "CRITICAL: Unable to access supplier certificate/key.");
                continue 'event;
            }
        };

        info!(
            replication_cert_not_before = ?server_cert.tbs_certificate.validity.not_before,
            replication_cert_not_after = ?server_cert.tbs_certificate.validity.not_after,
        );

        // rustls expects these to be der
        let Ok(server_key_der) = PrivateKeyDer::try_from(server_key.as_bytes().to_vec()) else {
            error!("CRITICAL: Unable to convert server key from DER.");
            continue 'event;
        };

        let Ok(server_cert_der) = server_cert.to_der().map(CertificateDer::from) else {
            error!("CRITICAL: Unable to convert server cert to DER.");
            continue 'event;
        };

        let mut client_certs = Vec::new();

        // For each node in the map, either spawn a task to pull from that node,
        // or setup the node as allowed to pull from us.
        for (origin, node) in replication_node_map.iter() {
            // Setup client certs
            match node {
                RepNodeConfig::MutualPull {
                    partner_cert: consumer_cert,
                    automatic_refresh: _,
                }
                | RepNodeConfig::AllowPull { consumer_cert } => {
                    let Ok(consumer_cert_der) = consumer_cert.to_der().map(CertificateDer::from)
                    else {
                        warn!("WARNING: Unable to convert client cert to DER.");
                        continue 'event;
                    };

                    client_certs.push(consumer_cert_der)
                }
                RepNodeConfig::Pull {
                    supplier_cert: _,
                    automatic_refresh: _,
                } => {}
            };

            match node {
                RepNodeConfig::MutualPull {
                    partner_cert: supplier_cert,
                    automatic_refresh,
                }
                | RepNodeConfig::Pull {
                    supplier_cert,
                    automatic_refresh,
                } => {
                    let Ok(supplier_cert_der) = supplier_cert.to_der().map(CertificateDer::from)
                    else {
                        warn!("WARNING: Unable to convert client cert to DER.");
                        continue 'event;
                    };

                    let task_rx = task_tx.subscribe();
                    let task_tx_c = task_tx.clone();

                    let handle: JoinHandle<()> = tokio::spawn(repl_task(
                        origin.clone(),
                        server_key_der.clone_key(),
                        server_cert_der.clone(),
                        supplier_cert_der.clone(),
                        consumer_conn_settings.clone(),
                        task_rx,
                        task_tx_c,
                        *automatic_refresh,
                        idms.clone(),
                    ));

                    task_handles.push_back(handle);
                    debug_assert_eq!(task_handles.len(), task_tx.receiver_count());
                }
                RepNodeConfig::AllowPull { consumer_cert: _ } => {}
            };
        }

        // ⚠️  This section is critical to the security of replication
        //    Since replication relies on mTLS we MUST ensure these options
        //    are absolutely correct!
        //
        // Setup the TLS builder.

        // ⚠️  CRITICAL - ensure that the cert store only has client certs from
        // the repl map added.

        let tls_acceptor = if client_certs.is_empty() {
            warn!("No replication client certs are available, replication connections will be ignored.");
            None
        } else {
            let mut client_cert_roots = RootCertStore::empty();

            for client_cert in client_certs.into_iter() {
                if let Err(err) = client_cert_roots.add(client_cert) {
                    error!(?err, "CRITICAL, unable to add client certificate.");
                    continue 'event;
                }
            }

            let provider: Arc<_> = rustls::crypto::aws_lc_rs::default_provider().into();

            let client_cert_verifier_result = WebPkiClientVerifier::builder_with_provider(
                client_cert_roots.into(),
                provider.clone(),
            )
            // We don't allow clients that lack a certificate to correct.
            // allow_unauthenticated()
            .build();

            let client_cert_verifier = match client_cert_verifier_result {
                Ok(ccv) => ccv,
                Err(err) => {
                    error!(
                        ?err,
                        "CRITICAL, unable to configure client certificate verifier."
                    );
                    continue 'event;
                }
            };

            let tls_server_config = match ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .and_then(|builder| {
                    builder
                        .with_client_cert_verifier(client_cert_verifier)
                        .with_single_cert(vec![server_cert_der], server_key_der)
                }) {
                Ok(tls_server_config) => tls_server_config,
                Err(err) => {
                    error!(
                        ?err,
                        "CRITICAL, unable to create TLS Server Config. Will retry ..."
                    );
                    continue 'event;
                }
            };

            Some(TlsAcceptor::from(Arc::new(tls_server_config)))
        };

        loop {
            // This is great to diagnose when spans are entered or present and they capture
            // things incorrectly.
            // eprintln!("🔥 C ---> {:?}", tracing::Span::current());
            let eventid = Uuid::new_v4();

            tokio::select! {
                Ok(action) = rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break 'event,
                        CoreAction::Reload => {}
                    }
                }
                Some(ctrl_msg) = ctrl_rx.recv() => {
                    match ctrl_msg {
                        ReplCtrl::GetCertificate {
                            respond
                        } => {
                            let _span = debug_span!("supplier_accept_loop", uuid = ?eventid).entered();
                            if respond.send(server_cert.clone()).is_err() {
                                warn!("Server certificate was requested, but requsetor disconnected");
                            } else {
                                trace!("Sent server certificate via control channel");
                            }
                        }
                        ReplCtrl::RenewCertificate {
                            respond
                        } => {
                            let span = debug_span!("supplier_accept_loop", uuid = ?eventid);
                            async {
                                debug!("renewing replication certificate ...");
                                // Renew the cert.
                                let res = {
                                    let ct = duration_from_epoch_now();
                                    idms.proxy_write(ct).await
                                        .and_then(|mut idms_prox_write|
                                    idms_prox_write
                                        .qs_write
                                        .supplier_renew_key_cert(&domain_name)
                                        .and_then(|res| idms_prox_write.commit().map(|()| res))
                                        )
                                };

                                let success = res.is_ok();

                                if let Err(err) = res {
                                    error!(?err, "failed to renew server certificate");
                                }

                                if respond.send(success).is_err() {
                                    warn!("Server certificate renewal was requested, but requester disconnected!");
                                } else {
                                    trace!("Sent server certificate renewal status via control channel");
                                }
                            }
                            .instrument(span)
                            .await;

                            // Start a reload.
                            continue 'event;
                        }
                        ReplCtrl::RefreshConsumer {
                            respond
                        } => {
                            // Indicate to consumer tasks that they should do a refresh.
                            let (tx, rx) = mpsc::channel(1);

                            let refresh_coord = Arc::new(
                                Mutex::new(
                                (
                                    false, tx
                                )
                                )
                            );

                            if task_tx.send(ReplConsumerCtrl::Refresh(refresh_coord)).is_err() {
                                error!("Unable to begin replication consumer refresh, tasks are unable to be notified.");
                            }

                            if respond.send(rx).is_err() {
                                warn!("Replication consumer refresh was requested, but requester disconnected");
                            } else {
                                trace!("Sent refresh comms channel to requester");
                            }
                        }
                    }
                }
                // Handle accepts.
                // Handle *reloads*
                /*
                _ = reload.recv() => {
                    info!("Initiating TLS reload");
                    continue
                }
                */
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((tcpstream, client_socket_addr)) => {
                            if let Some(clone_tls_acceptor) = tls_acceptor.clone() {
                                let clone_idms = idms.clone();
                                // We don't care about the join handle here - once a client connects
                                // it sticks to whatever ssl settings it had at launch.
                                tokio::spawn(
                                    handle_repl_conn(max_frame_bytes, tcpstream, client_socket_addr, clone_tls_acceptor, clone_idms)
                                );
                            } else {
                                // TLS is not setup, generally due to no accepted/trusted client
                                // certs being present. Drop the connection.
                                warn!("Ignoring connection from {client_socket_addr} as replication is not configured correctly.");
                                warn!("This is because you have not configured this server with trusted partner certificates.");
                            }
                        }
                        Err(e) => {
                            error!("replication acceptor error, continuing -> {:?}", e);
                        }
                    }
                }
            } // end select
              // Continue to poll/loop
        }
    }
    // Shutdown child tasks.
    info!("Stopping {} Replication Tasks ...", task_handles.len());
    debug_assert!(task_handles.len() >= task_tx.receiver_count());
    let _ = task_tx.send(ReplConsumerCtrl::Stop);
    for task_handle in task_handles.drain(..) {
        // Let each task join.
        let res: Result<(), _> = task_handle.await.map(|_| ());
        if res.is_err() {
            warn!("Failed to join replication task, continuing ...");
        }
    }

    info!("Stopped {}", super::TaskName::ReplicationSupervisor);
}
