mod extractors;
mod generic;
mod javascript;
mod manifest;
mod middleware;
mod oauth2;
mod tests;
mod ui;
mod v1;
mod v1_scim;

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::{Configuration, ServerRole, TlsConfiguration};
use axum::extract::connect_info::{IntoMakeServiceWithConnectInfo, ResponseFuture};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{Redirect, Response};
use axum::routing::*;
use axum::Router;
use axum_csp::{CspDirectiveType, CspValue};
use axum_macros::FromRef;
use compact_jwt::{Jws, JwsSigner, JwsUnverified};
use generic::*;
use http::{HeaderMap, HeaderValue};
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrStream, Http};
use hyper::Body;
use javascript::*;
use kanidm_proto::v1::OperationError;
use kanidmd_lib::status::StatusActor;
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};
use tokio_openssl::SslStream;

use futures_util::future::poll_fn;
use serde::Serialize;
use tokio::net::TcpListener;

use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::CoreAction;

use self::v1::SessionId;

#[derive(Clone, FromRef)]
pub struct ServerState {
    pub status_ref: &'static kanidmd_lib::status::StatusActor,
    pub qe_w_ref: &'static crate::actors::v1_write::QueryServerWriteV1,
    pub qe_r_ref: &'static crate::actors::v1_read::QueryServerReadV1,
    // Store the token management parts.
    pub jws_signer: compact_jwt::JwsSigner,
    pub jws_validator: compact_jwt::JwsValidator,
    // The SHA384 hashes of javascript files we're going to serve to users
    pub js_files: Vec<JavaScriptFile>,
    pub(crate) trust_x_forward_for: bool,
    pub csp_header: HeaderValue,
}

impl ServerState {
    fn reinflate_uuid_from_bytes(&self, input: &str) -> Option<Uuid> {
        match JwsUnverified::from_str(input) {
            Ok(val) => val
                .validate(&self.jws_validator)
                .map(|jws: Jws<SessionId>| jws.into_inner().sessionid)
                .ok(),
            Err(_) => None,
        }
    }

    fn get_current_auth_session_id(&self, headers: &HeaderMap) -> Option<Uuid> {
        // We see if there is a signed header copy first.
        headers
            .get("X-KANIDM-AUTH-SESSION-ID")
            .and_then(|hv| {
                // Get the first header value.
                hv.to_str().ok()
            })
            .and_then(|s| Some(self.reinflate_uuid_from_bytes(s)).unwrap_or(None))
    }
}

pub fn get_js_files(role: ServerRole) -> Vec<JavaScriptFile> {
    let mut js_files: Vec<JavaScriptFile> = Vec::new();

    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        // let's set up the list of js module hashes
        {
            let filepath = "wasmloader.js";
            #[allow(clippy::unwrap_used)]
            js_files.push(JavaScriptFile {
                filepath,
                hash: generate_integrity_hash(format!(
                    "{}/{}",
                    env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                    filepath,
                ))
                .unwrap(),
                filetype: Some("module".to_string()),
            });
        }
        // let's set up the list of non-module hashes
        {
            let filepath = "external/bootstrap.bundle.min.js";
            #[allow(clippy::unwrap_used)]
            js_files.push(JavaScriptFile {
                filepath,
                hash: generate_integrity_hash(format!(
                    "{}/{}",
                    env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                    filepath,
                ))
                .unwrap(),
                filetype: None,
            });
        }
    };
    js_files
}

pub async fn create_https_server(
    config: Configuration,
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let jws_validator = jws_signer.get_validator().map_err(|e| {
        error!(?e, "Failed to get jws validator");
    })?;

    let js_files = get_js_files(config.role);
    // set up the CSP headers
    // script-src 'self'
    //      'sha384-Zao7ExRXVZOJobzS/uMp0P1jtJz3TTqJU4nYXkdmsjpiVD+/wcwCyX7FGqRIqvIz'
    //      'sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM'
    //      'unsafe-eval';
    let js_directives = js_files
        .clone()
        .into_iter()
        .map(|f| f.hash)
        .collect::<Vec<String>>();
    let mut js_directives: Vec<CspValue> = js_directives
        .into_iter()
        .map(|value| CspValue::Sha384 { value })
        .collect();
    js_directives.extend(vec![CspValue::UnsafeEval, CspValue::SelfSite]);

    let csp_header = axum_csp::CspSetBuilder::new()
        // default-src 'self';
        .add(CspDirectiveType::DefaultSrc, vec![CspValue::SelfSite])
        // form-action https: 'self';
        .add(
            CspDirectiveType::FormAction,
            vec![CspValue::SelfSite, CspValue::SchemeHttps],
        )
        // base-uri 'self';
        .add(
            CspDirectiveType::BaseUri,
            vec![CspValue::SelfSite, CspValue::SchemeHttps],
        )
        // worker-src 'none';
        .add(CspDirectiveType::WorkerSource, vec![CspValue::None])
        // frame-ancestors 'none'
        .add(CspDirectiveType::FrameAncestors, vec![CspValue::None])
        .add(CspDirectiveType::ScriptSource, js_directives)
        .add(
            CspDirectiveType::ImgSrc,
            vec![CspValue::SelfSite, CspValue::SchemeData],
        );

    let trust_x_forward_for = config.trust_x_forward_for;

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files,
        trust_x_forward_for,
        csp_header: csp_header.finish(),
    };

    let static_routes = match config.role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            // Create a spa router that captures everything at ui without key extraction.
            let spa_router = Router::new()
                .route("/", get(crate::https::ui::ui_handler))
                .fallback(crate::https::ui::ui_handler);

            Router::new()
                // direct users to the base app page. If a login is required,
                // then views will take care of redirection. We shouldn't redir
                // to login because that force clears previous sessions!
                .route("/", get(|| async { Redirect::temporary("/ui") }))
                .route("/manifest.webmanifest", get(manifest::manifest))
                .nest("/ui", spa_router)
                .layer(middleware::compression::new()) // TODO: this needs to be configured properly
        }
        ServerRole::WriteReplicaNoUI => Router::new(),
    };
    let app = Router::new()
        .route("/robots.txt", get(robots_txt))
        .route("/status", get(status))
        .merge(oauth2::oauth2_route_setup(state.clone()))
        .merge(v1_scim::scim_route_setup())
        .merge(v1::router(state.clone()));

    let app = match config.role {
        ServerRole::WriteReplicaNoUI => app,
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            let pkg_path = PathBuf::from(env!("KANIDM_WEB_UI_PKG_PATH"));
            if !pkg_path.exists() {
                eprintln!(
                    "Couldn't find Web UI package path: ({}), quitting.",
                    env!("KANIDM_WEB_UI_PKG_PATH")
                );
                std::process::exit(1);
            }
            let pkg_router = Router::new()
                .nest_service("/pkg", ServeDir::new(pkg_path).precompressed_br())
                .layer(middleware::compression::new());
            app.merge(pkg_router)
        }
    };

    let app = app
        .merge(static_routes)
        .layer(from_fn_with_state(
            state.clone(),
            middleware::security_headers::security_headers_layer,
        ))
        .layer(from_fn(middleware::version_middleware))
        .layer(from_fn(
            middleware::hsts_header::strict_transport_security_layer,
        ))
        .layer(TraceLayer::new_for_http())
        // This must be the LAST middleware.
        // This is because the last middleware here is the first to be entered and the last
        // to be exited, and this middleware sets up ids' and other bits for for logging
        // coherence to be maintained.
        .layer(from_fn(middleware::kopid_middleware))
        .with_state(state)
        // the connect_info bit here lets us pick up the remote address of the client
        .into_make_service_with_connect_info::<SocketAddr>();

    let addr = SocketAddr::from_str(&config.address).map_err(|err| {
        error!(
            "Failed to parse address ({:?}) from config: {:?}",
            config.address, err
        );
    })?;

    info!("Starting the web server...");

    Ok(tokio::spawn(async move {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => {},
                }
            }
            res = match config.tls_config {
                Some(tls_param) => {
                    tokio::spawn(server_loop(tls_param, addr, app))
                },
                None => {
                    tokio::spawn(axum_server::bind(addr).serve(app))
                }
            } => {
                if let Err(err) = res {
                    error!("Web server exited with {:?}", err);
                }
            }
        };
        #[cfg(feature = "otel")]
        opentelemetry::global::shutdown_tracer_provider();
        info!("Stopped WebAcceptorActor");
    }))
}

async fn server_loop(
    tls_param: TlsConfiguration,
    addr: SocketAddr,
    app: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
) -> Result<(), std::io::Error> {
    let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let mut app = app;
    tls_builder
        .set_certificate_chain_file(tls_param.chain.clone())
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("Failed to create TLS listener: {:?}", err),
            )
        })?;
    tls_builder
        .set_private_key_file(tls_param.key.clone(), SslFiletype::PEM)
        .map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("Failed to create TLS listener: {:?}", err),
            )
        })?;
    tls_builder.check_private_key().map_err(|err| {
        std::io::Error::new(
            ErrorKind::Other,
            format!("Failed to create TLS listener: {:?}", err),
        )
    })?;
    let acceptor = tls_builder.build();
    let listener = TcpListener::bind(addr).await?;

    let protocol = Arc::new(Http::new());
    let mut listener =
        hyper::server::conn::AddrIncoming::from_listener(listener).map_err(|err| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("Failed to create listener: {:?}", err),
            )
        })?;
    loop {
        if let Some(Ok(stream)) = poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
            let acceptor = acceptor.clone();
            let svc = tower::MakeService::make_service(&mut app, &stream);
            tokio::spawn(handle_conn(acceptor, stream, svc, protocol.clone()));
        }
    }
}

// #[instrument(name = "handle-connection", level = "debug", skip_all)]
/// This handles an individual connection.
async fn handle_conn(
    acceptor: SslAcceptor,
    stream: AddrStream,
    svc: ResponseFuture<Router, SocketAddr>,
    protocol: Arc<Http>,
) -> Result<(), std::io::Error> {
    let ssl = Ssl::new(acceptor.context()).map_err(|e| {
        error!("Failed to create TLS context: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    let mut tls_stream = SslStream::new(ssl, stream).map_err(|e| {
        error!("Failed to create TLS stream: {:?}", e);
        std::io::Error::from(ErrorKind::ConnectionAborted)
    })?;

    match SslStream::accept(Pin::new(&mut tls_stream)).await {
        Ok(_) => {
            let svc = svc.await.map_err(|e| {
                error!("Failed to build HTTP response: {:?}", e);
                std::io::Error::from(ErrorKind::Other)
            })?;

            protocol
                .serve_connection(tls_stream, svc)
                .await
                .map_err(|e| {
                    error!("Failed to complete connection: {:?}", e);
                    std::io::Error::from(ErrorKind::ConnectionAborted)
                })
        }
        Err(_error) => {
            // trace!("Failed to handle connection: {:?}", error);
            Ok(())
        }
    }
}

/// Convert any kind of Result<T, OperationError> into an axum response with a stable type
/// by JSON-encoding the body.
#[instrument(name = "to_axum_response", level = "debug")]
pub fn to_axum_response<T: Serialize + core::fmt::Debug>(
    v: Result<T, OperationError>,
) -> Response<Body> {
    match v {
        Ok(iv) => {
            let body = match serde_json::to_string(&iv) {
                Ok(val) => val,
                Err(err) => {
                    error!("Failed to serialise response: {:?}", err);
                    format!("{:?}", iv)
                }
            };
            trace!("Response Body: {:?}", body);
            #[allow(clippy::unwrap_used)]
            Response::builder().body(Body::from(body)).unwrap()
        }
        Err(e) => {
            debug!("OperationError: {:?}", e);
            let res = match &e {
                OperationError::NotAuthenticated | OperationError::SessionExpired => {
                    // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                    Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer")
                }
                OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                    Response::builder().status(http::StatusCode::FORBIDDEN)
                }
                OperationError::NoMatchingEntries => {
                    Response::builder().status(http::StatusCode::NOT_FOUND)
                }
                OperationError::PasswordQuality(_)
                | OperationError::EmptyRequest
                | OperationError::SchemaViolation(_) => {
                    Response::builder().status(http::StatusCode::BAD_REQUEST)
                }
                _ => Response::builder().status(http::StatusCode::INTERNAL_SERVER_ERROR),
            };
            match serde_json::to_string(&e) {
                #[allow(clippy::expect_used)]
                Ok(val) => res
                    .body(Body::from(val))
                    .expect("Failed to build response!"),
                #[allow(clippy::expect_used)]
                Err(_) => res
                    .body(Body::from(format!("{:?}", e)))
                    .expect("Failed to build response!"),
            }
        }
    }
}
