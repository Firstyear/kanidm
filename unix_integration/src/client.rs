use std::error::Error;
use std::io::{Error as IoError, ErrorKind};

use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::net::UnixStream;
// use tokio::runtime::Builder;
use tokio::time::{self, Duration};
use tokio_util::codec::Framed;
use tokio_util::codec::{Decoder, Encoder};

use crate::unix_proto::{ClientRequest, ClientResponse};

struct ClientCodec;

impl Decoder for ClientCodec {
    type Error = IoError;
    type Item = ClientResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match serde_json::from_slice::<ClientResponse>(src) {
            Ok(msg) => {
                // Clear the buffer for the next message.
                src.clear();
                Ok(Some(msg))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder<ClientRequest> for ClientCodec {
    type Error = IoError;

    fn encode(&mut self, msg: ClientRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            IoError::new(ErrorKind::Other, "JSON encode error")
        })?;
        debug!("Attempting to send request -> {:?} ...", data);
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

async fn call_daemon_inner(
    path: &str,
    req: ClientRequest,
) -> Result<ClientResponse, Box<dyn Error>> {
    trace!(?path, ?req);
    let stream = UnixStream::connect(path).await?;
    trace!("connected");

    let mut reqs = Framed::new(stream, ClientCodec::new());

    reqs.send(req).await?;
    reqs.flush().await?;
    trace!("flushed, waiting ...");

    match reqs.next().await {
        Some(Ok(res)) => {
            debug!("Response -> {:?}", res);
            Ok(res)
        }
        _ => {
            error!("Error making request to kanidm_unixd");
            Err(Box::new(IoError::new(ErrorKind::Other, "oh no!")))
        }
    }
}

/// Makes a call to kanidm_unixd via a unix socket at `path`
pub async fn call_daemon(
    path: &str,
    req: ClientRequest,
    timeout: u64,
) -> Result<ClientResponse, Box<dyn Error>> {
    let sleep = time::sleep(Duration::from_secs(timeout));
    tokio::pin!(sleep);

    tokio::select! {
        _ = &mut sleep => {
            error!(?timeout, "Timed out making request to kanidm_unixd");
            Err(Box::new(IoError::new(ErrorKind::Other, "timeout")))
        }
        res = call_daemon_inner(path, req) => {
            res
        }
    }
}
