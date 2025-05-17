use bytes::{BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
use std::error::Error;
use std::io::Error as IoError;
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

impl Encoder<&ClientRequest> for ClientCodec {
    type Error = IoError;

    fn encode(&mut self, msg: &ClientRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(msg).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            IoError::other("JSON encode error")
        })?;
        debug!("Attempting to send request -> {}", msg.as_safe_string());
        dst.put(data.as_slice());
        Ok(())
    }
}

impl ClientCodec {
    fn new() -> Self {
        ClientCodec
    }
}

pub struct DaemonClient {
    req_stream: Framed<UnixStream, ClientCodec>,
    default_timeout: u64,
}

impl DaemonClient {
    pub async fn new(path: &str, default_timeout: u64) -> Result<Self, Box<dyn Error>> {
        trace!(?path);
        let stream = UnixStream::connect(path).await.inspect_err(|e| {
            error!(
                "Unix socket stream setup error while connecting to {} -> {:?}",
                path, e
            );
        })?;

        let req_stream = Framed::new(stream, ClientCodec::new());

        trace!("connected");

        Ok(DaemonClient {
            req_stream,
            default_timeout,
        })
    }

    async fn call_inner(&mut self, req: &ClientRequest) -> Result<ClientResponse, Box<dyn Error>> {
        self.req_stream.send(req).await?;
        self.req_stream.flush().await?;
        trace!("flushed, waiting ...");
        match self.req_stream.next().await {
            Some(Ok(res)) => {
                debug!("Response -> {:?}", res);
                Ok(res)
            }
            _ => {
                error!("Error making request to kanidm_unixd");
                Err(Box::new(IoError::other("oh no!")))
            }
        }
    }

    pub async fn call(
        &mut self,
        req: &ClientRequest,
        timeout: Option<u64>,
    ) -> Result<ClientResponse, Box<dyn Error>> {
        let sleep = time::sleep(Duration::from_secs(timeout.unwrap_or(self.default_timeout)));
        tokio::pin!(sleep);

        tokio::select! {
            _ = &mut sleep => {
                error!(?timeout, "Timed out making request to kanidm_unixd");
                Err(Box::new(IoError::other("timeout")))
            }
            res = self.call_inner(req) => {
                res
            }
        }
    }
}
