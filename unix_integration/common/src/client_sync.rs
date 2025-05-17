use crate::constants::DEFAULT_CONN_TIMEOUT;
use crate::unix_proto::{ClientRequest, ClientResponse};
use std::error::Error;
use std::io::{Error as IoError, Read, Write};
use std::time::{Duration, SystemTime};

pub use std::os::unix::net::UnixStream;

pub struct DaemonClientBlocking {
    stream: UnixStream,
    default_timeout: u64,
}

impl From<UnixStream> for DaemonClientBlocking {
    fn from(stream: UnixStream) -> Self {
        DaemonClientBlocking {
            stream,
            default_timeout: DEFAULT_CONN_TIMEOUT,
        }
    }
}

impl DaemonClientBlocking {
    pub fn new(path: &str, default_timeout: u64) -> Result<DaemonClientBlocking, Box<dyn Error>> {
        debug!(%path);

        let stream = UnixStream::connect(path)
            .map_err(|e| {
                error!(
                    "Unix socket stream setup error while connecting to {} -> {:?}",
                    path, e
                );
                e
            })
            .map_err(Box::new)?;

        Ok(DaemonClientBlocking {
            stream,
            default_timeout,
        })
    }

    pub fn call_and_wait(
        &mut self,
        req: &ClientRequest,
        timeout: Option<u64>,
    ) -> Result<ClientResponse, Box<dyn Error>> {
        let timeout = Duration::from_secs(timeout.unwrap_or(self.default_timeout));

        let data = serde_json::to_vec(&req).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            Box::new(IoError::other("JSON encode error"))
        })?;

        match self.stream.set_read_timeout(Some(timeout)) {
            Ok(()) => {}
            Err(e) => {
                error!(
                    "Unix socket stream setup error while setting read timeout -> {:?}",
                    e
                );
                return Err(Box::new(e));
            }
        };
        match self.stream.set_write_timeout(Some(timeout)) {
            Ok(()) => {}
            Err(e) => {
                error!(
                    "Unix socket stream setup error while setting write timeout -> {:?}",
                    e
                );
                return Err(Box::new(e));
            }
        };

        self.stream
            .write_all(data.as_slice())
            .and_then(|_| self.stream.flush())
            .map_err(|e| {
                error!("stream write error -> {:?}", e);
                e
            })
            .map_err(Box::new)?;

        // Now wait on the response.
        let start = SystemTime::now();
        let mut read_started = false;
        let mut data = Vec::with_capacity(1024);
        let mut counter = 0;

        loop {
            let mut buffer = [0; 1024];
            let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
            if durr > timeout {
                error!("Socket timeout");
                // timed out, not enough activity.
                break;
            }
            // Would be a lot easier if we had peek ...
            // https://github.com/rust-lang/rust/issues/76923
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    if read_started {
                        debug!("read_started true, we have completed");
                        // We're done, no more bytes.
                        break;
                    } else {
                        debug!("Waiting ...");
                        // Still can wait ...
                        continue;
                    }
                }
                Ok(count) => {
                    data.extend_from_slice(&buffer);
                    counter += count;
                    if count == 1024 {
                        debug!("Filled 1024 bytes, looping ...");
                        // We have filled the buffer, we need to copy and loop again.
                        read_started = true;
                        continue;
                    } else {
                        debug!("Filled {} bytes, complete", count);
                        // We have a partial read, so we are complete.
                        break;
                    }
                }
                Err(e) => {
                    error!("Stream read failure from {:?} -> {:?}", &self.stream, e);
                    // Failure!
                    return Err(Box::new(e));
                }
            }
        }

        // Extend from slice fills with 0's, so we need to truncate now.
        data.truncate(counter);

        // Now attempt to decode.
        let cr = serde_json::from_slice::<ClientResponse>(data.as_slice()).map_err(|e| {
            error!("socket encoding error -> {:?}", e);
            Box::new(IoError::other("JSON decode error"))
        })?;

        Ok(cr)
    }
}
