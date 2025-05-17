use bytes::{Buf, BufMut, BytesMut};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

use kanidmd_lib::repl::proto::{ReplIncrementalContext, ReplRefreshContext, ReplRuvRange};

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsumerRequest {
    Ping,
    Incremental(ReplRuvRange),
    Refresh,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SupplierResponse {
    Pong,
    Incremental(ReplIncrementalContext),
    Refresh(ReplRefreshContext),
}

#[derive(Default)]
pub struct ConsumerCodec {
    max_frame_bytes: usize,
}

impl ConsumerCodec {
    pub fn new(max_frame_bytes: usize) -> Self {
        ConsumerCodec { max_frame_bytes }
    }
}

impl Decoder for ConsumerCodec {
    type Error = io::Error;
    type Item = SupplierResponse;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_length_checked_json(self.max_frame_bytes, src)
    }
}

impl Encoder<ConsumerRequest> for ConsumerCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ConsumerRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode_length_checked_json(msg, dst)
    }
}

#[derive(Default)]
pub struct SupplierCodec {
    max_frame_bytes: usize,
}

impl SupplierCodec {
    pub fn new(max_frame_bytes: usize) -> Self {
        SupplierCodec { max_frame_bytes }
    }
}

impl Decoder for SupplierCodec {
    type Error = io::Error;
    type Item = ConsumerRequest;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_length_checked_json(self.max_frame_bytes, src)
    }
}

impl Encoder<SupplierResponse> for SupplierCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: SupplierResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        encode_length_checked_json(msg, dst)
    }
}

fn encode_length_checked_json<R: Serialize>(msg: R, dst: &mut BytesMut) -> Result<(), io::Error> {
    // First, if there is anything already in dst, we should split past it.
    let mut work = dst.split_off(dst.len());

    // Null the head of the buffer.
    let zero_len = u64::MIN.to_be_bytes();
    work.extend_from_slice(&zero_len);

    // skip the buffer ahead 8 bytes.
    // Remember, this split returns the *already set* bytes.
    // ⚠️  Can't use split or split_at - these return the
    // len bytes into a new bytes mut which confuses unsplit
    // by appending the value when we need to append our json.
    let json_buf = work.split_off(zero_len.len());

    let mut json_writer = json_buf.writer();

    serde_json::to_writer(&mut json_writer, &msg).map_err(|err| {
        error!(?err, "consumer encoding error");
        io::Error::other("JSON encode error")
    })?;

    let json_buf = json_writer.into_inner();

    let final_len = json_buf.len() as u64;
    let final_len_bytes = final_len.to_be_bytes();

    if final_len_bytes.len() != work.len() {
        error!("consumer buffer size error");
        return Err(io::Error::other("buffer length error"));
    }

    work.copy_from_slice(&final_len_bytes);

    // Now stitch them back together.
    work.unsplit(json_buf);

    dst.unsplit(work);

    Ok(())
}

fn decode_length_checked_json<T: DeserializeOwned>(
    max_frame_bytes: usize,
    src: &mut BytesMut,
) -> Result<Option<T>, io::Error> {
    trace!(capacity = ?src.capacity());

    if src.len() < 8 {
        // Not enough for the length header.
        trace!("Insufficient bytes for length header.");
        return Ok(None);
    }

    let (src_len_bytes, json_bytes) = src.split_at(8);
    let mut len_be_bytes = [0; 8];

    assert_eq!(len_be_bytes.len(), src_len_bytes.len());
    len_be_bytes.copy_from_slice(src_len_bytes);
    let req_len = u64::from_be_bytes(len_be_bytes);

    if req_len == 0 {
        error!("request has size 0");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty request"));
    }

    if req_len > max_frame_bytes as u64 {
        error!(
            "requested decode frame too large {} > {}",
            req_len, max_frame_bytes
        );
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "request too large",
        ));
    }

    if (json_bytes.len() as u64) < req_len {
        trace!(
            "Insufficient bytes for json, need: {} have: {}",
            req_len,
            src.len()
        );
        return Ok(None);
    }

    // If there are excess bytes, we need to limit our slice to that view.
    debug_assert!(req_len as usize <= json_bytes.len());
    let (json_bytes, _remainder) = json_bytes.split_at(req_len as usize);

    // Okay, we have enough. Lets go.
    let res = serde_json::from_slice(json_bytes)
        .map(|msg| Some(msg))
        .map_err(|err| {
            error!(?err, "received invalid input");
            io::Error::new(io::ErrorKind::InvalidInput, "JSON decode error")
        });

    // Trim to length.
    if src.len() as u64 == req_len {
        src.clear();
    } else {
        src.advance((8 + req_len) as usize);
    };

    res
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    use super::{ConsumerCodec, ConsumerRequest, SupplierCodec, SupplierResponse};

    #[test]
    fn test_repl_codec() {
        sketching::test_init();

        let mut consumer_codec = ConsumerCodec::new(32);

        let mut buf = BytesMut::with_capacity(32);

        // Empty buffer
        assert!(matches!(consumer_codec.decode(&mut buf), Ok(None)));

        let zero = [0, 0, 0, 0];
        buf.extend_from_slice(&zero);

        // Not enough to fill the length header.
        assert!(matches!(consumer_codec.decode(&mut buf), Ok(None)));

        // Length header reports a zero size request.
        let zero = [0, 0, 0, 0];
        buf.extend_from_slice(&zero);
        assert_eq!(buf.len(), 8);
        assert!(consumer_codec.decode(&mut buf).is_err());

        // Clear buffer - setup a request with a length > allowed max.
        buf.clear();
        let len_bytes = (34_u64).to_be_bytes();
        buf.extend_from_slice(&len_bytes);

        // Even though the buf len is only 8, this will error as the overall
        // request will be too large.
        assert_eq!(buf.len(), 8);
        assert!(consumer_codec.decode(&mut buf).is_err());

        // Assert that we request more data on a validly sized req
        buf.clear();
        let len_bytes = (20_u64).to_be_bytes();
        buf.extend_from_slice(&len_bytes);
        // Pad in some extra bytes.
        buf.extend_from_slice(&zero);
        assert_eq!(buf.len(), 12);
        assert!(matches!(consumer_codec.decode(&mut buf), Ok(None)));

        // Make a request that is correctly sized.
        buf.clear();
        let mut supplier_codec = SupplierCodec::new(32);

        assert!(consumer_codec
            .encode(ConsumerRequest::Ping, &mut buf)
            .is_ok());
        assert!(matches!(
            supplier_codec.decode(&mut buf),
            Ok(Some(ConsumerRequest::Ping))
        ));
        // The buf will have been cleared by the supplier codec here.
        assert!(buf.is_empty());
        assert!(supplier_codec
            .encode(SupplierResponse::Pong, &mut buf)
            .is_ok());
        assert!(matches!(
            consumer_codec.decode(&mut buf),
            Ok(Some(SupplierResponse::Pong))
        ));
        assert!(buf.is_empty());

        // Make two requests in a row.
        buf.clear();
        let mut supplier_codec = SupplierCodec::new(32);

        assert!(consumer_codec
            .encode(ConsumerRequest::Ping, &mut buf)
            .is_ok());
        assert!(consumer_codec
            .encode(ConsumerRequest::Ping, &mut buf)
            .is_ok());

        assert!(matches!(
            supplier_codec.decode(&mut buf),
            Ok(Some(ConsumerRequest::Ping))
        ));
        assert!(!buf.is_empty());
        assert!(matches!(
            supplier_codec.decode(&mut buf),
            Ok(Some(ConsumerRequest::Ping))
        ));

        // The buf will have been cleared by the supplier codec here.
        assert!(buf.is_empty());
    }
}
