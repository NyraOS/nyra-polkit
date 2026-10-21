// SPDX-License-Identifier: MIT
//! The connection to the system bus, refusing method calls larger than [`MAX_CALL_SIZE`].
//!
//! zbus reads a whole message and deserializes it before the daemon sees it, and the bus allows
//! messages of up to 32 MiB: a few large calls in parallel would grow the daemon by hundreds of
//! MiB. zbus has no size option, but its `ReadHalf` trait lets us look at the header of each
//! message before the body is read (docs/DESIGN.md, "Message size").

use async_io::Async;
use async_trait::async_trait;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use zbus::Message;
use zbus::address::Transport;
use zbus::address::transport::UnixSocket;
use zbus::connection::Builder;
use zbus::connection::socket::{BoxedSplit, ReadHalf, Split};

/// The largest method call (header and body) the daemon accepts. A real check is well under 4 KiB;
/// this leaves room for many details.
pub const MAX_CALL_SIZE: usize = 256 * 1024;

const PRIMARY_HEADER_SIZE: usize = 16;
const METHOD_CALL: u8 = 1;
/// How much of a refused message is read at a time.
const DISCARD_CHUNK: usize = 64 * 1024;

/// A builder for the system bus connection (the address follows `DBUS_SYSTEM_BUS_ADDRESS`, as
/// `Builder::system` does) whose incoming method calls are capped at [`MAX_CALL_SIZE`].
pub async fn system_builder() -> Result<Builder<'static>, String> {
    let address = zbus::Address::system().map_err(|error| error.to_string())?;
    let Transport::Unix(unix) = address.transport() else {
        return Err(format!(
            "{address}: only a unix socket address is supported"
        ));
    };
    let UnixSocket::File(path) = unix.path() else {
        return Err(format!("{address}: only a socket path is supported"));
    };
    let stream = Async::<UnixStream>::connect(path)
        .await
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let (read, write) = BoxedSplit::from(stream).take();
    let capped: BoxedSplit = Split::new(Box::new(CallLimit(read)), write);
    Ok(Builder::socket(capped))
}

/// The read half of the bus socket. It can neither pass file descriptors (the default of
/// `ReadHalf`, kept on purpose: the daemon needs none) nor reply to a refused call: zbus gives the
/// read half no way to send. A refused call is dropped; its caller gives up at its own timeout.
#[derive(Debug)]
struct CallLimit(Box<dyn ReadHalf>);

#[async_trait]
impl ReadHalf for CallLimit {
    async fn receive_message(
        &mut self,
        seq: u64,
        received: &mut Vec<u8>,
        fds: &mut Vec<OwnedFd>,
    ) -> zbus::Result<Message> {
        loop {
            while received.len() < PRIMARY_HEADER_SIZE {
                let mut more = vec![0; PRIMARY_HEADER_SIZE - received.len()];
                let (read, _) = self.0.recvmsg(&mut more).await?;
                if read == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                }
                received.extend_from_slice(&more[..read]);
            }
            match method_call_size(&received[..PRIMARY_HEADER_SIZE]) {
                Some(size) if size > MAX_CALL_SIZE => self.discard(size, received).await?,
                // The inner read half starts from the header bytes already read.
                _ => return self.0.receive_message(seq, received, fds).await,
            }
        }
    }

    async fn recvmsg(&mut self, buffer: &mut [u8]) -> std::io::Result<(usize, Vec<OwnedFd>)> {
        self.0.recvmsg(buffer).await
    }
}

impl CallLimit {
    /// Throws away the next `size` bytes: those in `received` first, then those still to come.
    async fn discard(&mut self, size: usize, received: &mut Vec<u8>) -> zbus::Result<()> {
        let buffered = size.min(received.len());
        received.drain(..buffered);
        let mut remaining = size - buffered;
        let mut chunk = vec![0; DISCARD_CHUNK.min(remaining)];
        while remaining > 0 {
            let wanted = remaining.min(chunk.len());
            let (read, _) = self.0.recvmsg(&mut chunk[..wanted]).await?;
            if read == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            remaining -= read;
        }
        Ok(())
    }
}

/// The size of the whole message if the header is that of a method call, else `None` (other
/// messages, from the bus or from the services we call, are left to zbus).
fn method_call_size(header: &[u8]) -> Option<usize> {
    let number = |at: usize| {
        let bytes = header[at..at + 4].try_into().unwrap();
        match header[0] {
            b'l' => Some(u32::from_le_bytes(bytes)),
            b'B' => Some(u32::from_be_bytes(bytes)),
            _ => None,
        }
    };
    if header[1] != METHOD_CALL {
        return None;
    }
    let (body, fields) = (number(4)? as usize, number(12)? as usize);
    // The body starts on an 8-byte boundary.
    let header_size = (PRIMARY_HEADER_SIZE + fields).next_multiple_of(8);
    Some(header_size.saturating_add(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(endian: u8, kind: u8, body: u32, fields: u32) -> Vec<u8> {
        let (body, fields) = match endian {
            b'l' => (body.to_le_bytes(), fields.to_le_bytes()),
            _ => (body.to_be_bytes(), fields.to_be_bytes()),
        };
        [&[endian, kind, 0, 1][..], &body, &[0; 4], &fields].concat()
    }

    #[test]
    fn the_size_counts_the_header_with_its_padding_and_the_body() {
        assert_eq!(method_call_size(&header(b'l', 1, 100, 45)), Some(64 + 100));
        assert_eq!(method_call_size(&header(b'B', 1, 100, 48)), Some(64 + 100));
        assert_eq!(
            method_call_size(&header(b'l', 1, u32::MAX, 0)),
            Some(16 + u32::MAX as usize)
        );
    }

    #[test]
    fn only_method_calls_with_a_known_byte_order_are_measured() {
        assert_eq!(method_call_size(&header(b'l', 2, 100, 0)), None);
        assert_eq!(method_call_size(&header(b'l', 4, 100, 0)), None);
        assert_eq!(method_call_size(&header(b'x', 1, 100, 0)), None);
    }
}
