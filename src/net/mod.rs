//! Networking facilities for shadowsocks communication.

pub mod stream;

mod buf;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::io::{AsyncRead, ReadBuf};

use crate::net::buf::OwnedReadBuf;

/// Shadowsocks constant values.
pub mod constants {
    /// The maximum payload size of shadowsocks.
    pub const MAXIMUM_PAYLOAD_SIZE: usize = 0x3FFF;
    // const MAXIMUM_TAG_SIZE: usize = 16;
    // const MAXIMUM_MESSAGE_SIZE: usize = 2 + MAXIMUM_PAYLOAD_SIZE + 2 * MAXIMUM_TAG_SIZE;
}

/// Resolves target socket address.
///
/// Returns the first resolved socket address.
pub async fn lookup_host(host: &str) -> io::Result<SocketAddr> {
    match tokio::net::lookup_host(host).await {
        Ok(mut iter) => Ok(iter.next().unwrap()),
        Err(e) => Err(e),
    }
}

pub(crate) fn poll_read_exact<R>(
    reader: &mut R,
    owned_read_buf: &mut OwnedReadBuf,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<()>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    if owned_read_buf.is_full() {
        // The last call to `poll_read_exact()` has returned `Ready`,
        // Now there is a brand new call to `poll_read_exact()`.
        owned_read_buf.require(buf.len());
    }

    debug_assert_eq!(owned_read_buf.capacity(), buf.len());

    while !owned_read_buf.is_full() {
        let mut read_buf = ReadBuf::new(owned_read_buf.uninitialized_mut());
        let remaining = read_buf.remaining();

        ready!(Pin::new(&mut *reader).poll_read(cx, &mut read_buf))?;

        let nread = remaining - read_buf.remaining();
        if nread == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into()).into();
        }

        owned_read_buf.add_filled(nread);
    }

    buf.copy_from_slice(owned_read_buf.filled());

    Ok(()).into()
}
