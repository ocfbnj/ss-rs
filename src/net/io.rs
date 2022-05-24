//! Utility I/O functions.

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::ready;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::net::buf::OwnedReadBuf;

pub(crate) mod constants {
    /// The maximum payload size of shadowsocks.
    pub const MAXIMUM_PAYLOAD_SIZE: usize = 0x3FFF;
    // const MAXIMUM_TAG_SIZE: usize = 16;
    // const MAXIMUM_MESSAGE_SIZE: usize = 2 + MAXIMUM_PAYLOAD_SIZE + 2 * MAXIMUM_TAG_SIZE;
}

/// Copies from reader to writer only once.
///
/// Returns the number of bytes copied.
#[inline]
pub async fn copy_once<R, W>(reader: &mut R, writer: &mut W) -> io::Result<usize>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut payload = [0u8; constants::MAXIMUM_PAYLOAD_SIZE];

    let bytes_copied = reader.read(&mut payload).await?;
    if bytes_copied != 0 {
        writer.write_all(&payload[..bytes_copied]).await?;
    }

    Ok(bytes_copied)
}

/// Transfers bidirectionally the payload between A and B.
///
/// Returns (A to B bytes transferred, B to A byte stransferred).
pub async fn transfer_between<A, B>(a: A, b: B, timeout: Duration) -> io::Result<(usize, usize)>
where
    A: AsyncRead + AsyncWrite + Send,
    B: AsyncRead + AsyncWrite + Send,
{
    let (mut ra, mut wa) = tokio::io::split(a);
    let (mut rb, mut wb) = tokio::io::split(b);

    let mut atob = 0;
    let mut btoa = 0;

    let mut atob_done = false;
    let mut btoa_done = false;

    while !atob_done || !btoa_done {
        tokio::select! {
            _ = tokio::time::sleep(timeout) => {
                return Err(
                    io::Error::new(
                        ErrorKind::TimedOut,
                        format!("there are no data in the past {} seconds", timeout.as_secs())
                    )
                );
            }
            res = copy_once(&mut ra, &mut wb), if atob_done == false => {
                match res {
                    Ok(0) => {
                        atob_done = true;
                        wb.shutdown().await.unwrap_or_default();
                    }
                    Ok(n) => atob += n,
                    Err(e) => return Err(e),
                }
            }
            res = copy_once(&mut rb, &mut wa), if btoa_done == false => {
                match res {
                    Ok(0) => {
                        btoa_done = true;
                        wa.shutdown().await.unwrap_or_default();
                    }
                    Ok(n) => btoa += n,
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok((atob, btoa))
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

    assert_eq!(owned_read_buf.capacity(), buf.len());

    while !owned_read_buf.is_full() {
        let mut read_buf = ReadBuf::new(owned_read_buf.uninitialized_mut());
        let remaining = read_buf.remaining();

        ready!(Pin::new(&mut *reader).poll_read(cx, &mut read_buf))?;

        let nread = remaining - read_buf.remaining();
        if nread == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the source get eof",
            ))
            .into();
        }

        owned_read_buf.add_filled(nread);
    }

    buf.copy_from_slice(owned_read_buf.filled());

    Ok(()).into()
}
