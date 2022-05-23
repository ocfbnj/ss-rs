use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
