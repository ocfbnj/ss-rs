use std::io;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::oneshot::{Receiver, Sender},
    task::JoinHandle,
};

pub const MAXIMUM_PAYLOAD_SIZE: usize = 0x3FFF;
// const MAXIMUM_TAG_SIZE: usize = 16;
// const MAXIMUM_MESSAGE_SIZE: usize = 2 + MAXIMUM_PAYLOAD_SIZE + 2 * MAXIMUM_TAG_SIZE;

pub async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut rd: R,
    mut wr: W,
) -> io::Result<usize> {
    let mut payload = [0u8; MAXIMUM_PAYLOAD_SIZE];
    let mut bytes_transferred = 0;

    loop {
        let n = rd.read(&mut payload).await?;
        if n == 0 {
            return Ok(bytes_transferred);
        }

        wr.write_all(&payload[..n]).await?;

        bytes_transferred += n;
    }
}

pub fn transfer<R: AsyncRead + Unpin + Send + 'static, W: AsyncWrite + Unpin + Send + 'static>(
    name: String,
    tx: Sender<()>,
    rx: Receiver<()>,
    mut rd: R,
    mut wr: W,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        select! {
            _ = rx => {
                log::trace!("Transfer received exit signal: {}", name);
            }
            res = copy(&mut rd, &mut wr) => {
                match res {
                    Ok(n) => log::trace!("Transfer end up with {} bytes: {}", n, name),
                    Err(e) => {
                        if e.kind() == io::ErrorKind::Other {
                            log::error!("Transfer {} error: {}", name, e);
                        } else {
                            log::debug!("Transfer {} error: {}", name, e);
                        }
                    },
                };
            }
        }

        tx.send(()).unwrap_or_default();
        wr.shutdown().await.unwrap_or_default();
    })
}
