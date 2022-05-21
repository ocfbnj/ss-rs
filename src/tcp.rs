use std::{error::Error, io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    context::Ctx,
    crypto::cipher::Method,
    net::{
        io::transfer_between,
        listener::EncryptedTcpListener,
        stream::{EncryptedTcpStream, TcpStream},
    },
    socks::socks5::Socks5Addr,
};

async fn handle(mut stream: EncryptedTcpStream, peer: SocketAddr) {
    // Constructs a socks5 address with timeout
    let result = tokio::time::timeout(Duration::from_secs(15), Socks5Addr::construct(&mut stream));
    let target_addr = match result.await {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            if e.kind() == ErrorKind::Other {
                log::error!("Read target address failed: {}, peer {}", e, peer);
            } else {
                log::warn!("Read target address failed: {}, peer {}", e, peer);
            }
            return;
        }
        Err(e) => {
            log::warn!("Read target address timed out: {}, peer {}", e, peer);
            return;
        }
    };

    log::debug!("Request target address: {} -> {}", peer, target_addr);

    // Connects to target address
    let target_stream = match TcpStream::connect(target_addr.to_string()).await {
        Ok(stream) => stream,
        Err(e) => {
            log::warn!("Unable to connect to {}: {}", target_addr, e);
            return;
        }
    };

    let trans = format!("{} <=> {}", peer, target_addr);

    // Establishes connection between peer and target
    match transfer_between(stream, target_stream, Duration::from_secs(60)).await {
        Ok((atob, btoa)) => log::debug!(
            "{} done: left to right {} bytes, right to left {} bytes",
            trans,
            atob,
            btoa
        ),
        Err(e) => {
            if e.kind() == ErrorKind::Other {
                log::error!("{} end up with error: {}", trans, e);
            } else {
                log::warn!("{} end up with error: {}", trans, e);
            }
        }
    }
}

/// Starts a shadowsocks remote server.
pub async fn ss_remote(
    addr: SocketAddr,
    method: Method,
    key: Vec<u8>,
    ctx: Arc<Ctx>,
) -> Result<(), Box<dyn Error>> {
    let listener = EncryptedTcpListener::bind(addr, method, &key, ctx).await?;

    log::info!("Listening on {}", addr);

    loop {
        let (encrypted_stream, peer) = listener.accept().await?;
        log::debug!("Accept {}", peer);

        tokio::spawn(handle(encrypted_stream, peer));
    }
}
