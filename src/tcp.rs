use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::io::AsyncWriteExt;

use crate::{
    context::Ctx,
    crypto::cipher::Method,
    net::{
        io::transfer_between,
        listener::{EncryptedTcpListener, TcpListener},
        stream::{EncryptedTcpStream, TcpStream},
    },
    socks::{self, socks5::Socks5Addr},
};

/// Starts a shadowsocks remote server.
pub async fn ss_remote(
    addr: SocketAddr,
    method: Method,
    key: Vec<u8>,
    ctx: Arc<Ctx>,
) -> io::Result<()> {
    let listener = EncryptedTcpListener::bind(addr, method, &key, ctx).await?;

    log::info!("ss-remote listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((encrypted_stream, peer)) => {
                log::debug!("Accept {}", peer);
                tokio::spawn(handle_ss_remote(encrypted_stream, peer));
            }
            Err(e) => log::warn!("Accept error: {}", e),
        }
    }
}

/// Starts a shadowsocks local server.
pub async fn ss_local(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    method: Method,
    key: Vec<u8>,
    ctx: Arc<Ctx>,
) -> io::Result<()> {
    let listener = TcpListener::bind(local_addr).await?;

    log::info!("ss-local listening on {}", local_addr);
    log::info!("The remote server address is {}", remote_addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                log::debug!("Accept {}", peer);
                tokio::spawn(handle_ss_local(
                    stream,
                    peer,
                    remote_addr,
                    method,
                    key.clone(),
                    ctx.clone(),
                ));
            }
            Err(e) => log::warn!("Accept error: {}", e),
        }
    }
}

async fn handle_ss_remote(mut stream: EncryptedTcpStream, peer: SocketAddr) {
    // Constructs a socks5 address with timeout
    let result = tokio::time::timeout(Duration::from_secs(15), Socks5Addr::construct(&mut stream));
    let target_addr = match result.await {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            match e.kind() {
                ErrorKind::Other => log::warn!("Read target address failed: {}, peer {}", e, peer),
                _ => log::debug!("Read target address failed: {}, peer {}", e, peer),
            }
            return;
        }
        Err(e) => {
            log::debug!("Read target address timed out: {}, peer {}", e, peer);
            return;
        }
    };

    log::debug!("Request target address: {} -> {}", peer, target_addr);

    // Connects to target address
    let target_stream = match TcpStream::connect(target_addr.to_string()).await {
        Ok(stream) => stream,
        Err(e) => {
            log::debug!("Unable to connect to {}: {}", target_addr, e);
            return;
        }
    };

    let trans = format!("{} <=> {}", peer, target_addr);

    // Establishes connection between peer and target
    match transfer_between(stream, target_stream, Duration::from_secs(60)).await {
        Ok((atob, btoa)) => log::trace!("{} done: ltor {} bytes, rtol {} bytes", trans, atob, btoa),
        Err(e) => match e.kind() {
            ErrorKind::Other => log::warn!("{} error: {}", trans, e),
            _ => log::debug!("{} error: {}", trans, e),
        },
    }
}

async fn handle_ss_local(
    mut stream: TcpStream,
    peer: SocketAddr,
    remote_addr: SocketAddr,
    method: Method,
    key: Vec<u8>,
    ctx: Arc<Ctx>,
) {
    // Constructs a SOCKS address with timeout
    let result = tokio::time::timeout(Duration::from_secs(15), socks::handshake(&mut stream));
    let target_addr: Socks5Addr = match result.await {
        Ok(Ok(addr)) => addr.into(),
        Ok(Err(e)) => {
            match e.kind() {
                ErrorKind::Other => log::warn!("Read target address failed: {}, peer {}", e, peer),
                _ => log::debug!("Read target address failed: {}, peer {}", e, peer),
            }
            return;
        }
        Err(e) => {
            log::debug!("Read target address timed out: {}, peer {}", e, peer);
            return;
        }
    };

    log::debug!("Request target address: {} -> {}", peer, target_addr);

    // Connects to ss-remote
    let mut target_stream = match EncryptedTcpStream::connect(remote_addr, method, &key, ctx).await
    {
        Ok(stream) => stream,
        Err(e) => {
            log::error!("Unable to connect to {}: {}", remote_addr, e);
            return;
        }
    };

    // Writes target address
    let target_addr_bytes = target_addr.get_raw_parts();
    match target_stream.write_all(&target_addr_bytes).await {
        Ok(_) => {}
        Err(e) => {
            log::error!("Write target address to {} failed: {}", remote_addr, e);
            return;
        }
    }

    let trans = format!("{} <=> {}", peer, target_addr);

    // Establishes connection between peer and target
    match transfer_between(stream, target_stream, Duration::from_secs(60)).await {
        Ok((atob, btoa)) => log::trace!("{} done: ltor {} bytes, rtol {} bytes", trans, atob, btoa),
        Err(e) => match e.kind() {
            ErrorKind::Other => log::warn!("{} error: {}", trans, e),
            _ => log::debug!("{} error: {}", trans, e),
        },
    }
}
