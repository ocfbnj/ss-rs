use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    context::Ctx,
    crypto::cipher::Method,
    net::{
        io::{lookup_host, transfer_between},
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
    let listener = EncryptedTcpListener::bind(addr, method, &key, ctx.clone()).await?;

    log::info!("ss-remote listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((encrypted_stream, peer)) => {
                log::debug!("Accept {}", peer);
                tokio::spawn(handle_ss_remote(encrypted_stream, peer, ctx.clone()));
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

async fn handle_ss_remote(mut stream: EncryptedTcpStream, peer: SocketAddr, ctx: Arc<Ctx>) {
    // Checks whether or not to reject the client
    if ctx.is_bypass(peer.ip(), None) {
        log::warn!("Reject the client: peer {}", peer);
        return;
    }

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

    // Resolves target socket address
    let target_socket_addr = match lookup_host(&target_addr.to_string()).await {
        Ok(addr) => addr,
        Err(e) => {
            log::warn!("Resolve {} failed: {}, peer {}", target_addr, e, peer);
            return;
        }
    };
    let target_ip = target_socket_addr.ip();

    // Checks whether or not to block outbound
    if ctx.is_block_outbound(target_ip, Some(&target_addr.to_string())) {
        log::warn!(
            "Block outbound address: {} -> {} ({})",
            peer,
            target_addr,
            target_ip
        );
        return;
    }

    log::debug!(
        "Allow outbound address: {} -> {} ({})",
        peer,
        target_addr,
        target_ip
    );

    // Connects to target address
    let target_stream = match TcpStream::connect(target_socket_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            log::debug!(
                "Unable to connect to {} ({}): {}",
                target_addr,
                target_ip,
                e
            );
            return;
        }
    };

    // Establishes connection between peer and target
    let trans = format!("{} <=> {} ({})", peer, target_addr, target_ip);
    transfer(stream, target_stream, &trans).await;
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

    // Resolves target socket address
    let target_socket_addr = match lookup_host(&target_addr.to_string()).await {
        Ok(addr) => Some(addr),
        Err(e) => {
            log::debug!("Resolve {} failed: {}, peer {}", target_addr, e, peer);
            None
        }
    };

    let trans: String;
    match target_socket_addr {
        Some(addr) if ctx.is_bypass(addr.ip(), Some(&target_addr.to_string())) => {
            trans = format!("{} <=> {} ({})", peer, target_addr, addr.ip());

            log::debug!(
                "Bypass target address: {} -> {} ({})",
                peer,
                target_addr,
                addr.ip()
            );

            // Connects to target host
            let target_stream = match TcpStream::connect(addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!(
                        "Unable to connect to {} ({}): {}",
                        target_addr,
                        addr.ip(),
                        e
                    );
                    return;
                }
            };

            // Establishes connection between peer and target
            transfer(stream, target_stream, &trans).await;
        }
        _ => {
            trans = format!("{} <=> {}", peer, target_addr);

            log::debug!("Proxy target address: {} -> {}", peer, target_addr);

            // Connects to ss-remote
            let mut target_stream =
                match EncryptedTcpStream::connect(remote_addr, method, &key, ctx).await {
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

            // Establishes connection between peer and target
            transfer(stream, target_stream, &trans).await;
        }
    }
}

async fn transfer<A, B>(a: A, b: B, trans: &str)
where
    A: AsyncRead + AsyncWrite + Send,
    B: AsyncRead + AsyncWrite + Send,
{
    match transfer_between(a, b, Duration::from_secs(90)).await {
        Ok((atob, btoa)) => log::trace!("{} done: ltor {} bytes, rtol {} bytes", trans, atob, btoa),
        Err(e) => match e.kind() {
            ErrorKind::Other => log::warn!("{} error: {}", trans, e),
            _ => log::debug!("{} error: {}", trans, e),
        },
    }
}
