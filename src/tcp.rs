//! Shadowsocks tcp services.

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, ToSocketAddrs},
};

use crate::{
    context::Ctx,
    crypto::cipher::Method,
    net::{
        lookup_host,
        stream::{TcpStream as SsTcpStream, TimeoutStream},
    },
    socks5::{self, Socks5Addr},
};

mod constants {
    use std::time::Duration;

    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
}

/// TCP Listener for incoming shadowsocks connection.
pub struct SsTcpListener {
    inner_listener: TokioTcpListener,
    cipher_method: Method,
    cipher_key: Vec<u8>,
    ctx: Arc<Ctx>,
}

impl SsTcpListener {
    /// Creates a new TcpListener for incoming shadowsocks connection,
    /// which will be bound to the specified address.
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        cipher_method: Method,
        cipher_key: &[u8],
        ctx: Arc<Ctx>,
    ) -> io::Result<Self> {
        let inner_listener = TokioTcpListener::bind(addr).await?;
        Ok(SsTcpListener {
            inner_listener,
            cipher_method,
            cipher_key: cipher_key.to_owned(),
            ctx,
        })
    }

    /// Accepts a new incoming shadowsocks connection from this listener.
    pub async fn accept(&self) -> io::Result<(SsTcpStream<TokioTcpStream>, SocketAddr)> {
        let (stream, addr) = self.inner_listener.accept().await?;
        Ok((
            SsTcpStream::new(
                stream,
                self.cipher_method,
                &self.cipher_key,
                self.ctx.clone(),
            ),
            addr,
        ))
    }
}

/// Starts a shadowsocks remote server.
pub async fn ss_remote(
    addr: SocketAddr,
    method: Method,
    key: Vec<u8>,
    ctx: Arc<Ctx>,
) -> io::Result<()> {
    let listener = SsTcpListener::bind(addr, method, &key, ctx.clone()).await?;

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
    let listener = TokioTcpListener::bind(local_addr).await?;

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

/// Handles incoming connection from ss-remote.
pub async fn handle_ss_remote<T>(stream: SsTcpStream<T>, peer: SocketAddr, ctx: Arc<Ctx>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = make_timed_stream(stream);

    // 1. Checks whether or not to reject the client
    if ctx.is_bypass(peer.ip(), None) {
        log::warn!("Reject the client: peer {}", peer);
        return;
    }

    // 2. Constructs a socks5 address with timeout
    let target_addr = match Socks5Addr::construct(&mut stream).await {
        Ok(addr) => addr,
        Err(e) => {
            match e.kind() {
                ErrorKind::Other => {
                    log::warn!("Read target address failed: {}, peer {}", e, peer);
                    // We shouldn't close the connection,
                    // See https://github.com/shadowsocks/shadowsocks-rust/issues/292
                    read_to_end(&mut stream).await.unwrap_or_default();
                }
                _ => log::debug!("Read target address failed: {}, peer {}", e, peer),
            }
            return;
        }
    };

    // 3. Resolves target socket address
    let target_socket_addr = match lookup_host(&target_addr.to_string()).await {
        Ok(addr) => addr,
        Err(e) => {
            log::warn!("Resolve {} failed: {}, peer {}", target_addr, e, peer);
            return;
        }
    };
    let target_ip = target_socket_addr.ip();

    // 4. Checks whether or not to block outbound
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

    // 5. Connects to target address
    let mut target_stream = match TokioTcpStream::connect(target_socket_addr).await {
        Ok(stream) => make_timed_stream(stream),
        Err(e) => {
            log::debug!(
                "Unable to connect to {} ({}): {}, peer {}",
                target_addr,
                target_ip,
                e,
                peer
            );
            return;
        }
    };

    // 6. Establishes connection between ss-local and target
    let trans = format!("{} <=> {} ({})", peer, target_addr, target_ip);
    transfer(&mut stream, &mut target_stream, &trans).await;
}

/// Handles incoming connection from ss-local.
pub async fn handle_ss_local(
    stream: TokioTcpStream,
    peer: SocketAddr,
    remote_addr: SocketAddr,
    method: Method,
    key: Vec<u8>,
    ctx: Arc<Ctx>,
) {
    let mut stream = make_timed_stream(stream);

    // 1. Constructs a socks5 address with timeout
    let target_addr = match socks5::handshake(&mut stream).await {
        Ok(addr) => addr,
        Err(e) => {
            match e.kind() {
                ErrorKind::Other => log::warn!("Read target address failed: {}, peer {}", e, peer),
                _ => log::debug!("Read target address failed: {}, peer {}", e, peer),
            }
            return;
        }
    };

    // 2. Resolves target socket address
    let target_socket_addr = match lookup_host(&target_addr.to_string()).await {
        Ok(addr) => Some(addr),
        Err(e) => {
            log::debug!("Resolve {} failed: {}, peer {}", target_addr, e, peer);
            None
        }
    };

    // 3. Relays target address, bypass or proxy
    let trans: String;
    let host = target_addr
        .to_string()
        .split(':')
        .next()
        .map(str::to_owned)
        .unwrap_or_default();
    match target_socket_addr {
        Some(addr) if ctx.is_bypass(addr.ip(), Some(&host)) => {
            trans = format!("{} <=> {} ({})", peer, target_addr, addr.ip());

            log::debug!(
                "Bypass target address: {} -> {} ({})",
                peer,
                target_addr,
                addr.ip()
            );

            // 3.1 Connects to target host
            let mut target_stream = match TokioTcpStream::connect(addr).await {
                Ok(stream) => make_timed_stream(stream),
                Err(e) => {
                    log::error!(
                        "Unable to connect to {} ({}): {}, peer {}",
                        target_addr,
                        addr.ip(),
                        e,
                        peer
                    );
                    return;
                }
            };

            // 3.2 Establishes connection between ss-local and target
            transfer(&mut stream, &mut target_stream, &trans).await;
        }
        _ => {
            trans = format!("{} <=> {}", peer, target_addr);

            if log::log_enabled!(log::Level::Debug) {
                let mut str = format!("Proxy target address: {} -> {}", peer, target_addr);

                if let Some(addr) = target_socket_addr {
                    str.push_str(&format!(" ({})", addr.ip()));
                }

                log::debug!("{}", str);
            }

            // 3.1 Connects to ss-remote
            let mut target_stream = match TokioTcpStream::connect(remote_addr).await {
                Ok(stream) => make_timed_stream(SsTcpStream::new(stream, method, &key, ctx)),
                Err(e) => {
                    log::error!("Unable to connect to {}: {}, peer {}", remote_addr, e, peer);
                    return;
                }
            };

            // 3.2 Writes target address
            let target_addr_bytes = target_addr.get_raw_parts();
            match target_stream.write_all(&target_addr_bytes).await {
                Ok(_) => {}
                Err(e) => {
                    log::error!(
                        "Write target address to {} failed: {}, peer {}",
                        remote_addr,
                        e,
                        peer
                    );
                    return;
                }
            }

            // 3.3 Establishes connection between ss-local and ss-remote
            transfer(&mut stream, &mut target_stream, &trans).await;
        }
    }
}

async fn transfer<A, B>(a: &mut A, b: &mut B, trans: &str)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match tokio::io::copy_bidirectional(a, b).await {
        Ok((atob, btoa)) => log::trace!("{} done: ltor {} bytes, rtol {} bytes", trans, atob, btoa),
        Err(e) => match e.kind() {
            ErrorKind::Other => log::warn!("{} error: {}", trans, e),
            _ => log::debug!("{} error: {}", trans, e),
        },
    }
}

async fn read_to_end<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = [0; 2048];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
    }

    Ok(())
}

fn make_timed_stream<T>(stream: T) -> TimeoutStream<T> {
    TimeoutStream::new(stream, constants::DEFAULT_TIMEOUT)
}
