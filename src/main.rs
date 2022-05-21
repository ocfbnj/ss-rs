use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

use clap::Parser;
use tokio::sync::oneshot;

use ss_rs::{
    args::Args,
    context::Ctx,
    crypto::{cipher::Method, derive_key},
    net::{
        io::transfer,
        listener::EncryptedTcpListener,
        stream::{EncryptedTcpStream, TcpStream},
    },
    socks::socks5::Socks5Addr,
};

async fn serve(stream: EncryptedTcpStream, peer: SocketAddr) {
    let (mut rd1, wr1) = tokio::io::split(stream);

    let target_addr = match tokio::time::timeout(
        Duration::from_secs(15),
        Socks5Addr::construct(&mut rd1),
    )
    .await
    {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => {
            log::error!("Error on {}: {}", peer, e);
            return;
        }
        Err(e) => {
            log::warn!("Error on {}: {}", peer, e);
            return;
        }
    };

    log::debug!("Request target address: {} -> {}", peer, target_addr);

    // Establish connection between peer and target
    let target_stream = match TcpStream::connect(target_addr.to_string()).await {
        Ok(stream) => stream,
        Err(e) => {
            log::warn!("Cannot connect to {}: {}", target_addr, e);
            return;
        }
    };

    let (rd2, wr2) = tokio::io::split(target_stream);

    let transfer1 = format!("{} -> {}", peer, target_addr);
    let transfer2 = format!("{} -> {}", target_addr, peer);

    let (tx1, rx1) = oneshot::channel::<()>();
    let (tx2, rx2) = oneshot::channel::<()>();

    transfer(transfer1, tx2, rx1, rd1, wr2);
    transfer(transfer2, tx1, rx2, rd2, wr1);
}

async fn ss_remote(
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

        tokio::spawn(serve(encrypted_stream, peer));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args = Args::parse();

    let addr = args.remote_addr;
    let method = args.method;
    let password = args.password;

    let mut key = vec![0u8; method.key_size()];
    derive_key(password.as_bytes(), &mut key);

    let ctx = Arc::new(Ctx::new());

    ss_remote(addr, method, key, ctx).await
}
