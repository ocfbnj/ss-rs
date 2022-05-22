use std::{io, net::SocketAddr, sync::Arc};

use tokio::net::{TcpListener as TokioTcpListener, ToSocketAddrs};

use crate::{
    context::Ctx,
    crypto::cipher::Method,
    net::stream::{EncryptedTcpStream, TcpStream},
};

pub struct TcpListener {
    inner_listener: TokioTcpListener,
}

impl TcpListener {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let inner_listener = TokioTcpListener::bind(addr).await?;
        Ok(TcpListener { inner_listener })
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.inner_listener.accept().await?;
        Ok((TcpStream::new(stream), addr))
    }
}

pub struct EncryptedTcpListener {
    inner_listener: TokioTcpListener,
    cipher_method: Method,
    cipher_key: Vec<u8>,
    ctx: Arc<Ctx>,
}

impl EncryptedTcpListener {
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        cipher_method: Method,
        cipher_key: &[u8],
        ctx: Arc<Ctx>,
    ) -> io::Result<Self> {
        let inner_listener = TokioTcpListener::bind(addr).await?;
        Ok(EncryptedTcpListener {
            inner_listener,
            cipher_method: cipher_method,
            cipher_key: cipher_key.to_owned(),
            ctx: ctx.clone(),
        })
    }

    pub async fn accept(&self) -> io::Result<(EncryptedTcpStream, SocketAddr)> {
        let (stream, addr) = self.inner_listener.accept().await?;
        Ok((
            EncryptedTcpStream::new(
                stream,
                self.cipher_method,
                &self.cipher_key,
                self.ctx.clone(),
            ),
            addr,
        ))
    }
}
