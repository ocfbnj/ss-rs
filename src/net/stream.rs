use std::{
    fmt::{self, Display, Formatter},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_core::ready;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream as TokioTcpStream, ToSocketAddrs},
};

use crate::{
    context::Ctx,
    crypto::{
        cipher::{Cipher, Method},
        hkdf_sha1, Nonce,
    },
    net::{buf::OwnedReadBuf, io::MAXIMUM_PAYLOAD_SIZE},
};

pub struct TcpStream {
    inner_stream: TokioTcpStream,
}

impl TcpStream {
    pub fn new(inner_stream: TokioTcpStream) -> Self {
        TcpStream { inner_stream }
    }

    pub async fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Ok(TcpStream {
            inner_stream: TokioTcpStream::connect(addr).await?,
        })
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner_stream = &mut self.get_mut().inner_stream;
        Pin::new(inner_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let inner_stream = &mut self.get_mut().inner_stream;
        Pin::new(inner_stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner_stream = &mut self.get_mut().inner_stream;
        Pin::new(inner_stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner_stream = &mut self.get_mut().inner_stream;
        Pin::new(inner_stream).poll_shutdown(cx)
    }
}

pub struct EncryptedTcpStream {
    inner_stream: TokioTcpStream,

    cipher_method: Method,
    cipher_key: Vec<u8>,

    enc_cipher: Option<Cipher>,
    dec_cipher: Option<Cipher>,

    enc_nonce: Nonce,
    dec_nonce: Nonce,

    incoming_salt: Option<Vec<u8>>, // for replay protection

    read_state: ReadState,
    write_state: WriteState,

    in_payload: Vec<u8>,  // decrypted payload
    out_payload: Vec<u8>, // encrypted payload

    read_buf: OwnedReadBuf,

    ctx: Arc<Ctx>,
}

impl EncryptedTcpStream {
    pub fn new(
        inner_stream: TokioTcpStream,
        cipher_method: Method,
        cipher_key: &[u8],
        ctx: Arc<Ctx>,
    ) -> Self {
        EncryptedTcpStream {
            inner_stream,
            cipher_method,
            cipher_key: cipher_key.to_owned(),
            enc_cipher: None,
            dec_cipher: None,
            enc_nonce: Nonce::new(cipher_method.iv_size()),
            dec_nonce: Nonce::new(cipher_method.iv_size()),
            incoming_salt: None,
            read_state: ReadState::ReadSalt,
            write_state: WriteState::WriteSalt,
            in_payload: Vec::new(),
            out_payload: Vec::new(),
            read_buf: OwnedReadBuf::zero(),
            ctx: ctx.clone(),
        }
    }

    pub async fn connect<A: ToSocketAddrs>(
        addr: A,
        cipher_method: Method,
        cipher_key: &[u8],
        ctx: Arc<Ctx>,
    ) -> io::Result<Self> {
        let inner_stream = TokioTcpStream::connect(addr).await?;

        Ok(EncryptedTcpStream::new(
            inner_stream,
            cipher_method,
            cipher_key,
            ctx,
        ))
    }
}

impl EncryptedTcpStream {
    fn poll_read_decrypt_helper(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let res = ready!(self.poll_read_decrypt(cx, buf));

        if let Err(e) = res {
            if !(e.kind() == io::ErrorKind::UnexpectedEof && e.to_string() == "the source get eof")
            {
                return Err(e).into();
            }
        }

        Ok(()).into()
    }

    fn poll_read_decrypt(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::ReadSalt => {
                    ready!(self.poll_read_salt(cx))?;
                    self.read_state = ReadState::ReadLength;
                }
                ReadState::ReadLength => {
                    let len = ready!(self.poll_read_length(cx))?;
                    self.read_state = ReadState::ReadPayload(len);
                }
                ReadState::ReadPayload(payload_len) => {
                    self.in_payload = ready!(self.poll_read_payload(cx, payload_len))?;
                    self.read_state = ReadState::ReadPayloadOut;
                }
                ReadState::ReadPayloadOut => {
                    let buf_len = buf.capacity();
                    let payload_len = self.in_payload.len();

                    if buf_len >= payload_len {
                        buf.put_slice(&self.in_payload);
                        self.read_state = ReadState::ReadLength;
                    } else {
                        let (data, remaining) = self.in_payload.split_at(buf_len);
                        buf.put_slice(data);
                        self.in_payload = remaining.to_owned();
                        self.read_state = ReadState::ReadPayloadOut;
                    }

                    return Ok(()).into();
                }
            }
        }
    }

    fn poll_read_salt(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.dec_cipher.is_none() {
            let mut salt = vec![0u8; self.cipher_method.salt_size()];
            ready!(self.poll_read_exact(cx, &mut salt))?;

            self.incoming_salt = Some(salt.clone());

            let mut subkey = vec![0u8; self.cipher_method.key_size()];
            hkdf_sha1(&self.cipher_key, &salt, &mut subkey);

            let cipher = Cipher::new(self.cipher_method, &mut subkey);
            self.dec_cipher.replace(cipher);
        }

        Ok(()).into()
    }

    fn poll_read_length(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut buf = vec![0u8; 2 + self.cipher_method.tag_size()];
        ready!(self.poll_read_exact(cx, &mut buf))?;

        let len = self.decrypt(&buf)?;
        let len = [len[0], len[1]];
        let payload_len = (u16::from_be_bytes(len) as usize) & MAXIMUM_PAYLOAD_SIZE;

        if let Some(salt) = self.incoming_salt.take() {
            if !self.ctx.check_replay(&salt) {
                return Err(io::Error::new(io::ErrorKind::Other, Error::DuplicateSalt)).into();
            }
        }

        Ok(payload_len).into()
    }

    fn poll_read_payload(
        &mut self,
        cx: &mut Context<'_>,
        payload_len: usize,
    ) -> Poll<io::Result<Vec<u8>>> {
        let mut buf = vec![0u8; payload_len + self.cipher_method.tag_size()];
        ready!(self.poll_read_exact(cx, &mut buf))?;
        let payload = self.decrypt(&buf)?;

        Ok(payload).into()
    }

    fn poll_read_exact(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<()>> {
        if self.read_buf.is_full() {
            self.read_buf = OwnedReadBuf::new(buf.len());
        }

        while !self.read_buf.is_full() {
            let mut read_buf = ReadBuf::new(self.read_buf.get_unfilled());
            let remaining = read_buf.remaining();

            ready!(Pin::new(&mut self.inner_stream).poll_read(cx, &mut read_buf))?;

            let nread = remaining - read_buf.remaining();
            if nread == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the source get eof",
                ))
                .into();
            }

            self.read_buf.advance(nread);
        }

        buf.copy_from_slice(self.read_buf.get_filled());

        Ok(()).into()
    }
}

impl AsyncRead for EncryptedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_decrypt_helper(cx, buf)
    }
}

impl EncryptedTcpStream {
    fn poll_write_encrypt(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state {
                WriteState::WriteSalt => {
                    ready!(self.poll_write_salt(cx))?;
                    self.write_state = WriteState::WriteLength;
                }
                WriteState::WriteLength => {
                    ready!(self.poll_write_length(cx, payload))?;
                    self.write_state = WriteState::WritePayload;
                }
                WriteState::WritePayload => {
                    ready!(self.poll_write_payload(cx, payload))?;
                    self.write_state = WriteState::WritePayloadOut;
                }
                WriteState::WritePayloadOut => {
                    while !self.out_payload.is_empty() {
                        let nwrite = ready!(
                            Pin::new(&mut self.inner_stream).poll_write(cx, &self.out_payload)
                        )?;

                        if nwrite == 0 {
                            return Err(io::ErrorKind::BrokenPipe.into()).into();
                        }

                        self.out_payload = self.out_payload[nwrite..].to_vec();
                    }

                    self.write_state = WriteState::WriteLength;

                    let length = usize::min(payload.len(), MAXIMUM_PAYLOAD_SIZE);
                    return Ok(length).into();
                }
            }
        }
    }

    fn poll_write_salt(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use rand::prelude::*;

        if self.enc_cipher.is_none() {
            let mut salt = vec![0u8; self.cipher_method.salt_size()];
            let mut rng = StdRng::from_entropy();
            rng.fill_bytes(&mut salt);

            let mut subkey = vec![0u8; self.cipher_method.key_size()];
            hkdf_sha1(&self.cipher_key, &salt, &mut subkey);

            let cipher = Cipher::new(self.cipher_method, &mut subkey);
            self.enc_cipher.replace(cipher);

            self.out_payload.append(&mut salt);
        }

        Ok(()).into()
    }

    fn poll_write_length(&mut self, _cx: &mut Context<'_>, payload: &[u8]) -> Poll<io::Result<()>> {
        let length = usize::min(payload.len(), MAXIMUM_PAYLOAD_SIZE);
        let len = (length as u16).to_be_bytes();

        let mut buf = self.encrypt(&len)?;
        self.out_payload.append(&mut buf);

        Ok(()).into()
    }

    fn poll_write_payload(
        &mut self,
        _cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<()>> {
        let length = usize::min(payload.len(), MAXIMUM_PAYLOAD_SIZE);

        let mut buf = self.encrypt(&payload[..length])?;
        self.out_payload.append(&mut buf);

        Ok(()).into()
    }
}

impl AsyncWrite for EncryptedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_encrypt(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner_stream = &mut self.get_mut().inner_stream;
        Pin::new(inner_stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner_stream = &mut self.get_mut().inner_stream;
        Pin::new(inner_stream).poll_shutdown(cx)
    }
}

impl EncryptedTcpStream {
    fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        match self
            .enc_cipher
            .as_ref()
            .expect("no salt received")
            .encrypt(&self.enc_nonce, plaintext)
        {
            Ok(data) => {
                self.enc_nonce.increment();
                Ok(data)
            }
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, Error::Encryption)),
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        match self
            .dec_cipher
            .as_ref()
            .expect("no salt received")
            .decrypt(&self.dec_nonce, ciphertext)
        {
            Ok(data) => {
                self.dec_nonce.increment();
                Ok(data)
            }
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, Error::Decryption)),
        }
    }
}

/// Errors during shadowsocks communication.
#[derive(Debug)]
pub enum Error {
    /// Encryption error.
    Encryption,

    /// Decryption error.
    Decryption,

    /// Duplicate salt received, possible replay attack.
    DuplicateSalt,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encryption => write!(f, "encryption error"),
            Error::Decryption => write!(f, "decryption error"),
            Error::DuplicateSalt => write!(f, "duplicate salt received, possible replay attack"),
        }
    }
}

impl std::error::Error for Error {}

enum ReadState {
    ReadSalt,
    ReadLength,
    ReadPayload(usize),
    ReadPayloadOut,
}

enum WriteState {
    WriteSalt,
    WriteLength,
    WritePayload,
    WritePayloadOut,
}
