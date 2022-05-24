//! SOCKS protocol implementation.

pub mod socks4;
pub mod socks5;

use std::{
    fmt::{self, Display, Formatter},
    io,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::socks::{socks4::Socks4Addr, socks5::Socks5Addr};

/// Errors when handle SOCKS protocols.
#[derive(Debug)]
pub enum Error {
    /// Unsupported socks version.
    Version(u8),

    /// Socks version number is inconsistent with before.
    VersionInconsistent { now: u8, before: u8 },

    /// No supported socks method found.
    Method,

    /// Unsupported socks command.
    Command(u8),

    /// The requested domain name is not a string.
    DomainName,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Version(v) => write!(f, "{} is the unsupported socks version", v),
            Error::VersionInconsistent { now, before } => {
                write!(
                    f,
                    "socks version number({}) is inconsistent with before({})",
                    now, before
                )
            }
            Error::Method => write!(f, "only support the NO AUTHENTICATION method"),
            Error::Command(cmd) => write!(f, "only support the CONNECT method, request {}", cmd),
            Error::DomainName => write!(f, "the requested domain name is not a string."),
        }
    }
}

impl std::error::Error for Error {}

/// Represents a SOCKS address.
pub enum SocksAddr {
    Socks4Addr(Socks4Addr),
    Socks5Addr(Socks5Addr),
}

impl Display for SocksAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SocksAddr::Socks4Addr(socks4) => write!(f, "{}", socks4),
            SocksAddr::Socks5Addr(socks5) => write!(f, "{}", socks5),
        }
    }
}

/// SOCKS4a / SOCKS5 handshake.
///
/// Returns a SOCKS address.
pub async fn handshake<S>(stream: &mut S) -> io::Result<SocksAddr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8];
    stream.read_exact(&mut buf).await?;
    let version = buf[0];

    match version {
        socks4::constants::VERSION => Ok(SocksAddr::Socks4Addr(socks4::handshake(stream).await?)),
        socks5::constants::VERSION => Ok(SocksAddr::Socks5Addr(socks5::handshake(stream).await?)),
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            Error::Version(version),
        )),
    }
}
