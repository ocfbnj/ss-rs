use std::{
    fmt::{self, Display, Formatter},
    io,
    net::{Ipv4Addr, SocketAddrV4},
};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use super::Error;

pub mod constants {
    pub const VERSION: u8 = 0x04;

    // Command
    pub const COMMAND_CONNECT: u8 = 0x01;
}

/// Represents a SOCKS4/4a address.
pub enum Socks4Addr {
    Ipv4(SocketAddrV4),
    DomainName((String, u16)),
}

impl Socks4Addr {
    pub async fn construct<R>(reader: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let mut reader = BufReader::new(reader);

        let mut buf = [0u8; 6];
        reader.read_exact(&mut buf).await?;

        let port = u16::from_be_bytes([buf[0], buf[1]]);
        let addr: Socks4Addr;

        if buf[2..5].iter().all(|&x| x == 0) && buf[5] != 0 {
            // Domain name
            let mut userid = Vec::new();
            reader.read_until(0x00, &mut userid).await?;

            let mut domain_name_bytes = Vec::new();
            reader.read_until(0x00, &mut domain_name_bytes).await?;
            domain_name_bytes.pop(); // pop NULL byte

            let domain_name = match String::from_utf8(domain_name_bytes) {
                Ok(s) => s,
                Err(_) => return Err(io::Error::new(io::ErrorKind::Other, Error::DomainName)),
            };

            addr = Socks4Addr::DomainName((domain_name, port));
        } else {
            // Ipv4 address
            addr = Socks4Addr::Ipv4(SocketAddrV4::new(
                Ipv4Addr::new(buf[2], buf[3], buf[4], buf[5]),
                port,
            ));

            let mut userid = Vec::new();
            reader.read_until(0x00, &mut userid).await?;
        }

        Ok(addr)
    }
}

impl Display for Socks4Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Socks4Addr::Ipv4(v4) => write!(f, "{}", v4.to_string()),
            Socks4Addr::DomainName((host, port)) => write!(f, "{}:{}", host, port),
        }
    }
}

/// SOCKS4a handshake.
///
/// Notes: The first bytes is missing.
pub async fn handshake<S>(stream: &mut S) -> io::Result<Socks4Addr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;

    let cd = buf[0];
    if cd != constants::COMMAND_CONNECT {
        return Err(io::Error::new(io::ErrorKind::Other, Error::Command(cd)));
    }

    let addr = Socks4Addr::construct(stream).await?;

    let rsp = [0x00, 90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    stream.write_all(&rsp).await?;

    Ok(addr)
}
