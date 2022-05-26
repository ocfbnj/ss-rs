//! SOCKS5 protocol implementation.

use std::{
    fmt::{self, Display, Formatter},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 protocol related constants.
pub mod constants {
    pub const VERSION: u8 = 0x05;

    // Atyp
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN_NAME: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;

    // Method
    pub const METHOD_NO_AUTHENTICATION: u8 = 0x00;

    // Command
    pub const COMMAND_CONNECT: u8 = 0x01;
}

/// Represents a SOCKS5 address.
pub enum Socks5Addr {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
    DomainName((String, u16)),
}

impl Socks5Addr {
    /// Constructs a new SOCKS5 address from a async input stream.
    pub async fn construct<R>(reader: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let mut buf = [0u8];
        reader.read_exact(&mut buf).await?;
        let atyp = buf[0];

        match atyp {
            constants::ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                reader.read_exact(&mut buf).await?;

                let ipv4_addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);

                Ok(Socks5Addr::Ipv4(SocketAddrV4::new(ipv4_addr, port)))
            }
            constants::ATYP_DOMAIN_NAME => {
                let mut buf = [0u8];
                reader.read_exact(&mut buf).await?;
                let len = buf[0] as usize;

                let mut buf = vec![0u8; len + 2];
                reader.read_exact(&mut buf).await?;

                let domain_name_bytes = buf[..len].to_vec();
                let domain_name = match String::from_utf8(domain_name_bytes) {
                    Ok(x) => x,
                    Err(_) => return Err(io::Error::new(io::ErrorKind::Other, Error::DomainName)),
                };

                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);

                Ok(Socks5Addr::DomainName((domain_name, port)))
            }
            constants::ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                reader.read_exact(&mut buf).await?;

                let a = u16::from_be_bytes([buf[0], buf[1]]);
                let b = u16::from_be_bytes([buf[2], buf[3]]);
                let c = u16::from_be_bytes([buf[4], buf[5]]);
                let d = u16::from_be_bytes([buf[6], buf[7]]);
                let e = u16::from_be_bytes([buf[8], buf[9]]);
                let f = u16::from_be_bytes([buf[10], buf[11]]);
                let g = u16::from_be_bytes([buf[12], buf[13]]);
                let h = u16::from_be_bytes([buf[14], buf[15]]);

                let ipv6_addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                let port = u16::from_be_bytes([buf[16], buf[17]]);

                Ok(Socks5Addr::Ipv6(SocketAddrV6::new(ipv6_addr, port, 0, 0)))
            }
            x => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{} is a invalid address type", x),
            )),
        }
    }

    /// Returns SOCKS5 address raw representation.
    pub fn get_raw_parts(&self) -> Vec<u8> {
        let mut addr = Vec::<u8>::new();

        match self {
            Socks5Addr::Ipv4(v4) => {
                addr.push(constants::ATYP_IPV4);
                addr.append(&mut v4.ip().octets().to_vec());
                addr.append(&mut v4.port().to_be_bytes().to_vec());
            }
            Socks5Addr::Ipv6(v6) => {
                addr.push(constants::ATYP_IPV6);
                addr.append(&mut v6.ip().octets().to_vec());
                addr.append(&mut v6.port().to_be_bytes().to_vec());
            }
            Socks5Addr::DomainName((domain_name, port)) => {
                addr.push(constants::ATYP_DOMAIN_NAME);
                addr.push(domain_name.len() as u8);
                addr.append(&mut domain_name.clone().into_bytes());
                addr.append(&mut port.to_be_bytes().to_vec());
            }
        };

        addr
    }
}

impl Display for Socks5Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Socks5Addr::Ipv4(v4) => write!(f, "{}", v4.to_string()),
            Socks5Addr::Ipv6(v6) => write!(f, "{}", v6.to_string()),
            Socks5Addr::DomainName((host, port)) => write!(f, "{}:{}", host, port),
        }
    }
}

/// Errors when handle SOCKS5 protocols.
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
            Error::DomainName => write!(f, "the requested domain name is not a string"),
        }
    }
}

impl std::error::Error for Error {}

/// SOCKS5 handshake.
pub async fn handshake<S>(stream: &mut S) -> io::Result<Socks5Addr>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    // Stage 1
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    let ver = buf[0];
    if ver != constants::VERSION {
        return Err(io::Error::new(io::ErrorKind::Other, Error::Version(ver)));
    }

    let mut methods = vec![0u8; buf[1] as usize];
    stream.read_exact(&mut methods).await?;

    if !methods
        .iter()
        .any(|&x| x == constants::METHOD_NO_AUTHENTICATION)
    {
        return Err(io::Error::new(io::ErrorKind::Other, Error::Method));
    }

    let rsp = [constants::VERSION, constants::METHOD_NO_AUTHENTICATION];
    stream.write_all(&rsp).await?;

    // Stage 2
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).await?;

    let ver = buf[0];
    if ver != constants::VERSION {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            Error::VersionInconsistent {
                now: ver,
                before: 0x05,
            },
        ));
    }

    let cmd = buf[1];
    if cmd != constants::COMMAND_CONNECT {
        return Err(io::Error::new(io::ErrorKind::Other, Error::Command(cmd)));
    }

    let addr = Socks5Addr::construct(stream).await?;

    let rsp = [
        constants::VERSION,
        0x00,
        0x00,
        constants::ATYP_IPV4,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    stream.write_all(&rsp).await?;

    Ok(addr)
}
