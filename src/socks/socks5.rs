use std::{
    fmt::Display,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use tokio::io::{AsyncRead, AsyncReadExt};

// const VERSION: u8 = 0x05;

pub enum Socks5Addr {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
    DomainName((String, u16)),
}

impl Socks5Addr {
    pub async fn construct<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8];
        reader.read_exact(&mut buf).await?;
        let atyp = buf[0];

        match atyp {
            // Ipv4
            1 => {
                let mut buf = [0u8; 6];
                reader.read_exact(&mut buf).await?;

                let ipv4_addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);

                Ok(Socks5Addr::Ipv4(SocketAddrV4::new(ipv4_addr, port)))
            }
            // Domain name
            3 => {
                let mut buf = [0u8];
                reader.read_exact(&mut buf).await?;
                let len = buf[0] as usize;

                let mut buf = vec![0u8; len + 2];
                reader.read_exact(&mut buf).await?;
                let domain_name = match String::from_utf8(buf[..len].to_vec()) {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("{:?} is not a domain name", buf),
                        ))
                    }
                };

                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);

                Ok(Socks5Addr::DomainName((domain_name, port)))
            }
            // Ipv6
            4 => {
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
}

impl Display for Socks5Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Addr::Ipv4(v4) => write!(f, "{}", v4.to_string()),
            Socks5Addr::Ipv6(v6) => write!(f, "{}", v6.to_string()),
            Socks5Addr::DomainName((host, port)) => write!(f, "{}:{}", host, port),
        }
    }
}
