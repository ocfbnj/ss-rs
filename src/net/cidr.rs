//! CIDR parser.

use std::{
    fmt::{self, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

mod constants {
    pub const MAXIMUM_IPV4_MASK: u8 = 32;
    pub const MAXIMUM_IPV6_MASK: u8 = 128;
}

/// Represents a CIDR network.
pub struct Cidr {
    /// The network.
    pub addr: IpAddr,

    /// The subnet mask.
    pub mask: u8,
}

impl FromStr for Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, mask) = match s.split_once("/") {
            Some(res) => res,
            None => return Err(Error::NoSlash),
        };

        let is_ipv4 = Ipv4Addr::from_str(addr);
        let is_ipv6 = Ipv6Addr::from_str(addr);

        if is_ipv4.is_err() && is_ipv6.is_err() {
            return Err(Error::NotAddr(addr.to_owned()));
        }

        if let Ok(v4) = is_ipv4 {
            let mask = match mask.parse::<u8>() {
                Ok(res) => res,
                Err(_) => return Err(Error::NotMask(mask.to_string())),
            };

            if mask > constants::MAXIMUM_IPV4_MASK {
                return Err(Error::NotMask(mask.to_string()));
            }

            return Ok(Cidr {
                addr: IpAddr::V4(v4),
                mask,
            });
        }

        let v6 = unsafe { is_ipv6.unwrap_unchecked() };

        let mask = match mask.parse::<u8>() {
            Ok(res) => res,
            Err(_) => return Err(Error::NotMask(mask.to_owned())),
        };

        if mask > constants::MAXIMUM_IPV6_MASK {
            return Err(Error::NotMask(mask.to_string()));
        }

        Ok(Cidr {
            addr: IpAddr::V6(v6),
            mask,
        })
    }
}

/// Errors when parse a CIDR.
#[derive(Debug)]
pub enum Error {
    /// No forward slash found.
    NoSlash,

    /// Not a ip address.
    NotAddr(String),

    /// Not a subnet mask.
    NotMask(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoSlash => write!(f, "no forward slash found"),
            Error::NotAddr(addr) => write!(f, "{} is not a valid ip address", addr),
            Error::NotMask(mask) => write!(f, "{} is not a valid subnet mask", mask),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr() {
        let iplist = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "220.160.0.0/11",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "::ffff:127.0.0.1/104",
            "fc00::/7",
            "fe80::/10",
            "2001:b28:f23d:f001::e/128",
        ];

        for ip in iplist {
            let _: Cidr = ip.parse().unwrap();
        }
    }

    #[test]
    fn test_error() {
        assert!("127.0.0.1".parse::<Cidr>().is_err());
        assert!("127.0.0./12".parse::<Cidr>().is_err());
        assert!("127.0.0/12".parse::<Cidr>().is_err());

        assert!(":1:/12".parse::<Cidr>().is_err());
        assert!("122ff:/12".parse::<Cidr>().is_err());
        assert!("122z:/12".parse::<Cidr>().is_err());

        assert!("127.0.0.1/33".parse::<Cidr>().is_err());
        assert!("127.0.0.1/99999999".parse::<Cidr>().is_err());

        assert!("::1/129".parse::<Cidr>().is_err());
        assert!("1222::1/999999999999".parse::<Cidr>().is_err());
    }
}
