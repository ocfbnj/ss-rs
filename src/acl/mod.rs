/// A set of ip networks.
pub mod ip_set;

/// CIDR parser.
pub mod cidr;

use std::{
    io::{self, ErrorKind},
    net::IpAddr,
    path::Path,
};

use crate::acl::ip_set::IpSet;

use self::cidr::Cidr;

/// Access control list.
pub struct Acl {
    bypass_list: IpSet,
    proxy_list: IpSet,
    outbound_block_list: IpSet,

    mode: Mode,
}

impl Acl {
    /// Creates a empty ACL.
    pub fn new() -> Self {
        Acl {
            bypass_list: IpSet::new(),
            proxy_list: IpSet::new(),
            outbound_block_list: IpSet::new(),
            mode: Mode::WhiteList,
        }
    }

    /// Creates a new acl from a file.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(Self::from_str(&data))
    }

    /// Creates a new acl from a string.
    pub fn from_str(data: &str) -> Self {
        // Trims whitespace and comments.
        let lines = data
            .lines()
            .map(|line| {
                let line = line.trim();
                let end = line.find('#').unwrap_or(line.len());
                &line[..end]
            })
            .filter(|line| !line.is_empty());

        let mut acl = Acl::new();
        let mut cur_ip_set = &mut acl.bypass_list;

        fn insert(record: &str, ip_set: &mut IpSet) -> io::Result<()> {
            let cidr: Cidr = record.parse()?;
            ip_set.insert(cidr);

            Ok(())
        }

        for line in lines {
            match line {
                "[proxy_all]" | "[accept_all]" => acl.mode = Mode::WhiteList,
                "[bypass_all]" | "[reject_all]" => acl.mode = Mode::BlackList,
                "[bypass_list]" | "[black_list]" => cur_ip_set = &mut acl.bypass_list,
                "[proxy_list]" | "[white_list]" => cur_ip_set = &mut acl.proxy_list,
                "[outbound_block_list]" => cur_ip_set = &mut acl.outbound_block_list,
                _ => match insert(line, cur_ip_set) {
                    Err(e) if e.kind() == ErrorKind::Other => {
                        log::warn!("Insert {} to the ip set failed: {}", line, e);
                    }
                    _ => {}
                },
            }
        }

        acl
    }

    /// Returns true if the given ip or host should be bypassed.
    pub fn is_bypass(&self, ip: IpAddr, _host: Option<&str>) -> bool {
        if self.bypass_list.contains(ip) {
            return true;
        }

        if self.proxy_list.contains(ip) {
            return false;
        }

        self.mode == Mode::BlackList
    }

    /// Returns true if the given ip or host should be block.
    pub fn is_block_outbound(&self, ip: IpAddr, _host: Option<&str>) -> bool {
        if self.outbound_block_list.contains(ip) {
            return true;
        }

        self.mode == Mode::BlackList
    }
}

/// Access control list mode.
#[derive(PartialEq, Eq)]
pub enum Mode {
    // Proxies all addresses that didn't match any rules. (default)
    WhiteList,

    // Bypasses all addresses that didn't match any rules
    BlackList,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl() {
        const DATA: &'static str = "
        [proxy_all]

        [bypass_list]
        0.0.0.0/8
        10.0.0.0/8
        100.64.0.0/10
        127.0.0.0/8
        169.254.0.0/16
        172.16.0.0/12
        192.0.0.0/24
        192.0.2.0/24
        192.88.99.0/24
        192.168.0.0/16
        198.18.0.0/15
        198.51.100.0/24
        203.0.113.0/24
        224.0.0.0/4
        240.0.0.0/4
        255.255.255.255/32
        ::1/128
        ::ffff:127.0.0.1/104
        fc00::/7
        fe80::/10
        ";

        let acl = Acl::from_str(DATA);

        assert_eq!(acl.is_bypass("127.0.0.1".parse().unwrap(), None), true);
        assert_eq!(acl.is_bypass("192.168.0.1".parse().unwrap(), None), true);
        assert_eq!(acl.is_bypass("::1".parse().unwrap(), None), true);
        assert_eq!(
            acl.is_bypass("::ffff:127.0.0.1".parse().unwrap(), None),
            true
        );

        assert_eq!(acl.is_bypass("126.0.0.1".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("1.1.1.1".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("8.8.8.8".parse().unwrap(), None), false);

        assert_eq!(acl.is_bypass("::2".parse().unwrap(), None), false);
        assert_eq!(
            acl.is_bypass("::ffff:192.168.0.1".parse().unwrap(), None),
            false
        );
    }

    #[test]
    fn test_error() {
        assert!(Acl::from_file(Path::new("1234567890abcdefghijklmnopqrstuvwxyz")).is_err());
    }
}
