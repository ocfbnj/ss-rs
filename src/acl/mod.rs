//! Access control list.

pub mod cidr;
pub mod ip_set;
pub mod rule_set;

use std::{io, net::IpAddr, path::Path};

use regex::Regex;

use crate::{
    acl::cidr::Cidr,
    acl::{ip_set::IpSet, rule_set::RuleSet},
};

/// Access control list.
pub struct Acl {
    bypass_list: IpSet,
    proxy_list: IpSet,
    outbound_block_list: IpSet,

    bypass_rules: RuleSet,
    proxy_rules: RuleSet,
    outbound_block_rules: RuleSet,

    mode: Mode,
}

impl Acl {
    /// Creates a empty ACL.
    pub fn new() -> Self {
        Acl {
            bypass_list: IpSet::new(),
            proxy_list: IpSet::new(),
            outbound_block_list: IpSet::new(),
            bypass_rules: RuleSet::new(),
            proxy_rules: RuleSet::new(),
            outbound_block_rules: RuleSet::new(),
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
        let mut cur_rule_set = &mut acl.bypass_rules;

        fn insert(record: &str, ip_set: &mut IpSet, rule_set: &mut RuleSet) -> bool {
            let cidr = record.parse::<Cidr>();
            if let Ok(cidr) = cidr {
                ip_set.insert(cidr);
                log::trace!("Insert {} to the ip set", record);
                return true;
            }

            let regex = record.parse::<Regex>();
            if let Ok(regex) = regex {
                rule_set.insert(regex);
                log::trace!("Insert {} to the rule set", record);
                return true;
            }

            false
        }

        for line in lines {
            match line {
                "[proxy_all]" | "[accept_all]" => acl.mode = Mode::WhiteList,
                "[bypass_all]" | "[reject_all]" => acl.mode = Mode::BlackList,
                "[bypass_list]" | "[black_list]" => {
                    cur_ip_set = &mut acl.bypass_list;
                    cur_rule_set = &mut acl.bypass_rules;
                }
                "[proxy_list]" | "[white_list]" => {
                    cur_ip_set = &mut acl.proxy_list;
                    cur_rule_set = &mut acl.proxy_rules;
                }
                "[outbound_block_list]" => {
                    cur_ip_set = &mut acl.outbound_block_list;
                    cur_rule_set = &mut acl.outbound_block_rules;
                }
                _ => {
                    if !insert(line, cur_ip_set, cur_rule_set) {
                        log::warn!("Insert {} to the ACL failed", line);
                    }
                }
            }
        }

        acl
    }

    /// Returns true if the given ip or host should be bypassed.
    pub fn is_bypass(&self, ip: IpAddr, host: Option<&str>) -> bool {
        let ip_str = ip.to_string();

        if let Some(host) = host {
            if host != ip_str {
                if self.bypass_rules.contains(host) {
                    return true;
                }

                if self.proxy_rules.contains(host) {
                    return false;
                }
            }
        }

        if self.bypass_list.contains(ip) {
            return true;
        }

        if self.proxy_list.contains(ip) {
            return false;
        }

        self.mode == Mode::BlackList
    }

    /// Returns true if the given ip or host should be block.
    pub fn is_block_outbound(&self, ip: IpAddr, host: Option<&str>) -> bool {
        if self.outbound_block_list.contains(ip) {
            return true;
        }

        let ip = ip.to_string();

        if self.outbound_block_rules.contains(&ip) {
            return true;
        }

        if let Some(host) = host {
            if host != ip {
                if self.outbound_block_rules.contains(host) {
                    return true;
                }
            }
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
        const DATA: &'static str = r"
        [proxy_all]

        [bypass_list]
        127.0.0.0/8
        192.168.0.0/16
        ::1/128
        fc00::/7

        (^|\.)baidu\.com$
        (^|\.)google\.com$
        (^|\.)ocfbnj\.cn$
        ";

        let acl = Acl::from_str(DATA);

        assert_eq!(acl.is_bypass("127.0.0.1".parse().unwrap(), None), true);
        assert_eq!(acl.is_bypass("192.168.0.1".parse().unwrap(), None), true);

        assert_eq!(acl.is_bypass("::1".parse().unwrap(), None), true);
        assert_eq!(acl.is_bypass("fc00::".parse().unwrap(), None), true);

        assert_eq!(
            acl.is_bypass("220.181.38.148".parse().unwrap(), Some("baidu.com")),
            true
        );

        assert_eq!(
            acl.is_bypass("220.181.38.148".parse().unwrap(), Some("www.baidu.com")),
            true
        );

        assert_eq!(
            acl.is_bypass("8.214.121.167".parse().unwrap(), Some("ocfbnj.cn")),
            true
        );

        assert_eq!(acl.is_bypass("8.8.8.8".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("126.0.0.1".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("192.167.0.1".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("192.169.0.1".parse().unwrap(), None), false);

        assert_eq!(acl.is_bypass("8888::".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("::2".parse().unwrap(), None), false);
        assert_eq!(acl.is_bypass("fa00::".parse().unwrap(), None), false);

        assert_eq!(
            acl.is_bypass("8.8.8.8".parse().unwrap(), Some("qq.com")),
            false
        );

        assert_eq!(
            acl.is_bypass("220.181.38.148".parse().unwrap(), Some("baidu.com ")),
            false
        );

        assert_eq!(
            acl.is_bypass("220.181.38.148".parse().unwrap(), Some("3baidu.com ")),
            false
        );

        assert_eq!(
            acl.is_bypass("220.181.38.148".parse().unwrap(), Some("ocfbnj.com ")),
            false
        );
    }

    #[test]
    fn test_error() {
        assert!(Acl::from_file(Path::new("1234567890abcdefghijklmnopqrstuvwxyz")).is_err());
    }
}
