//! A set of ip networks.

use std::net::IpAddr;

use bitvec::{
    order::{BitOrder, Msb0},
    slice::BitSlice,
    store::BitStore,
    view::BitView,
};

use crate::net::cidr::Cidr;

struct Trie {
    root: TrieNode,
}

impl Trie {
    pub fn new() -> Self {
        Trie {
            root: TrieNode::new(),
        }
    }

    pub fn insert_bits<T, O>(&mut self, bits: &BitSlice<T, O>)
    where
        T: BitStore,
        O: BitOrder,
    {
        let mut cur = &mut self.root;

        for bit in bits.iter() {
            match *bit {
                true => {
                    if cur.right.is_none() {
                        cur.right = Some(Box::new(TrieNode::new()));
                    }

                    cur = unsafe { cur.right.as_mut().unwrap_unchecked().as_mut() };
                }
                false => {
                    if cur.left.is_none() {
                        cur.left = Some(Box::new(TrieNode::new()));
                    }

                    cur = unsafe { cur.left.as_mut().unwrap_unchecked().as_mut() };
                }
            }
        }

        cur.is_complete = true;
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        let mut cur = &self.root;
        let bits = data.view_bits::<Msb0>();

        for bit in bits.iter() {
            match *bit {
                true => {
                    if cur.right.is_none() {
                        return false;
                    }

                    cur = unsafe { cur.right.as_ref().unwrap_unchecked().as_ref() };
                }
                false => {
                    if cur.left.is_none() {
                        return false;
                    }

                    cur = unsafe { cur.left.as_ref().unwrap_unchecked().as_ref() };
                }
            }

            if cur.is_complete {
                break;
            }
        }

        true
    }

    pub fn clear(&mut self) {
        self.root.left = None;
        self.root.right = None;
        self.root.is_complete = false;
    }
}

struct TrieNode {
    left: Option<Box<TrieNode>>,
    right: Option<Box<TrieNode>>,
    is_complete: bool,
}

impl TrieNode {
    pub fn new() -> Self {
        TrieNode {
            left: None,
            right: None,
            is_complete: false,
        }
    }
}

/// Stores a set of ip networks.
pub struct IpSet {
    ipv4: Trie,
    ipv6: Trie,
}

impl IpSet {
    /// Creates a new ip set.
    pub fn new() -> Self {
        IpSet {
            ipv4: Trie::new(),
            ipv6: Trie::new(),
        }
    }

    /// Inserts a new ip network into the set.
    pub fn insert(&mut self, cidr: Cidr) {
        let mask = cidr.mask as usize;

        match cidr.addr {
            IpAddr::V4(v4) => self
                .ipv4
                .insert_bits(&v4.octets().view_bits::<Msb0>()[..mask]),
            IpAddr::V6(v6) => self
                .ipv6
                .insert_bits(&v6.octets().view_bits::<Msb0>()[..mask]),
        }
    }

    /// Checks whether the given ip address is in the ip set.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.ipv4.contains(&v4.octets()),
            IpAddr::V6(v6) => self.ipv6.contains(&v6.octets()),
        }
    }

    /// Clears the ip set.
    pub fn clear(&mut self) {
        self.ipv4.clear();
        self.ipv6.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_set() {
        let iplist = [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "192.168.0.0/16",
            "220.160.0.0/11",
            "255.255.255.255/32",
            "::1/128",
            "::ffff:127.0.0.1/104",
            "fc00::/7",
            "fe80::/10",
            "2001:b28:f23d:f001::e/128",
        ];

        let mut set = IpSet::new();

        for ip in iplist {
            set.insert(ip.parse().unwrap());
        }

        assert_eq!(set.contains("0.0.0.1".parse().unwrap()), true);
        assert_eq!(set.contains("127.0.0.1".parse().unwrap()), true);
        assert_eq!(set.contains("192.168.0.1".parse().unwrap()), true);
        assert_eq!(set.contains("220.181.38.148".parse().unwrap()), true);
        assert_eq!(set.contains("255.255.255.255".parse().unwrap()), true);

        assert_eq!(set.contains("::1".parse().unwrap()), true);
        assert_eq!(set.contains("::ffff:127.0.0.1".parse().unwrap()), true);
        assert_eq!(set.contains("fc00::ffff".parse().unwrap()), true);
        assert_eq!(set.contains("fe80::1234".parse().unwrap()), true);
        assert_eq!(set.contains("2001:b28:f23d:f001::e".parse().unwrap()), true);

        assert_eq!(set.contains("1.1.1.1".parse().unwrap()), false);
        assert_eq!(set.contains("128.0.0.1".parse().unwrap()), false);
        assert_eq!(set.contains("8.7.198.46".parse().unwrap()), false);
        assert_eq!(set.contains("210.181.38.251".parse().unwrap()), false);
        assert_eq!(set.contains("::ffff:192.0.0.1".parse().unwrap()), false);
        assert_eq!(set.contains("2001:b28:f23d:1::f".parse().unwrap()), false);

        set.clear();

        assert_eq!(set.contains("0.0.0.1".parse().unwrap()), false);
        assert_eq!(set.contains("127.0.0.1".parse().unwrap()), false);
        assert_eq!(set.contains("192.168.0.1".parse().unwrap()), false);
        assert_eq!(set.contains("220.181.38.148".parse().unwrap()), false);
        assert_eq!(set.contains("255.255.255.255".parse().unwrap()), false);

        assert_eq!(set.contains("::1".parse().unwrap()), false);
        assert_eq!(set.contains("::ffff:127.0.0.1".parse().unwrap()), false);
        assert_eq!(set.contains("fc00::ffff".parse().unwrap()), false);
        assert_eq!(set.contains("fe80::1234".parse().unwrap()), false);
    }
}
