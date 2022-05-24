//! Shadowsocks context.

use std::net::IpAddr;

use crate::{acl::Acl, security::ReplayProtection};

/// Context for the shadowsocks communication.
///
/// It provides replay protection and access control list.
pub struct Ctx {
    replay_protection: ReplayProtection,
    acl: Option<Acl>,
}

impl Ctx {
    /// Creates a new context.
    pub fn new() -> Self {
        Ctx {
            replay_protection: ReplayProtection::new(),
            acl: None,
        }
    }

    /// Checks for possible replay attacks.
    pub fn check_replay(&self, salt: &[u8]) -> bool {
        self.replay_protection.check_and_insert(&salt)
    }

    /// Set access control list.
    pub fn set_acl(&mut self, acl: Acl) {
        self.acl = Some(acl);
    }

    /// Returns true if the given ip or host should be bypassed.
    pub fn is_bypass(&self, ip: IpAddr, host: Option<&str>) -> bool {
        match self.acl {
            Some(ref acl) => acl.is_bypass(ip, host),
            _ => false,
        }
    }

    /// Returns true if the given ip or host should be block.
    pub fn is_block_outbound(&self, ip: IpAddr, host: Option<&str>) -> bool {
        match self.acl {
            Some(ref acl) => acl.is_block_outbound(ip, host),
            _ => false,
        }
    }
}
