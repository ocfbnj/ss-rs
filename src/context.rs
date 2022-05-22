use crate::security::ReplayProtection;

/// Context for the shadowsocks communication.
pub struct Ctx {
    replay_protection: ReplayProtection,
}

impl Ctx {
    pub fn new() -> Self {
        Ctx {
            replay_protection: ReplayProtection::new(),
        }
    }

    /// Checks for possible replay attacks.
    pub fn check_replay(&self, salt: &[u8]) -> bool {
        self.replay_protection.check_and_insert(&salt)
    }
}
