use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use crate::crypto::aead::Variant;

/// Shadowsocks cipher.
pub struct Cipher {
    method: Method,
    cipher: Variant,
}

impl Cipher {
    /// Creates a new Cipher with method and key.
    pub fn new(method: Method, key: &[u8]) -> Self {
        Cipher {
            method,
            cipher: Variant::new(method, key),
        }
    }

    /// Encrypts the given plaintext.
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> aead::Result<Vec<u8>> {
        self.cipher.encrypt(nonce, plaintext)
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> aead::Result<Vec<u8>> {
        self.cipher.decrypt(nonce, ciphertext)
    }

    /// Get the encryption method in use.
    pub fn method(&self) -> Method {
        self.method
    }
}

/// Errors when handle shadowsocks ciphers.
#[derive(Debug)]
pub enum Error {
    /// Unsupported encryption method.
    Method(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Method(name) => write!(f, "{} is unsupported encryption method", name),
        }
    }
}

impl std::error::Error for Error {}

/// Encryption methods.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl Method {
    /// Returns required key size of the method.
    #[inline(always)]
    pub const fn key_size(&self) -> usize {
        match self {
            Method::ChaCha20Poly1305 | Method::Aes256Gcm => 32,
            Method::Aes128Gcm => 16,
        }
    }

    /// Returns required salt size of the method.
    #[inline(always)]
    pub const fn salt_size(&self) -> usize {
        match self {
            Method::ChaCha20Poly1305 | Method::Aes256Gcm => 32,
            Method::Aes128Gcm => 16,
        }
    }

    /// Returns required iv size of the method.
    #[inline(always)]
    pub const fn iv_size(&self) -> usize {
        12
    }

    /// Returns required tag size of the method.
    #[inline(always)]
    pub const fn tag_size(&self) -> usize {
        16
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Method::ChaCha20Poly1305 => write!(f, "chacha20-ietf-poly1305"),
            Method::Aes128Gcm => write!(f, "aes-128-gcm"),
            Method::Aes256Gcm => write!(f, "aes-256-gcm"),
        }
    }
}

impl FromStr for Method {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "chacha20-ietf-poly1305" => Ok(Method::ChaCha20Poly1305),
            "aes-128-gcm" => Ok(Method::Aes128Gcm),
            "aes-256-gcm" => Ok(Method::Aes256Gcm),
            s => Err(Error::Method(s.to_owned())),
        }
    }
}
