//! Authenticated Encryption with Associated Data (AEAD) algorithms.

use aead::{Aead, Key, KeyInit, Nonce};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::crypto::cipher::Method;

/// AEAD variants.
pub enum Variant {
    ChaCha20Poly1305(ChaCha20Poly1305),
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl Variant {
    /// Creates a new AEAD variant with method and key.
    pub fn new(method: Method, key: &[u8]) -> Self {
        match method {
            Method::ChaCha20Poly1305 => Variant::ChaCha20Poly1305(ChaCha20Poly1305::new(
                Key::<ChaCha20Poly1305>::from_slice(key),
            )),
            Method::Aes128Gcm => {
                Variant::Aes128Gcm(Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key)))
            }
            Method::Aes256Gcm => {
                Variant::Aes256Gcm(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
            }
        }
    }

    /// Encrypts the given plaintext.
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> aead::Result<Vec<u8>> {
        match self {
            Variant::ChaCha20Poly1305(c) => {
                c.encrypt(Nonce::<ChaCha20Poly1305>::from_slice(nonce), plaintext)
            }
            Variant::Aes128Gcm(c) => c.encrypt(Nonce::<Aes128Gcm>::from_slice(nonce), plaintext),
            Variant::Aes256Gcm(c) => c.encrypt(Nonce::<Aes256Gcm>::from_slice(nonce), plaintext),
        }
    }

    /// Decrypts the given ciphertext.
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> aead::Result<Vec<u8>> {
        match self {
            Variant::ChaCha20Poly1305(c) => {
                c.decrypt(Nonce::<ChaCha20Poly1305>::from_slice(nonce), ciphertext)
            }
            Variant::Aes128Gcm(c) => c.decrypt(Nonce::<Aes128Gcm>::from_slice(nonce), ciphertext),
            Variant::Aes256Gcm(c) => c.decrypt(Nonce::<Aes256Gcm>::from_slice(nonce), ciphertext),
        }
    }
}
