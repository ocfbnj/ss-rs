use aead::{Aead, Error, Key, NewAead, Nonce};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

use crate::crypto::cipher::Method;

pub enum CipherVariant {
    ChaCha20Poly1305(ChaCha20Poly1305),
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl CipherVariant {
    pub fn new(method: Method, key: &[u8]) -> Self {
        match method {
            Method::ChaCha20Poly1305 => CipherVariant::ChaCha20Poly1305(ChaCha20Poly1305::new(
                Key::<ChaCha20Poly1305>::from_slice(key),
            )),
            Method::Aes128Gcm => {
                CipherVariant::Aes128Gcm(Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key)))
            }
            Method::Aes256Gcm => {
                CipherVariant::Aes256Gcm(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
            }
        }
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            CipherVariant::ChaCha20Poly1305(c) => {
                c.encrypt(Nonce::<ChaCha20Poly1305>::from_slice(nonce), plaintext)
            }
            CipherVariant::Aes128Gcm(c) => {
                c.encrypt(Nonce::<Aes128Gcm>::from_slice(nonce), plaintext)
            }
            CipherVariant::Aes256Gcm(c) => {
                c.encrypt(Nonce::<Aes256Gcm>::from_slice(nonce), plaintext)
            }
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            CipherVariant::ChaCha20Poly1305(c) => {
                c.decrypt(Nonce::<ChaCha20Poly1305>::from_slice(nonce), ciphertext)
            }
            CipherVariant::Aes128Gcm(c) => {
                c.decrypt(Nonce::<Aes128Gcm>::from_slice(nonce), ciphertext)
            }
            CipherVariant::Aes256Gcm(c) => {
                c.decrypt(Nonce::<Aes256Gcm>::from_slice(nonce), ciphertext)
            }
        }
    }
}

pub struct Cipher {
    method: Method,
    cipher: CipherVariant,
}

impl Cipher {
    pub fn new(method: Method, key: &[u8]) -> Self {
        Cipher {
            method,
            cipher: CipherVariant::new(method, key),
        }
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.cipher.encrypt(nonce, plaintext)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.cipher.decrypt(nonce, ciphertext)
    }

    pub fn method(&self) -> Method {
        self.method
    }
}
