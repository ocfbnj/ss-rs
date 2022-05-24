//! Encryption and decryption.

pub mod aead;
pub mod cipher;

use std::ops::Deref;

use hkdf::Hkdf;
use sha1::Sha1;

/// A simple encapsulation of bytes array.
#[derive(Debug)]
pub struct Nonce {
    value: Vec<u8>,
}

impl Nonce {
    /// Creates a new nonce.
    pub fn new(len: usize) -> Self {
        Nonce {
            value: vec![0; len],
        }
    }

    /// Increment the nonce.
    pub fn increment(&mut self) {
        for i in 0..self.value.len() {
            self.value[i] = self.value[i].wrapping_add(1);
            if self.value[i] != 0 {
                break;
            }
        }
    }
}

impl Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Produces a subkey that is cryptographically strong even if the input secret key is weak.
pub fn hkdf_sha1(key: &[u8], salt: &[u8], subkey: &mut [u8]) {
    let hkdf = Hkdf::<Sha1>::new(Some(salt), key);
    hkdf.expand(b"ss-subkey", subkey).expect(&format!(
        "{} is a invalid output length, expected {}",
        subkey.len(),
        key.len()
    ));
}

/// Generates the master key from a password.
pub fn derive_key(password: &[u8], key: &mut [u8]) {
    let key_size = key.len();
    let mut md_buf: Vec<u8> = Vec::new();

    let mut j = 0;
    while j < key_size {
        md_buf.append(&mut password.to_vec());
        let md = md5::compute(&md_buf).0;

        for &b in md.iter() {
            if j >= key_size {
                break;
            }

            key[j] = b;
            j += 1;
        }

        md_buf = md.to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha1_key128() {
        let key = [1u8; 16];
        let salt = b"1234567812345678";
        let mut subkey = [0u8; 16];
        let expected_subkey: [u8; 16] = [
            176, 72, 135, 140, 255, 57, 14, 7, 193, 98, 58, 118, 112, 42, 119, 97,
        ];

        hkdf_sha1(&key, salt, &mut subkey);

        assert_eq!(subkey, expected_subkey);
    }

    #[test]
    fn test_hkdf_sha1_key256() {
        let key = [1u8; 32];
        let salt = b"12345678123456781234567812345678";
        let mut subkey = [0u8; 32];
        let expected_subkey: [u8; 32] = [
            128, 145, 113, 44, 108, 52, 99, 117, 243, 229, 199, 245, 55, 99, 251, 53, 56, 225, 92,
            92, 5, 94, 252, 21, 4, 211, 164, 43, 251, 44, 61, 208,
        ];

        hkdf_sha1(&key, salt, &mut subkey);

        assert_eq!(subkey, expected_subkey);
    }

    #[test]
    fn test_derive_key128() {
        let password = b"hehe";
        let mut key = [0u8; 16];
        let expected_key = [
            82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106,
        ];

        derive_key(password, &mut key);

        assert_eq!(key, expected_key);
    }

    #[test]
    fn test_derive_key256() {
        let password = b"hehe";
        let mut key = [0u8; 32];
        let expected_key = [
            82, 156, 168, 5, 10, 0, 24, 7, 144, 207, 136, 182, 52, 104, 130, 106, 109, 81, 225,
            207, 24, 87, 148, 16, 101, 57, 172, 239, 219, 100, 183, 95,
        ];

        derive_key(password, &mut key);

        assert_eq!(key, expected_key);
    }
}
