use std::{error::Error, fmt::Display, str::FromStr};

#[derive(Debug, Clone, Copy)]
pub enum Method {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl Method {
    pub fn new(name: &str) -> Result<Self, MethodError> {
        Method::from_str(name)
    }
}

impl Method {
    #[inline(always)]
    pub const fn key_size(&self) -> usize {
        match self {
            Method::ChaCha20Poly1305 | Method::Aes256Gcm => 32,
            Method::Aes128Gcm => 16,
        }
    }

    #[inline(always)]
    pub const fn salt_size(&self) -> usize {
        match self {
            Method::ChaCha20Poly1305 | Method::Aes256Gcm => 32,
            Method::Aes128Gcm => 16,
        }
    }

    #[inline(always)]
    pub const fn iv_size(&self) -> usize {
        12
    }

    #[inline(always)]
    pub const fn tag_size(&self) -> usize {
        16
    }
}

impl ToString for Method {
    fn to_string(&self) -> String {
        match self {
            Method::ChaCha20Poly1305 => "chacha20-ietf-poly1305".to_owned(),
            Method::Aes128Gcm => "aes-128-gcm".to_owned(),
            Method::Aes256Gcm => "aes-256-gcm".to_owned(),
        }
    }
}

impl FromStr for Method {
    type Err = MethodError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "chacha20-ietf-poly1305" => Ok(Method::ChaCha20Poly1305),
            "aes-128-gcm" => Ok(Method::Aes128Gcm),
            "aes-256-gcm" => Ok(Method::Aes256Gcm),
            s => Err(MethodError::new(s)),
        }
    }
}

#[derive(Debug)]
pub struct MethodError {
    method: String,
}

impl MethodError {
    pub fn new<T: ToString>(method: T) -> MethodError {
        MethodError {
            method: method.to_string(),
        }
    }
}

impl Display for MethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no supported method: {}", self.method)
    }
}

impl Error for MethodError {}
