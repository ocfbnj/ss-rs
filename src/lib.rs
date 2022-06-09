//! An unofficial shadowsocks implementation that can work with official shadowsocks.
//!
//! # Features
//!
//! - [x] [SOCKS5](https://datatracker.ietf.org/doc/html/rfc1928) CONNECT command
//! - [x] [AEAD](https://shadowsocks.org/en/wiki/AEAD-Ciphers.html) ciphers
//! - [x] Defend against [replay attacks](https://github.com/shadowsocks/shadowsocks-org/issues/44)
//! - [x] [Access control list](https://github.com/shadowsocks/shadowsocks-rust#acl)
//!
//! # Get Started
//!
//! ## Server
//!
//! Start a server listening on port 5421 using `chacha20-ietf-poly1305` AEAD cipher with password `ocfbnj`.
//!
//! ~~~bash
//! ss-rs -s 0.0.0.0:5421 -k ocfbnj -m chacha20-ietf-poly1305
//! ~~~
//!
//! ## Client
//!
//! Start a client connecting to the `ocfbnj.cn`.
//!
//! The client listens on port 1080 for incoming SOCKS5 connections and uses `chacha20-ietf-poly1305` AEAD cipher with password `ocfbnj`.
//!
//! ~~~bash
//! ss-rs -s ocfbnj.cn:5421 -l localhost:1080 -k ocfbnj -m chacha20-ietf-poly1305
//! ~~~
//!
//! # How to build
//!
//! ## Prerequisites
//!
//! - Cargo installed (See [this](https://www.rust-lang.org/learn/get-started)).
//!
//! ## Building with Cargo
//!
//! 1. Clone
//!
//!     ~~~bash
//!     git clone https://github.com/ocfbnj/ss-rs
//!     cd ss-rs
//!     ~~~
//!
//! 2. Build
//!
//!     ~~~bash
//!     cargo b --release
//!     ~~~
//!
//!     Now you can find the binary in `./target/release/ss-rs`.

pub mod acl;
pub mod context;
pub mod crypto;
pub mod net;
pub mod plugin;
pub mod security;
pub mod socks5;
pub mod tcp;
pub mod url;
