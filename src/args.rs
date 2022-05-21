use std::net::SocketAddr;

use clap::Parser;

use crate::crypto::cipher::Method;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Socket address of your remote server
    #[clap(short = 's', long)]
    pub remote_addr: SocketAddr,

    /// Socket address of your local server (ss-local only)
    #[clap(short = 'l', long)]
    pub local_addr: Option<SocketAddr>,

    /// Password of your shadowsocks
    #[clap(short = 'k', long)]
    pub password: String,

    /// Encrypt method:
    /// aes-128-gcm, aes-256-gcm,
    /// chacha20-ietf-poly1305
    #[clap(short = 'm', long, default_value = "chacha20-ietf-poly1305")]
    pub method: Method,
}
