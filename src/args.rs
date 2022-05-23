use std::path::PathBuf;

use clap::Parser;

use ss_rs::crypto::cipher::Method;

/// Command-line parameter definitions for the ss-rs program.
#[derive(Parser, Debug)]
#[clap(version, about)]
pub struct Args {
    /// IP address and port of your remote server
    #[clap(short = 's', long)]
    pub remote_addr: String,

    /// IP address and port of your local server (ss-local only)
    #[clap(short = 'l', long)]
    pub local_addr: Option<String>,

    /// Password of your shadowsocks
    #[clap(short = 'k', long)]
    pub password: String,

    /// Encryption method
    #[clap(
        short = 'm',
        long,
        default_value = "chacha20-ietf-poly1305",
        possible_value = "chacha20-ietf-poly1305",
        possible_value = "aes-128-gcm",
        possible_value = "aes-256-gcm"
    )]
    pub method: Method,

    /// Access control list
    #[clap(long = "acl")]
    pub acl_path: Option<PathBuf>,
}
