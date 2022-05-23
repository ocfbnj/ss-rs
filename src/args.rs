use std::path::PathBuf;

use clap::Parser;

use ss_rs::crypto::cipher::Method;

/// Command-line parameter definitions for the ss-rs program.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
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

    /// Encrypt method:
    /// aes-128-gcm, aes-256-gcm,
    /// chacha20-ietf-poly1305
    #[clap(short = 'm', long, default_value = "chacha20-ietf-poly1305")]
    pub method: Method,

    /// Access control list
    #[clap(long = "acl")]
    pub acl_path: Option<PathBuf>,
}
