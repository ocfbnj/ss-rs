use std::sync::Arc;

use clap::Parser;

use ss_rs::{
    args::Args,
    context::Ctx,
    crypto::derive_key,
    tcp::{ss_local, ss_remote},
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();
    let remote_addr = args.remote_addr;
    let method = args.method;
    let password = args.password;

    let mut key = vec![0u8; method.key_size()];
    derive_key(password.as_bytes(), &mut key);
    let ctx = Arc::new(Ctx::new());

    if let Some(local_addr) = args.local_addr {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            res = ss_local(local_addr, remote_addr, method, key, ctx) => {
                match res {
                    Ok(_) => {}
                    Err(e) => log::error!("Unable to start ss-local: {}", e),
                }
            },
        }
    } else {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            res = ss_remote(remote_addr, method, key, ctx) => {
                match res {
                    Ok(_) => {}
                    Err(e) => log::error!("Unable to start ss-remote: {}", e),
                }
            },
        }
    }
}
