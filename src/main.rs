mod args;

use std::sync::Arc;

use clap::Parser;

use ss_rs::{
    acl::Acl,
    context::Ctx,
    crypto::derive_key,
    tcp::{ss_local, ss_remote},
};

use args::Args;

#[tokio::main]
async fn main() {
    env_logger::init();

    let args = Args::parse();
    let method = args.method;
    let password = args.password;

    let remote_addr = match ss_rs::net::io::lookup_host(&args.remote_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("Resolve {} failed: {}", args.remote_addr, e);
            return;
        }
    };

    let mut ctx = Ctx::new();
    if let Some(path) = args.acl_path {
        let acl = match Acl::from_file(&path) {
            Ok(res) => res,
            Err(e) => {
                log::error!("Unable to load ACL file: {}", e);
                return;
            }
        };

        ctx.set_acl(acl);
    }

    let mut key = vec![0u8; method.key_size()];
    derive_key(password.as_bytes(), &mut key);

    let ctx = Arc::new(ctx);

    if let Some(local_addr) = args.local_addr {
        let local_addr = match ss_rs::net::io::lookup_host(&local_addr).await {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("Resolve {} failed: {}", local_addr, e);
                return;
            }
        };

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
