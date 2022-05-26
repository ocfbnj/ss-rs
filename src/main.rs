mod args;

use std::{io::Write, sync::Arc};

use clap::Parser;
use env_logger::{Builder, Env};

use ss_rs::{
    acl::Acl,
    context::Ctx,
    crypto::derive_key,
    tcp::{ss_local, ss_remote},
};

use args::Args;

#[tokio::main]
async fn main() {
    // 1. Parses the command line arguments and initializes logger
    let args = Args::parse();

    init_logger(args.verbose);

    let method = args.method;
    let password = args.password;

    let remote_addr = match ss_rs::net::lookup_host(&args.remote_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("Resolve {} failed: {}", args.remote_addr, e);
            return;
        }
    };

    let mut local_addr = None;
    if let Some(addr) = args.local_addr {
        match ss_rs::net::lookup_host(&addr).await {
            Ok(addr) => local_addr = Some(addr),
            Err(e) => {
                log::error!("Resolve {} failed: {}", addr, e);
                return;
            }
        };
    }

    // 2. Derives a key from the given password
    let mut key = vec![0u8; method.key_size()];
    derive_key(password.as_bytes(), &mut key);

    // 3. Prepares shadowsocks context
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
    let ctx = Arc::new(ctx);

    // 4. Starts shadowsocks server
    if let Some(local_addr) = local_addr {
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

fn init_logger(verbose: bool) {
    let fallback_filter = match verbose {
        true => "ss_rs=debug",
        false => "ss_rs=info",
    };

    let env = Env::default().default_filter_or(fallback_filter);

    Builder::from_env(env)
        .format(|buf, record| {
            let timestamp = buf.timestamp_millis();
            let style = buf.default_level_style(record.level());

            writeln!(
                buf,
                "[{} {}] {}",
                timestamp,
                style.value(record.level()),
                record.args()
            )
        })
        .init();
}
