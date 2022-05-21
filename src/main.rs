use std::{error::Error, sync::Arc};

use clap::Parser;

use ss_rs::{args::Args, context::Ctx, crypto::derive_key, tcp::ss_remote};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args = Args::parse();
    let addr = args.remote_addr;
    let method = args.method;
    let password = args.password;

    let mut key = vec![0u8; method.key_size()];
    derive_key(password.as_bytes(), &mut key);
    let ctx = Arc::new(Ctx::new());

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            Ok(())
        },
        res = ss_remote(addr, method, key, ctx) => {
            res
        },
    }
}
