use std::{io::Write, sync::Arc};

use env_logger::{Builder, Env};
use tokio::process::Child;

use ss_rs::{
    acl::Acl,
    context::Ctx,
    crypto::derive_key,
    plugin::start_plugin,
    tcp::{ss_local, ss_remote},
    url::SsUrl,
};

mod args;

#[tokio::main]
async fn main() {
    // 1. Parses the command line arguments and initializes logger
    let args = args::parse();

    init_logger(args.verbose);

    let mut remote_addr = match ss_rs::net::lookup_host(&args.remote_addr).await {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("Resolve {} failed: {}", args.remote_addr, e);
            return;
        }
    };

    if args.show_url {
        let url = SsUrl::from(args);
        println!("{}", url);
        return;
    } else if args.show_cfg {
        println!("{:#?}", args);
        return;
    }

    let method = args.method;
    let password = args.password;
    let is_server = args.local_addr.is_none();

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

    // 4. Starts plugin
    let mut plugin = None;

    if let Some(plugin_name) = args.plugin {
        let (addr, process) = match start_plugin(
            &plugin_name,
            &args.plugin_opts.unwrap_or_default(),
            remote_addr,
            is_server,
        ) {
            Ok(res) => res,
            Err(e) => {
                log::error!("Unable to start plugin: {}", e);
                return;
            }
        };

        remote_addr = addr;
        plugin = Some(process);
    }

    // 5. Starts shadowsocks server
    if let Some(local_addr) = local_addr {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            res = async { plugin.as_mut().map(|p| p.wait()).unwrap().await }, if plugin.is_some() => {
                match res {
                    Ok(x) => log::error!("Plugin exited with status: {}", x),
                    Err(e) => log::error!("Wait plugin failed: {}", e),
                }

                return;
            }
            res = ss_local(local_addr, remote_addr, method, key, ctx) => {
                match res {
                    Ok(_) => {}
                    Err(e) => log::error!("Unable to start ss-local: {}", e),
                }
            }
        }
    } else {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            res = async { plugin.as_mut().map(|p| p.wait()).unwrap().await }, if plugin.is_some() => {
                match res {
                    Ok(x) => log::error!("Plugin exited with status: {}", x),
                    Err(e) => log::error!("Wait plugin failed: {}", e),
                }

                return;
            }
            res = ss_remote(remote_addr, method, key, ctx) => {
                match res {
                    Ok(_) => {}
                    Err(e) => log::error!("Unable to start ss-remote: {}", e),
                }
            }
        }
    }

    kill_plugin(plugin).await;
}

fn init_logger(verbose: bool) {
    let fallback_filter = match verbose {
        true => "ss_rs=debug",
        false => "ss_rs=info",
    };

    let env = Env::default().default_filter_or(fallback_filter);

    Builder::from_env(env)
        .format(|buf, record| {
            let datetime = chrono::Local::now();
            let datetime = datetime.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

            let style = buf.default_level_style(record.level());

            writeln!(
                buf,
                "[{} {}] {}",
                datetime,
                style.value(record.level()),
                record.args()
            )
        })
        .init();
}

async fn kill_plugin(process: Option<Child>) {
    if let Some(mut child) = process {
        match child.kill().await {
            Ok(_) => {}
            Err(e) => log::error!("Kill plugin failed: {}", e),
        };
    }
}
