//! SIP 003 plugin implementation.

use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, TcpListener},
    process::Stdio,
};

use tokio::process::{Child, Command};

/// Starts a plugin with the given options.
///
/// Returns listening address and the child process.
///
/// For ss-local: the listening address is plugin address.
///
/// For ss-remote: the listening address is ss-remote address (ss-remote is behind the plugin).
pub fn start_plugin(
    plugin: &str,
    plugin_opts: &str,
    raw_addr: SocketAddr,
    is_server: bool,
) -> io::Result<(SocketAddr, Child)> {
    log::info!(
        "Starting plugin ({}) with options ({})",
        plugin,
        plugin_opts
    );

    let free_port = match find_free_port() {
        Some(port) => port,
        None => {
            return Err(io::Error::new(ErrorKind::Other, "no free port available"));
        }
    };

    let listening_addr: SocketAddr = match is_server {
        true => format!("{}:{}", raw_addr.ip(), free_port).parse().unwrap(),
        false => format!("127.0.0.1:{}", free_port).parse().unwrap(),
    };

    let local_addr = listening_addr.clone();
    let remote_addr = raw_addr;
    let plugin = exec_plugin(plugin, plugin_opts, local_addr, remote_addr)?;

    match is_server {
        true => log::info!("Plugin listening on {}", remote_addr),
        false => log::info!("Plugin listening on {}", local_addr),
    }

    Ok((listening_addr, plugin))
}

fn exec_plugin(
    plugin: &str,
    plugin_opts: &str,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> io::Result<Child> {
    Command::new(plugin)
        .env("SS_LOCAL_HOST", local_addr.ip().to_string())
        .env("SS_LOCAL_PORT", local_addr.port().to_string())
        .env("SS_REMOTE_HOST", remote_addr.ip().to_string())
        .env("SS_REMOTE_PORT", remote_addr.port().to_string())
        .env("SS_PLUGIN_OPTIONS", plugin_opts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // .stderr(Stdio::null())
        .spawn()
}

fn find_free_port() -> Option<u16> {
    for port in (1025..=u16::MAX).rev() {
        match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(_) => return Some(port),
            Err(_) => continue,
        }
    }

    None
}
