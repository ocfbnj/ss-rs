use std::path::PathBuf;

use clap::{command, Arg};

use ss_rs::{crypto::cipher::Method, url::SsUrl};

/// Command-line parameter definitions for the ss-rs program.
// #[derive(Parser, Debug)]
// #[clap(version, about)]
#[derive(Debug)]
pub struct Args {
    /// IP address and port of your remote server
    // #[clap(short = 's', long)]
    pub remote_addr: String,

    /// IP address and port of your local server (ss-local only)
    // #[clap(short = 'l', long)]
    pub local_addr: Option<String>,

    /// Password of your shadowsocks
    // #[clap(short = 'k', long)]
    pub password: String,

    /// Encryption method
    // #[clap(
    //     short = 'm',
    //     long,
    //     default_value = "chacha20-ietf-poly1305",
    //     possible_value = "chacha20-ietf-poly1305",
    //     possible_value = "aes-128-gcm",
    //     possible_value = "aes-256-gcm"
    // )]
    pub method: Method,

    /// Access control list
    // #[clap(long = "acl")]
    pub acl_path: Option<PathBuf>,

    /// Plugin
    // #[clap(long)]
    pub plugin: Option<String>,

    /// Plugin options
    // #[clap(long)]
    pub plugin_opts: Option<String>,

    /// Debug mode
    // #[clap(short, long)]
    pub verbose: bool,

    /// Print corresponding SS-URL and then exit
    // #[clap(long)]
    pub show_url: bool,

    /// Print corresponding shadowsocks config and then exit
    // #[clap(long)]
    pub show_cfg: bool,
}

impl From<Args> for SsUrl {
    fn from(args: Args) -> Self {
        let (hostname, port) = args.remote_addr.split_once(':').unwrap();

        SsUrl {
            method: args.method,
            password: args.password,
            hostname: hostname.to_owned(),
            port: port.parse().unwrap(),
            plugin: args.plugin,
            plugin_opts: args.plugin_opts,
            tag: None,
        }
    }
}

pub fn parse() -> Args {
    let matches = command!()
        .author("Repository: https://github.com/ocfbnj/ss-rs")
        .arg(
            Arg::new("remote-addr")
                .short('s')
                .long("remote-addr")
                .takes_value(true)
                .value_name("REMOTE_ADDR")
                .help("IP address and port of your remote server")
                .required_unless_present("url"),
        )
        .arg(
            Arg::new("local-addr")
                .short('l')
                .long("local-addr")
                .takes_value(true)
                .value_name("LOCAL_ADDR")
                .help("IP address and port of your local server (ss-local only)"),
        )
        .arg(
            Arg::new("password")
                .short('k')
                .long("password")
                .takes_value(true)
                .value_name("PASSWORD")
                .help("Password of your shadowsocks")
                .required_unless_present("url"),
        )
        .arg(
            Arg::new("method")
                .short('m')
                .long("method")
                .takes_value(true)
                .value_name("METHOD")
                .validator(|x| x.parse::<Method>())
                .help("Encryption method")
                .possible_values(["chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"])
                .default_value("chacha20-ietf-poly1305"),
        )
        .arg(
            Arg::new("acl")
                .long("acl")
                .takes_value(true)
                .value_name("ACL_PATH")
                .help("Access control list"),
        )
        .arg(
            Arg::new("plugin")
                .long("plugin")
                .takes_value(true)
                .value_name("PLUGIN")
                .conflicts_with("url")
                .help("Plugin"),
        )
        .arg(
            Arg::new("plugin-opts")
                .long("plugin-opts")
                .takes_value(true)
                .value_name("PLUGIN_OPTS")
                .conflicts_with("url")
                .help("Plugin options"),
        )
        .arg(
            Arg::new("url")
                .long("url")
                .takes_value(true)
                .value_name("SS_URL")
                .validator(|x| x.parse::<SsUrl>())
                .help("Specify ss-remote SS-URL"),
        )
        .arg(
            Arg::new("show-url")
                .long("show-url")
                .help("Print corresponding SS-URL and then exit"),
        )
        .arg(
            Arg::new("show-cfg")
                .long("show-cfg")
                .conflicts_with("show-url")
                .help("Print corresponding shadowsocks config and then exit"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Debug mode"),
        )
        .get_matches();

    let remote_addr;
    let password;
    let method;
    let plugin;
    let plugin_opts;

    if let Some(url) = matches.value_of("url") {
        let ss_url: SsUrl = url.parse().unwrap();

        remote_addr = format!("{}:{}", ss_url.hostname, ss_url.port);
        password = ss_url.password;
        method = ss_url.method;
        plugin = ss_url.plugin;
        plugin_opts = ss_url.plugin_opts;
    } else {
        remote_addr = matches.value_of("remote-addr").unwrap().to_owned();
        password = matches.value_of("password").unwrap().to_owned();
        method = matches.value_of("method").unwrap().parse().unwrap();
        plugin = matches.value_of("plugin").map(|x| x.to_owned());
        plugin_opts = matches.value_of("plugin-opts").map(|x| x.to_owned());
    }

    let local_addr = matches.value_of("local-addr").map(|x| x.to_owned());
    let acl_path = matches.value_of("acl").map(|x| x.into());
    let verbose = matches.is_present("verbose");
    let show_url = matches.is_present("show-url");
    let show_cfg = matches.is_present("show-cfg");

    Args {
        remote_addr,
        local_addr,
        password,
        method,
        acl_path,
        plugin,
        plugin_opts,
        verbose,
        show_url,
        show_cfg,
    }
}
