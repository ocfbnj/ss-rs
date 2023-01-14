//! SS-URL parser

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose};

use crate::crypto::cipher::Method;

/// Represents a SS-URL.
#[derive(Debug)]
pub struct SsUrl {
    pub method: Method,
    pub password: String,
    pub hostname: String,
    pub port: u16,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub tag: Option<String>,
}

impl FromStr for SsUrl {
    type Err = ErrorKind;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("ss://") {
            return Err(ErrorKind::NotSsUrl);
        }
        s = &s[5..];

        let (method, password) = parse_userinfo(&mut s)?;
        let hostname = parse_hostname(&mut s)?;

        let port: u16;
        let mut plugin = None;
        let mut plugin_opts = None;
        let mut tag = None;

        if let Some(pos) = s.find(['/', '?', '#']) {
            port = parse_port(&s[..pos])?;

            let mut pos = pos;
            let mut has_plugin = false;

            loop {
                match s.as_bytes()[pos] {
                    b'/' => {
                        s = &s[pos + 1..];
                        match s.find(['?', '#']) {
                            Some(x) => pos = x,
                            None => break,
                        }
                    }
                    b'?' => {
                        has_plugin = true;

                        s = &s[pos + 1..];
                        match s.find(['#']) {
                            Some(x) => pos = x,
                            None => {
                                let (a, b) = parse_plugin(&s)?;
                                plugin = a;
                                plugin_opts = b;
                                break;
                            }
                        }
                    }
                    b'#' => {
                        if has_plugin {
                            let (a, b) = parse_plugin(&s[..pos])?;
                            plugin = a;
                            plugin_opts = b;
                        }

                        tag = Some(s[pos + 1..].to_owned());
                        break;
                    }
                    _ => {}
                }
            }
        } else {
            port = parse_port(&s)?;
        }

        Ok(SsUrl {
            method,
            password,
            hostname,
            port,
            plugin,
            plugin_opts,
            tag,
        })
    }
}

impl Display for SsUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = format!("{}:{}", self.method.to_string(), self.password);
        let s = general_purpose::URL_SAFE.encode(&s);
        let mut s = format!("ss://{}@{}:{}", s, self.hostname, self.port);

        if let Some(ref plugin) = self.plugin {
            s = format!("{}/?{}", s, plugin);
        }

        if let Some(ref plugin_opts) = self.plugin_opts {
            s = format!("{}={}", s, urlencoding::encode(plugin_opts));
        }

        if let Some(ref tag) = self.tag {
            s = format!("{}#{}", s, tag);
        }

        write!(f, "{}", s)
    }
}

fn parse_userinfo(s: &mut &str) -> Result<(Method, String), ErrorKind> {
    let pos = match s.find('@') {
        Some(x) => x,
        None => return Err(ErrorKind::Invalid),
    };

    let userinfo = &s[..pos];
    let userinfo = match general_purpose::URL_SAFE.decode(userinfo) {
        Ok(x) => String::from_utf8(x).unwrap(),
        Err(_) => return Err(ErrorKind::Decode),
    };

    let (method, password) = match userinfo.split_once(':') {
        Some(x) => x,
        None => return Err(ErrorKind::UserInfo),
    };

    let method: Method = match method.parse() {
        Ok(x) => x,
        Err(_) => return Err(ErrorKind::Method),
    };
    let password = password.to_owned();

    *s = &s[pos + 1..];
    Ok((method, password))
}

fn parse_hostname(s: &mut &str) -> Result<String, ErrorKind> {
    let pos = match s.find(':') {
        Some(x) => x,
        None => return Err(ErrorKind::Invalid),
    };

    let hostname = s[..pos].to_owned();

    *s = &s[pos + 1..];
    Ok(hostname)
}

fn parse_port(s: &str) -> Result<u16, ErrorKind> {
    match s.parse() {
        Ok(x) => Ok(x),
        Err(_) => Err(ErrorKind::Port),
    }
}

fn parse_plugin(s: &str) -> Result<(Option<String>, Option<String>), ErrorKind> {
    match s.split_once('=') {
        Some((a, b)) => Ok((Some(a.to_owned()), Some(match urlencoding::decode(b) {
            Ok(x) => x.into_owned(),
            Err(_) => return Err(ErrorKind::Plugin),
        }))),
        None => Ok((Some(s.to_owned()), None)),
    }
}

/// Errors when parsing a SS-URL.
#[derive(Debug)]
pub enum ErrorKind {
    /// Not a SS-URL.
    NotSsUrl,

    /// Base64 decode error.
    Decode,

    /// Invalid userinfo.
    UserInfo,

    /// Invalid method.
    Method,

    /// Invalid port number.
    Port,

    /// Invalid plugin.
    Plugin,

    /// Invalid url.
    Invalid,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::NotSsUrl => write!(f, "not a ss url"),
            ErrorKind::Decode => write!(f, "base64 decode error"),
            ErrorKind::UserInfo => write!(f, "invalid userinfo"),
            ErrorKind::Method => write!(f, "invalid method"),
            ErrorKind::Port => write!(f, "invalid port number"),
            ErrorKind::Plugin => write!(f, "invalid plugin"),
            ErrorKind::Invalid => write!(f, "invalid url"),
        }
    }
}

impl std::error::Error for ErrorKind {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let urllist = [
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888",
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/?",
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/?#",
            
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/?plugin",
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/?plugin=name%3Bplugin_opts",

            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/?plugin=url-encoded-plugin-argument-value%26unsupported-arguments%3Dshould-be-ignored#Dummy+profile+name",
            "ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#Example1",
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd2Q=@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2",
        ];

        for url in urllist.iter() {
            let ss_url = url.parse::<SsUrl>().unwrap();
            println!("{:#?}", ss_url);

            assert_eq!(&ss_url.to_string(), url);
        }

        let urllist = [
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/",
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888/#",
            "ss://YWVzLTI1Ni1nY206dGVzdA==@192.168.100.1:8888?#",
        ];

        for url in urllist.iter() {
            let ss_url = url.parse::<SsUrl>().unwrap();
            println!("{:#?}", ss_url);
        }
    }
}
