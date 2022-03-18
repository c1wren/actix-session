use crate::storage::SessionKey;
use anyhow::anyhow;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;
use std::convert::TryInto;

use anyhow::Result;

static DEFAULT_PORT: u16 = 6379;

/// This session key generation routine follows [OWASP's recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy).
pub(crate) fn generate_session_key() -> SessionKey {
    let value = std::iter::repeat(())
        .map(|()| OsRng.sample(Alphanumeric))
        .take(64)
        .collect::<Vec<_>>();
    // These unwraps will never panic because pre-conditions are always verified
    // (i.e. length and character set)
    String::from_utf8(value).unwrap().try_into().unwrap()
}

/// This function takes a redis URL string and parses it into a URL
/// as used by rust-url.  This is necessary as the default parser does
/// not understand how redis URLs function.
pub fn parse_redis_url(input: &str) -> Option<url::Url> {
    match url::Url::parse(input) {
        Ok(result) => match result.scheme() {
            "redis" | "rediss" | "redis+unix" | "unix" => Some(result),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Defines the connection address.
///
/// Not all connection addresses are supported on all platforms.  For instance
/// to connect to a unix socket you need to run this on an operating system
/// that supports them.
#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionAddr {
    /// Format for this is `(host, port)`.
    Tcp(String, u16),
    /// Format for this is `(host, port)`.
    TcpTls {
        /// Hostname
        host: String,
        /// Port
        port: u16,
        /// Disable hostname verification when connecting.
        ///
        /// # Warning
        ///
        /// You should think very carefully before you use this method. If hostname
        /// verification is not used, any valid certificate for any site will be
        /// trusted for use from any other. This introduces a significant
        /// vulnerability to man-in-the-middle attacks.
        insecure: bool,
    },
}

/// Holds the connection information that redis should use for connecting.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    /// A connection address for where to connect to.
    pub addr: ConnectionAddr,

    /// A boxed connection address for where to connect to.
    pub redis: RedisConnectionInfo,
}

/// Redis specific/connection independent information used to establish a connection to redis.
#[derive(Clone, Debug, Default)]
pub struct RedisConnectionInfo {
    /// The database number to use.  This is usually `0`.
    pub db: i64,
    /// Optionally a username that should be used for connection.
    pub username: Option<String>,
    /// Optionally a password that should be used for connection.
    pub password: Option<String>,
}

/// Converts an object into a connection info struct.  This allows the
/// constructor of the client to accept connection information in a
/// range of different formats.
pub trait IntoConnectionInfo {
    /// Converts the object into a connection info object.
    fn into_connection_info(self) -> Result<ConnectionInfo>;
}

impl IntoConnectionInfo for ConnectionInfo {
    fn into_connection_info(self) -> Result<ConnectionInfo> {
        Ok(self)
    }
}

impl<'a> TryInto<ConnectionInfo> for &'a str {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<ConnectionInfo, Self::Error> {
        self.into_connection_info()
    }
}

impl<'a> IntoConnectionInfo for &'a str {
    fn into_connection_info(self) -> Result<ConnectionInfo> {
        match parse_redis_url(self) {
            Some(u) => u.into_connection_info(),
            None => Err(anyhow!("Redis URL did not parse")),
        }
    }
}

impl<T> TryInto<ConnectionInfo> for (T, u16)
where
    T: Into<String>,
{
    type Error = anyhow::Error;

    fn try_into(self) -> Result<ConnectionInfo, Self::Error> {
        self.into_connection_info()
    }
}

impl<T> IntoConnectionInfo for (T, u16)
where
    T: Into<String>,
{
    fn into_connection_info(self) -> Result<ConnectionInfo> {
        Ok(ConnectionInfo {
            addr: ConnectionAddr::Tcp(self.0.into(), self.1),
            redis: RedisConnectionInfo::default(),
        })
    }
}

impl TryInto<ConnectionInfo> for String {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<ConnectionInfo, Self::Error> {
        self.into_connection_info()
    }
}

impl IntoConnectionInfo for String {
    fn into_connection_info(self) -> Result<ConnectionInfo> {
        match parse_redis_url(&self) {
            Some(u) => u.into_connection_info(),
            None => Err(anyhow!("Redis URL did not parse")),
        }
    }
}

fn url_to_tcp_connection_info(url: url::Url) -> Result<ConnectionInfo> {
    let host = match url.host() {
        Some(host) => host.to_string(),
        None => return Err(anyhow!("Missing hostname")),
    };
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let addr = if url.scheme() == "rediss" {
        match url.fragment() {
            Some("insecure") => ConnectionAddr::TcpTls {
                host,
                port,
                insecure: true,
            },
            Some(_) => return Err(anyhow!("only #insecure is supported as URL fragment")),
            _ => ConnectionAddr::TcpTls {
                host,
                port,
                insecure: false,
            },
        }
    } else {
        ConnectionAddr::Tcp(host, port)
    };
    Ok(ConnectionInfo {
        addr,
        redis: RedisConnectionInfo {
            db: match url.path().trim_matches('/') {
                "" => 0,
                path => match path.parse::<i64>().ok() {
                    Some(x) => x,
                    None => return Err(anyhow!("Invalid database number")),
                },
            },
            username: if url.username().is_empty() {
                None
            } else {
                match percent_encoding::percent_decode(url.username().as_bytes()).decode_utf8() {
                    Ok(decoded) => Some(decoded.into_owned()),
                    Err(_) => return Err(anyhow!("Username is not valid UTF-8 string")),
                }
            },
            password: match url.password() {
                Some(pw) => match percent_encoding::percent_decode(pw.as_bytes()).decode_utf8() {
                    Ok(decoded) => Some(decoded.into_owned()),
                    Err(_) => return Err(anyhow!("Password is not valid UTF-8 string")),
                },
                None => None,
            },
        },
    })
}

impl IntoConnectionInfo for url::Url {
    fn into_connection_info(self) -> Result<ConnectionInfo> {
        match self.scheme() {
            "redis" | "rediss" => url_to_tcp_connection_info(self),
            _ => {
                return Err(anyhow!(
                    "URL provided is not a redis URL or is not a supported redis URL"
                ))
            }
        }
    }
}
