//! Pluggable storage backends for session state.
#[cfg(feature = "cookie-session")]
#[cfg_attr(docsrs, doc(cfg(feature = "cookie-session")))]
pub use cookie::CookieSessionStore;
#[cfg(feature = "redis-session")]
#[cfg_attr(docsrs, doc(cfg(feature = "redis-session")))]
pub use redis_rs::{RedisSessionStore, RedisSessionStoreBuilder};

mod session_key;
pub use session_key::SessionKey;
mod interface;
pub use interface::{LoadError, SaveError, SessionStore, UpdateError};

#[cfg(feature = "cookie-session")]
mod cookie;
#[cfg(feature = "redis-session")]
mod redis_rs;

#[cfg(feature = "redis-session")]
mod utils;
