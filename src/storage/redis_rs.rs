use super::utils::{generate_session_key, ConnectionAddr, ConnectionInfo};
use super::SessionKey;
use crate::storage::interface::{LoadError, SaveError, SessionState, UpdateError};
use crate::storage::SessionStore;
use fred::pool::RedisPool;
use fred::prelude::*;
use fred::types::TlsConfig;
use futures_util::StreamExt;
use std::sync::Arc;
use time::{self, Duration};

/// Use Redis as session storage backend.
///
/// ```no_run
/// use actix_web::{web, App, HttpServer, HttpResponse, Error};
/// use actix_session::{SessionMiddleware, storage::RedisSessionStore};
/// use actix_web::cookie::Key;
///
/// // The secret key would usually be read from a configuration file/environment variables.
/// fn get_secret_key() -> Key {
///     # todo!()
///     // [...]
/// }
///
/// #[actix_rt::main]
/// async fn main() -> std::io::Result<()> {
///     let secret_key = get_secret_key();
///     let redis_connection_string = "redis://127.0.0.1:6379";
///     let store = RedisSessionStore::new(redis_connection_string).await.unwrap();
///     HttpServer::new(move ||
///             App::new()
///             .wrap(SessionMiddleware::new(
///                 store.clone(),
///                 secret_key.clone()
///             ))
///             .default_service(web::to(|| HttpResponse::Ok())))
///         .bind(("127.0.0.1", 8080))?
///         .run()
///         .await
/// }
/// ```
///
/// ## TLS support
///
/// Add the `redis-tls-session` feature flag to enable TLS support. You can then establish a TLS
/// connection to Redis using the `rediss://` URL scheme:
///
/// ```no_run
/// use actix_session::{storage::RedisSessionStore};
///
/// # #[actix_rt::main]
/// # async fn main() {
/// let redis_connection_string = "rediss://127.0.0.1:6379";
/// let store = RedisSessionStore::new(redis_connection_string).await.unwrap();
/// # }
/// ```
///
/// ## Implementation notes
///
/// `RedisSessionStore` leverages [`redis-rs`](https://github.com/mitsuhiko/redis-rs) as Redis client.
#[derive(Clone)]
pub struct RedisSessionStore {
    configuration: CacheConfiguration,
    client: RedisPool,
}

#[derive(Clone)]
struct CacheConfiguration {
    cache_keygen: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl Default for CacheConfiguration {
    fn default() -> Self {
        Self {
            cache_keygen: Arc::new(|s| s.to_owned()),
        }
    }
}

impl RedisSessionStore {
    /// A fluent API to configure [`RedisSessionStore`].
    /// It takes as input the only required input to create a new instance of [`RedisSessionStore`] - a
    /// connection string for Redis.
    pub fn builder(connection_info: ConnectionInfo) -> RedisSessionStoreBuilder {
        RedisSessionStoreBuilder {
            configuration: Default::default(),
            connection_info,
            heartbeat_interval: 0,
            enable_connection_status_logging: false,
        }
    }

    /// Create a new instance of [`RedisSessionStore`] using the default configuration.
    /// It takes as input the only required input to create a new instance of [`RedisSessionStore`] - a
    /// connection string for Redis.
    pub async fn new(connection_info: ConnectionInfo) -> Result<RedisSessionStore, anyhow::Error> {
        Self::builder(connection_info).build().await
    }
}

/// A fluent builder to construct a [`RedisActorSessionStore`] instance with custom
/// configuration parameters.
#[must_use]
pub struct RedisSessionStoreBuilder {
    connection_info: ConnectionInfo,
    configuration: CacheConfiguration,
    heartbeat_interval: u32,
    enable_connection_status_logging: bool,
}

impl RedisSessionStoreBuilder {
    /// Set a custom cache key generation strategy, expecting a session key as input.
    pub fn cache_keygen<F>(mut self, keygen: F) -> Self
    where
        F: Fn(&str) -> String + 'static + Send + Sync,
    {
        self.configuration.cache_keygen = Arc::new(keygen);
        self
    }

    /// Set the interval in seconds for heartbeat. Disabled by default. 0 = disabled.
    pub fn heartbeat_interval(mut self, interval: u32) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Enable or disable connection status logging. Disabled by default.
    pub fn connection_status_logging(mut self, enabled: bool) -> Self {
        self.enable_connection_status_logging = enabled;
        self
    }

    /// Finalise the builder and return a [`RedisActorSessionStore`] instance.
    pub async fn build(self) -> Result<RedisSessionStore, anyhow::Error> {
        let config = match self.connection_info.addr {
            ConnectionAddr::Tcp(host, port) => RedisConfig {
                username: self.connection_info.redis.username,
                password: self.connection_info.redis.password,
                server: ServerConfig::Centralized { host, port },
                tls: None,
                ..Default::default()
            },
            ConnectionAddr::TcpTls {
                host,
                port,
                insecure,
            } => RedisConfig {
                username: self.connection_info.redis.username,
                password: self.connection_info.redis.password,
                server: ServerConfig::Centralized { host, port },
                tls: if insecure {
                    None
                } else {
                    Some(TlsConfig::default())
                },
                ..Default::default()
            },
        };

        let client = RedisPool::new(config, 10)?;

        client.connect(Some(ReconnectPolicy::default()));
        let _ = client.wait_for_connect().await?;

        if self.heartbeat_interval != 0 || self.enable_connection_status_logging {
            for cl in client.clients() {
                if self.heartbeat_interval != 0 {
                    tracing::debug!("Enabling heartbeat for client {}.", cl.id());

                    let clone = cl.clone();
                    let interval = self.heartbeat_interval as u64;
                    actix_web::rt::spawn(async move {
                        match clone
                            .enable_heartbeat(std::time::Duration::from_secs(interval), false)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::debug!("Unable to enable heartbeat due to error: {}", e);
                            }
                        };
                    });
                }

                if self.enable_connection_status_logging {
                    // run a function when the connection closes unexpectedly
                    actix_web::rt::spawn(cl.on_error().for_each(|e| async move {
                        tracing::debug!("Client received connection error: {:?}", e);
                    }));
                    // run a function whenever the client reconnects
                    actix_web::rt::spawn(cl.on_reconnect().for_each(move |client| async move {
                        tracing::debug!("Client {} reconnected.", client.id());
                        match client
                            .enable_heartbeat(std::time::Duration::from_secs(15), false)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::debug!("Unable to enable heartbeat due to error: {}", e);
                            }
                        };
                    }));
                }
            }
        }

        tracing::debug!("RedisSessionStore has been created and client is connected.");

        Ok(RedisSessionStore {
            configuration: self.configuration,
            client,
        })
    }
}

#[async_trait::async_trait(?Send)]
impl SessionStore for RedisSessionStore {
    async fn load(&self, session_key: &SessionKey) -> Result<Option<SessionState>, LoadError> {
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());
        let val: Option<String> = self.client.get(cache_key).await.map_err(LoadError::Redis)?;

        match val {
            Some(value) => Ok(serde_json::from_str(&value)
                .map_err(Into::into)
                .map_err(LoadError::Deserialization)?),
            None => Ok(None),
        }
    }

    async fn save(
        &self,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let body = serde_json::to_string(&session_state)
            .map_err(Into::into)
            .map_err(SaveError::Serialization)?;
        let session_key = generate_session_key();
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());

        self.client
            .set(
                cache_key,
                body,
                Some(Expiration::EX(ttl.whole_seconds())),
                Some(SetOptions::NX),
                false,
            )
            .await
            .map_err(SaveError::Redis)?;

        Ok(session_key)
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: SessionState,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        let body = serde_json::to_string(&session_state)
            .map_err(Into::into)
            .map_err(UpdateError::Serialization)?;
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());

        let v: Option<RedisValue> = self
            .client
            .set(
                cache_key,
                body,
                Some(Expiration::EX(ttl.whole_seconds())),
                Some(SetOptions::XX),
                true,
            )
            .await
            .map_err(UpdateError::Redis)?;

        match v {
            Some(_) => Ok(session_key),
            None => {
                // The SET operation was not performed because the XX condition was not verified.
                // This can happen if the session state expired between the load operation and the update
                // operation. Unlucky, to say the least.
                // We fall back to the `save` routine to ensure that the new key is unique.

                self.save(session_state, ttl).await.map_err(|e| match e {
                    SaveError::Serialization(e) => UpdateError::Serialization(e),
                    SaveError::Generic(e) => UpdateError::Generic(e),
                    SaveError::Redis(e) => UpdateError::Redis(e),
                })
            }
        }
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        let cache_key = (self.configuration.cache_keygen)(session_key.as_ref());
        self.client.del(&cache_key).await?;

        Ok(())
    }
}

// GitHub Actions do not support service containers (i.e. Redis, in our case) on
// non-Linux runners, therefore this test will fail in CI due to connection issues on those platform
#[cfg(test)]
#[cfg(target_os = "linux")]
mod test {
    use crate::storage::redis_rs::RedisSessionStore;
    use crate::storage::utils::generate_session_key;
    use crate::storage::{LoadError, SessionStore};
    use crate::test_helpers::acceptance_test_suite;
    use redis::AsyncCommands;
    use std::collections::HashMap;

    async fn redis_store() -> RedisSessionStore {
        RedisSessionStore::new("redis://127.0.0.1:6379")
            .await
            .unwrap()
    }

    #[actix_rt::test]
    async fn test_session_workflow() {
        let redis_store = redis_store().await;
        acceptance_test_suite(move || redis_store.clone(), true).await;
    }

    #[actix_rt::test]
    async fn loading_a_missing_session_returns_none() {
        let store = redis_store().await;
        let session_key = generate_session_key();
        assert!(store.load(&session_key).await.unwrap().is_none());
    }

    #[actix_rt::test]
    async fn loading_an_invalid_session_state_returns_deserialization_error() {
        let store = redis_store().await;
        let session_key = generate_session_key();
        store
            .client
            .clone()
            .set::<_, _, ()>(session_key.as_ref(), "random-thing-which-is-not-json")
            .await
            .unwrap();
        assert!(matches!(
            store.load(&session_key).await.unwrap_err(),
            LoadError::DeserializationError(_),
        ));
    }

    #[actix_rt::test]
    async fn updating_of_an_expired_state_is_handled_gracefully() {
        let store = redis_store().await;
        let session_key = generate_session_key();
        let initial_session_key = session_key.as_ref().to_owned();
        let updated_session_key = store
            .update(session_key, HashMap::new(), &time::Duration::seconds(1))
            .await
            .unwrap();
        assert_ne!(initial_session_key, updated_session_key.as_ref());
    }
}
