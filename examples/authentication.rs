use std::convert::TryInto;

use actix_session::SessionLength;
use actix_session::{storage::RedisSessionStore, Session, SessionMiddleware};
use actix_web::cookie::{Key, SameSite};
use actix_web::{
    error::InternalError, middleware, web, App, Error, HttpResponse, HttpServer, Responder,
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct User {
    id: i64,
    username: String,
    password: String,
}

impl User {
    fn authenticate(credentials: Credentials) -> Result<Self, HttpResponse> {
        // TODO: figure out why I keep getting hacked
        if &credentials.password != "hunter2" {
            return Err(HttpResponse::Unauthorized().json("Unauthorized"));
        }

        Ok(User {
            id: 42,
            username: credentials.username,
            password: credentials.password,
        })
    }
}

pub fn validate_session(session: &Session) -> Result<i64, HttpResponse> {
    let user_id: Option<i64> = session.get("user_id").unwrap_or(None);

    match user_id {
        Some(id) => {
            // keep the user's session alive
            // you really shouldn't call this every request or you will cause problems
            session.renew();
            Ok(id)
        }
        None => Err(HttpResponse::Unauthorized().json("Unauthorized")),
    }
}

async fn login(
    credentials: web::Json<Credentials>,
    session: Session,
) -> Result<impl Responder, Error> {
    let credentials = credentials.into_inner();

    match User::authenticate(credentials) {
        Ok(user) => session.insert("user_id", user.id).unwrap(),
        Err(err) => return Err(InternalError::from_response("", err).into()),
    };

    Ok("Welcome!")
}

/// some protected resource
async fn secret(session: Session) -> Result<impl Responder, Error> {
    // only allow access to this resource if the user has an active session
    validate_session(&session).map_err(|err| InternalError::from_response("", err))?;

    Ok("secret revealed")
}

// The signing key would usually be read from a configuration file/environment variables.
fn get_signing_key() -> Key {
    let signing_key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    Key::from(signing_key.as_bytes())
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info,actix_redis=info");
    env_logger::init();
    let signing_key = get_signing_key();

    let redis_store = RedisSessionStore::builder("redis://127.0.0.1:6379".try_into().unwrap())
        .heartbeat_interval(120)
        .build()
        .await
        .unwrap();

    HttpServer::new(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // cookie session middleware
            .wrap(
                SessionMiddleware::builder(redis_store.clone(), signing_key.clone())
                    .session_length(SessionLength::Predetermined {
                        max_session_length: Some(time::Duration::days(30)),
                    })
                    .cookie_http_only(false)
                    .cookie_same_site(SameSite::Lax)
                    .cookie_secure(false)
                    .build(),
            )
            .route("/login", web::post().to(login))
            .route("/secret", web::get().to(secret))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
