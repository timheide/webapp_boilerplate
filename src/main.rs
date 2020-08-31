#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate log;
extern crate serde;
extern crate bcrypt;
extern crate config;

use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;
use rocket_contrib::json::Json;
use rocket_contrib::json::JsonValue;
use config::Config;
use rocket::{Outcome};
use rocket::request::{self, Request, FromRequest};
use dotenv::dotenv;
use rocket::http::Method;
use rocket_cors::{AllowedHeaders, AllowedOrigins, Cors};

mod frontend;
mod user;
mod mailer;

#[database("webapp_boilerplate")]
pub struct DbConn(diesel::MysqlConnection);

/// Custom Responder for Errors in the application
#[derive(Responder, Debug)]
pub enum CustomResponder {
    /// An unauthorized access
    #[response(status = 401)]
    Unauthorized(Json<JsonValue>),
    /// Something could not be found
    #[response(status = 404)]
    NotFound(Json<JsonValue>),
    /// An Error of some kind occured
    #[response(status = 500)]
    InternalServerError(Json<JsonValue>),
    /// The Request is missing some data
    #[response(status = 422)]
    UnprocessableEntity(Json<JsonValue>),
    /// Data conflict
    #[response(status = 409)]
    Conflict(Json<JsonValue>),
}

fn make_cors() -> Cors {
    let (allowed_origins, _failed_origins) = AllowedOrigins::some(&[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]);

    rocket_cors::Cors {
        allowed_origins,
        allowed_methods: vec![Method::Get, Method::Post, Method::Put, Method::Delete].into_iter().map(From::from).collect(),
        allowed_headers: AllowedHeaders::some(&["Content-Type","Authorization","Accept","Access-Control-Allow-Origin"]),
        allow_credentials: true,
        ..Default::default()
    }
}


fn main() {
    dotenv().ok();
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let mut rocket = rocket::ignite()
        .attach(DbConn::fairing())
        .attach(Template::fairing())
        .mount("/", rocket_cors::catch_all_options_routes())
        .manage(make_cors())
        .attach(make_cors())
        .mount("/assets", StaticFiles::from("templates/assets/"));
    rocket = user::mount(rocket);
    rocket = frontend::mount(rocket);
    rocket.launch();
}

#[derive(Debug)]
pub struct ApplicationConfig(pub Config);

impl<'a, 'r> FromRequest<'a, 'r> for ApplicationConfig {
    type Error = ();
    fn from_request(_request: &'a Request<'r>) -> request::Outcome<ApplicationConfig, ()> {
        let mut settings = config::Config::default();
        match settings.merge(config::File::with_name("Config")) {
            Ok(config) => {
                Outcome::Success(ApplicationConfig { 0: config.clone() })
            }
            Err(_) => { Outcome::Forward(()) }
        }
    }
}
