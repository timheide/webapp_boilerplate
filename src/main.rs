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

mod frontend;
mod user;
mod mailer;

#[database("mysql")]
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

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let mut rocket = rocket::ignite()
        .attach(DbConn::fairing())
        .attach(Template::fairing())
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
