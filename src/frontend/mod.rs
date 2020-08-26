use rocket_contrib::templates::Template;
use std::collections::{HashMap, BTreeMap};
use crate::user::model::User;
use hmac::{Hmac, NewMac};
use jwt::SignWithKey;
use sha2::Sha256;
use crate::{DbConn, ApplicationConfig};
use rocket::http::{Cookie, Cookies};
use rocket_contrib::templates::tera::Context;
use rocket::request::Form;
use bcrypt::{hash, DEFAULT_COST};

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    rocket.mount("/ui", routes![activate, request_reset, reset_password])
        .mount("/ui", routes![activate_error])
}

#[get("/activate/<registration_code>")]
fn activate(registration_code: String, connection: DbConn, config: ApplicationConfig, mut cookies: Cookies) -> Template {
    let mut user = match User::by_registration_code(registration_code, &connection.0) {
        Some(u) => u,
        None => {
            let mut context = Context::new();
            context.insert("error_message", "Could not find a user with this registration code");
            return Template::render("error/specific_error", &context);
        }
    };
    let secretkey = match config.0.get_str("secretkey") {
        Ok(x) => { x }
        Err(_) => {
            error!("Could not find secret key for user token enryption");
            return Template::render("error/generic_error", &Context::new());
        }
    };
    let key: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_bytes()).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("sub", user.id.unwrap().to_string());

    match claims.sign_with_key(&key) {
        Ok(message) => {
            let cookie = Cookie::build("token", message.clone()).path("/").secure(false).finish();
            cookies.add(cookie);
            //Set reset code to null because we have a successful login
            user.registration_code = None;
            User::update(&user, &connection.0);
            let mut context = Context::new();
            context.insert("token", &message);
            Template::render("activate", &context)
        }
        Err(_) => {
            error!("Token could not be created");
            return Template::render("error/generic_error", &Context::new());
        }
    }
}

#[get("/activate/<_registration_code>", rank = 2)]
pub fn activate_error(_registration_code: String) -> Template {
    let context: HashMap<String, String> = HashMap::new();
    Template::render("error", &context)
}

#[get("/request_reset/<reset_code>")]
fn request_reset(reset_code: String, connection: DbConn) -> Template {
    let user = match User::by_reset_code(reset_code, &connection.0) {
        Some(u) => u,
        None => {
            let mut context = Context::new();
            context.insert("error_message", "Could not find a user with this reset code");
            return Template::render("error/specific_error", &context);
        }
    };
    let mut context = Context::new();
    context.insert("reset_code", &user.reset_code.unwrap());
    Template::render("requestResetPassword", &context)
}

#[derive(FromForm)]
struct ResetForm {
    pub reset_code: String,
    pub password: String,
}

#[post("/reset_password", data = "<resetform>")]
fn reset_password(resetform: Form<ResetForm>, mut cookies: Cookies, config: ApplicationConfig, connection: DbConn) -> Template {
    if resetform.password.chars().count() < 8 {
        let mut context = Context::new();
        context.insert("error_message", "Password is too short. Minimum 8 characters!");
        return Template::render("error/specific_error", &context);
    }
    let mut user = match User::by_reset_code(resetform.reset_code.clone(), &connection.0) {
        Some(u) => u,
        None => {
            let mut context = Context::new();
            context.insert("error_message", "Could not find a user with this reset code");
            return Template::render("error/specific_error", &context);
        }
    };
    let secretkey = match config.0.get_str("secretkey") {
        Ok(x) => { x }
        Err(_) => {
            error!("Could not find secret key for user token enryption");
            return Template::render("error/generic_error", &Context::new());
        }
    };
    let key: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_ref()).unwrap();
    let mut claims = BTreeMap::new();
    claims.insert("sub", user.id.unwrap().to_string());

    match claims.sign_with_key(&key) {
        Ok(message) => {
            let cookie = Cookie::build("token", message.clone()).path("/").secure(false).finish();
            cookies.add(cookie);
            user.password = hash(&resetform.password, DEFAULT_COST).unwrap();
            //Set reset code to null because we have a successful reset
            user.reset_code = None;
            // since a user reset was successful, it's also fine to set regestration code to null
            user.registration_code = None;
            User::update(&user, &connection.0);

            let mut context = Context::new();
            context.insert("token", &message);
            Template::render("resetPassword", &context)
        }
        Err(_) => {
            error!("Token could not be created");
            return Template::render("error/generic_error", &Context::new());
        }
    }
}