pub mod model;
pub mod schema;
pub mod auth;

use rocket::{self, http::{Cookie, Cookies}, Data};

use bcrypt::{DEFAULT_COST, hash, verify};
use rocket_contrib::json::{Json, JsonError};
use rocket_contrib::json::JsonValue;
use self::model::User;
use hmac::{Hmac, NewMac};
use jwt::SignWithKey;
use sha2::Sha256;
use crate::{DbConn, CustomResponder, ApplicationConfig, mailer};
use rocket_contrib::templates::tera::Context;
use std::collections::BTreeMap;
use image::ImageFormat;
use rocket_multipart_form_data::{MultipartFormData, MultipartFormDataOptions, MultipartFormDataField};
use rocket::http::ContentType;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use rand::Rng;
use rand::distributions::Alphanumeric;

pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    rocket
        .mount("/user", routes![create, activate, update, update_email, resend_activation, request_reset, reset_password, update_password, login, logout, update_photo])
        .mount("/user", routes![update_password_error, update_photo_error, update_email_error])
}

#[derive(Serialize, Deserialize)]
struct NewUser {
    pub email: String,
    pub password: String,
}

#[post("/", data = "<newuser>")]
fn create(newuser: Result<Json<NewUser>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match newuser {
        Ok(newuser) => {
            if let Some(_) = User::by_email(&newuser.email, &connection.0) {
                return Err(CustomResponder::Conflict(Json(json!({ "status": {"code": 409, "text": "A User with this email address already exists" }}))));
            }
            let prepared_user = User::from(newuser.0);
            let created_user = match User::create(prepared_user, &connection.0) {
                Ok(u) => u,
                Err(_) => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "User could not be created" }}))))
            };

            //Send email
            let mut context = Context::new();
            context.insert("registration_code", &created_user.registration_code);
            let template = "createUser".to_string();
            let _ = mailer::sendmail(&created_user, context, template, String::from("web_application - Registration successful"), None);

            Ok(Json(json!({"data":{"user": created_user},"status": {"code":200, "text": "User created"}})))
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}


#[derive(Serialize, Deserialize)]
struct UpdateUser {
    pub firstname: String,
}

#[put("/", data = "<updateduser>")]
fn update(user: &User, updateduser: Result<Json<UpdateUser>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match updateduser {
        Ok(updateduser) => {
            let update = User {
                firstname: updateduser.firstname.clone(),
                ..user.clone()
            };
            User::update(&update, &connection.0);
            Ok(Json(json!({"status": {"code":200, "text": "User updated"}})))
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EmailAdress {
    pub email: String,
}


#[derive(Serialize, Deserialize)]
struct UpdateEmail {
    pub email: String,
    pub password: String,
}

#[put("/email", data = "<update_email>")]
fn update_email(user: &User, update_email: Result<Json<UpdateEmail>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match update_email {
        Ok(update_email) => {
            match User::by_email(&update_email.email, &connection.0) {
                None => {}
                Some(_) => {
                    return Err(CustomResponder::Conflict(Json(json!({ "status": {"code": 409, "text":"A user with this email already exists. Could not update." }}))));
                }
            }
            match User::by_username_and_password(&user.email, &update_email.password, &connection.0) {
                None => {
                    Err(CustomResponder::Unauthorized(Json(json!({ "status": {"code": 401, "text":"User not found or wrong Password." }}))))
                }
                Some(mut user) => {
                    user.email = update_email.email.clone();
                    User::update(&user, &connection.0);
                    Ok(Json(json!({"status": {"code":200, "text": "User updated"}})))
                }
            }
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

#[put("/email", rank = 999)]
fn update_email_error() -> Result<Json<JsonValue>, CustomResponder> {
    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Not authorized"}}))))
}

#[post("/request_reset", data = "<post_data>")]
fn request_reset(post_data: Result<Json<EmailAdress>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match post_data {
        Ok(post_data) => {
            match User::by_email(&post_data.email, &connection.0) {
                Some(mut u) => {
                    let reset_code: String = rand::thread_rng().sample_iter(&Alphanumeric).take(8).collect();
                    u.reset_code = Some(reset_code);
                    User::update(&u, &connection.0);
                    //Send email
                    let mut context = Context::new();
                    context.insert("firstname", &u.firstname);
                    context.insert("reset_code", &u.reset_code);
                    let template = "resetPassword".to_string();
                    let _mail_result = mailer::sendmail(&u,context, template, String::from("web_application - Password reset"), None);
                    Ok(Json(json!({"status": {"code": 200,"text": "Password reset email sent"}})))
                }
                None => {
                    Err(CustomResponder::NotFound(Json(json!({ "status": {"code": 404, "text": "User not found" }}))))
                }
            }
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ResetForm {
    pub reset_code: String,
    pub password: String,
}

#[post("/reset_password", data = "<resetform>")]
fn reset_password(resetform: Result<Json<ResetForm>, JsonError>, mut cookies: Cookies, config: ApplicationConfig, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match resetform {
        Ok(resetform) => {
            if resetform.password.chars().count() < 8 {
                return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Password is too short. Minimum 8 characters!" }}))));
            }
            let mut user = match User::by_reset_code(resetform.reset_code.clone(), &connection.0) {
                Some(u) => u,
                None => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 400, "text": "A user with this reset code could not be found" }}))))
            };
            let secretkey = match config.0.get_str("secretkey") {
                Ok(x) => { x }
                Err(_) => { return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Secret key for JWT missing" }})))); }
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
                    Ok(Json(json!({ "data" : {"token":message}, "status": {"code":200, "text": "Password reset successful"}})))
                }
                Err(_) => {
                    Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Token could not be created" }}))))
                }
            }
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}


#[get("/activate/<registration_code>")]
fn activate(registration_code: String, connection: DbConn, config: ApplicationConfig, mut cookies: Cookies) -> Result<Json<JsonValue>, CustomResponder> {
    let mut user = match User::by_registration_code(registration_code.clone(), &connection.0) {
        Some(u) => u,
        None => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 400, "text": "A User with this registration code could not be found" }}))))
    };
    let secretkey = match config.0.get_str("secretkey") {
        Ok(x) => { x }
        Err(_) => { return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Secret key for JWT missing" }})))); }
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
            Ok(Json(json!({ "data" : {"token":message}, "status": {"code":200, "text": "User activated"}})))
        }
        Err(_) => {
            Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Token could not be created" }}))))
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ResendActivationForm {
    pub email: String,
}

#[post("/resend_activation", data = "<activation_email>")]
fn resend_activation(activation_email: Result<Json<ResendActivationForm>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match activation_email {
        Ok(activation_email) => {
            let user = match User::by_email(&activation_email.email, &connection.0) {
                Some(u) => u,
                None => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 400, "text": "User could not be found" }}))))
            };
            if user.registration_code.is_some() {
                //Send email
                let mut context = Context::new();
                context.insert("firstname", &user.firstname);
                context.insert("registration_code", &user.registration_code);
                let template = "createUser".to_string();
                let _mail_result = mailer::sendmail(&user, context, template, String::from("web_application - Registration successful"), None);

                Ok(Json(json!({"status": {"code": 200,"text": "Activation email resent"}})))
            } else {
                Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "User already activated" }}))))
            }
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}


#[derive(Serialize, Deserialize)]
struct UpdatePassword {
    pub oldpassword: String,
    pub newpassword: String,
    pub repeatpassword: String,
}

#[put("/password", data = "<updatepassword>")]
fn update_password(user: &User, updatepassword: Result<Json<UpdatePassword>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    match updatepassword {
        Ok(updatepassword) => {
            if &updatepassword.newpassword != &updatepassword.repeatpassword {
                return Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": "Passwords do not match"}}))));
            }
            let valid = verify(&updatepassword.oldpassword, &user.password.clone()).unwrap();
            if valid {
                let hashed_pw = hash(&updatepassword.newpassword, DEFAULT_COST).unwrap();
                let update = User {
                    password: hashed_pw,
                    ..user.clone()
                };
                User::update(&update, &connection.0);
                Ok(Json(json!({"status": {"code":200, "text": "Password changed"}})))
            } else {
                Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Invalid password"}}))))
            }
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

#[put("/password", rank = 999)]
fn update_password_error() -> Result<Json<JsonValue>, CustomResponder> {
    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Not authorized"}}))))
}

#[derive(Serialize, Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

#[post("/login", data = "<credentials>")]
fn login(mut cookies: Cookies, credentials: Result<Json<Credentials>, JsonError>, connection: DbConn, conf: ApplicationConfig) -> Result<Json<JsonValue>, CustomResponder> {
    match credentials {
        Ok(credentials) => {
            match User::by_email_and_password(&credentials.email, &credentials.password, &connection.0) {
                None => {
                    Err(CustomResponder::Unauthorized(Json(json!({ "status": {"code": 401, "text":"User not found or wrong Password." }}))))
                }
                Some(mut user) => {
                    let secretkey = match conf.0.get_str("secretkey") {
                        Ok(x) => { x }
                        Err(_) => { return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Secret key for JWT missing" }})))); }
                    };
                    let key: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_ref()).unwrap();
                    let mut claims = BTreeMap::new();
                    claims.insert("sub", user.id.unwrap().to_string());

                    match claims.sign_with_key(&key) {
                        Ok(message) => {
                            let cookie = Cookie::build("token", message.clone()).path("/").secure(false).finish();
                            cookies.add(cookie);
                            //Set reset code to null because we have a successful login
                            user.reset_code = None;
                            User::update(&user, &connection.0);
                            Ok(Json(json!({ "data" : {"token":message}, "status" : { "code": 200, "text":"Login successful"}})))
                        }
                        Err(_) => {
                            Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Token could not be created" }}))))
                        }
                    }
                }
            }
        }
        Err(jsonerror) => {
            let errorstring = match jsonerror {
                JsonError::Io(_) => { String::from("") }
                JsonError::Parse(_, e) => { e.to_string() }
            };
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

#[post("/logout")]
fn logout(mut cookies: Cookies) -> Result<Json<JsonValue>, CustomResponder> {
    cookies.remove(Cookie::build("token", "").path("/").secure(false).finish());
    Ok(Json(json!({ "status" : { "code": 200, "text": "Logout successful" }})))
}

#[post("/profile_image", data = "<data>")]
fn update_photo(user: &User, content_type: &ContentType, data: Data, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder>
{
    let mut mut_user = user.clone();
    let mut options = MultipartFormDataOptions::new();
    options.allowed_fields.push(MultipartFormDataField::file("file").content_type_by_string(Some(mime::IMAGE_STAR)).unwrap());
    let multipart_form_data = MultipartFormData::parse(content_type, data, options).unwrap();
    let photo = multipart_form_data.files.get("file");
    if let Some(files) = photo {
        for file in files {
            let file_name = &file.file_name;
            let path = &file.path;
            let fin = BufReader::new(File::open(path).unwrap());
            let pathbuf = PathBuf::from(file_name.clone().unwrap().as_str());
            let imageformat = match image::ImageFormat::from_path(pathbuf) {
                Ok(i) => i,
                Err(_) => return Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Unrecognized File type."}}))))
            };
            let image = image::load(fin, imageformat).unwrap();
            let mut image_as_bytes: Vec<u8> = Vec::new();
            let _ = image.thumbnail(100, 100).write_to(&mut image_as_bytes, ImageFormat::Jpeg);
            mut_user.image = Some(image_as_bytes.clone());
            let _good = User::update(&mut_user, &connection.0);
        }
        return Ok(Json(json!({"data": mut_user,"status": {"code": 200,"text": "Image uploaded successfully"}})));
    } else {
        return Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 500,"text": "Image not found. Please use multipart/form with exactly one 'file' parameter being an image"}}))));
    }
}

#[post("/profile_image", rank = 999)]
fn update_photo_error() -> Result<Json<JsonValue>, CustomResponder> {
    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Not authorized"}}))))
}