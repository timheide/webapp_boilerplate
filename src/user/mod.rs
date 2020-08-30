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
use std::time::SystemTime;

/// Mount routes for Rocket.
pub fn mount(rocket: rocket::Rocket) -> rocket::Rocket {
    rocket
        // Mount regular routes
        .mount("/user", routes![create, activate, update, update_email, resend_activation, request_reset, reset_password, update_password, login, logout, update_photo])
        // Mount routes for error handling (Unauthorized)
        .mount("/user", routes![update_password_error, update_photo_error, update_email_error])
}

/// POST data object for a new User
// Deserialize from Serde is derived to enable deserialization from JSON data to a NewUser type
#[derive(Deserialize)]
struct NewUser {
    // email address for the new user
    pub email: String,
    // password for the new user
    pub password: String,
}

/// Create a new User
///
/// # Arguments
///
/// * `newuser` - A JSON encoded NewUser
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/ \
///   --header 'content-type: application/json' \
///   --data '{
/// 	"email": "info@example.com",
/// 	"password": "example_password"
/// }'
/// ```
///
#[post("/", data = "<newuser>")]
fn create(newuser: Result<Json<NewUser>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted Form data is a correct NewUser object
    match newuser {
        // found a correct NewUser
        Ok(newuser) => {
            // Return with a Conflict error if a user with this email address already exists
            if let Some(_) = User::by_email(&newuser.email, &connection.0) {
                return Err(CustomResponder::Conflict(Json(json!({ "status": {"code": 409, "text": "A User with this email address already exists" }}))));
            }
            // Create a new User from a NewUser object using a trait
            let prepared_user = User::from(newuser.0);
            // Save the prepared new user object in the Database
            let created_user = match User::create(prepared_user, &connection.0) {
                // The user was created successfully
                Ok(u) => u,
                // A database error occured
                Err(_) => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "User could not be created" }}))))
            };
            // The user has been created so we now send the activation email to the user
            // Create an empty context to add data to. Everything that is appended will be available in the HTML email template
            let mut context = Context::new();
            // Add the registration code to the tera template
            context.insert("registration_code", &created_user.registration_code);
            // Send the activation email to the created user
            let _ = mailer::sendmail(&created_user, context, String::from("createUser"), String::from("web_application - Registration successful"), None);
            // Return a JSON Object consisting of the newly created user and a status.
            Ok(Json(json!({"data":{"user": created_user},"status": {"code":200, "text": "User created"}})))
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

/// POST data object for an updated User
// Deserialize from Serde is derived to enable deserialization from JSON data to a UpdateUser type
#[derive(Deserialize)]
struct UpdateUser {
    // First name
    pub firstname: String,
}

/// Updates an existing user
///
/// # Arguments
///
/// * `user` -  The currently logged in User
/// * `updateuser` - A JSON encoded UpdateUser
/// * `connection` - Database connection
///
/// # Example
///
/// ## cURL with Cookie
/// ```text
/// curl --request PUT \
///   --url http://localhost:8000/user \
///   --header 'content-type: application/json' \
///   --cookie token=eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A \
///   --data '{
/// 	"firstname": "Daniel"
/// }'
/// ```
///
/// ## cURL with Bearer Token auth header
/// ```text
/// curl --request PUT \
///   --url http://localhost:8000/user \
///   --header 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A' \
///   --header 'content-type: application/json' \
///   --data '{
/// 	"firstname": "Daniel"
/// }'
/// ```
///
#[put("/", data = "<updateduser>")]
fn update(user: &User, updateduser: Result<Json<UpdateUser>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted Form data is a correct UpdateUser object
    match updateduser {
        // found a correct UpdateUser
        Ok(updateduser) => {
            // Create a new user object that is derived from the logged in user and has the changed values from the UpdateUser POST object
            let update = User {
                // set firstname
                firstname: updateduser.firstname.clone(),
                // Update edit date
                edit_date: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                // all other attributes are inherited from the logged in user
                ..user.clone()
            };
            // Update the database user
            User::update(&update, &connection.0);
            // Return a successful result
            Ok(Json(json!({"status": {"code":200, "text": "User updated"}})))
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}


/// POST data object for updating a users email address
// Deserialize from Serde is derived to enable deserialization from JSON data to the specific data type
#[derive(Deserialize)]
struct UpdateEmail {
    pub email: String,
    pub password: String,
}

/// Update an email address
///
/// # Arguments
///
/// * `update_email` - A JSON embedded UpdateEmail data type
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request PUT \
///   --url http://localhost:8000/user/email \
///   --header 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A' \
///   --header 'content-type: application/json' \
///   --data '{
/// 	"email": "updated@example.com",
/// 	"password": "example_password"
/// }'
/// ```
///
#[put("/email", data = "<update_email>")]
fn update_email(user: &User, update_email: Result<Json<UpdateEmail>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted Form data is a correct UpdateEmail object
    match update_email {
        Ok(update_email) => {
            // check if a user with the submitted email address already exists.
            match User::by_email(&update_email.email, &connection.0) {
                None => {}
                Some(_) => {
                    // a user with this email address already exists. exit.
                    return Err(CustomResponder::Conflict(Json(json!({ "status": {"code": 409, "text":"A user with this email already exists. Could not update." }}))));
                }
            }
            // for security measures it is checked whether
            match User::by_username_and_password(&user.email, &update_email.password, &connection.0) {
                None => {
                    // the provided password is incorrect
                    Err(CustomResponder::Unauthorized(Json(json!({ "status": {"code": 401, "text":"User not found or wrong Password." }}))))
                }
                Some(mut user) => {
                    // set the new email address
                    user.email = update_email.email.clone();
                    // update user
                    User::update(&user, &connection.0);
                    // return a successful result
                    Ok(Json(json!({"status": {"code":200, "text": "User email address updated"}})))
                }
            }
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

/// Error route for updating an email address. Is executed when no user is provided
#[put("/email", rank = 999)]
fn update_email_error() -> Result<Json<JsonValue>, CustomResponder> {
    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Not authorized"}}))))
}

/// POST data object for updating a users email address for password reset
// Deserialize from Serde is derived to enable deserialization from JSON data to the specific data type
#[derive(Deserialize)]
struct EmailAddress {
    /// the email address for that the account reset is made
    pub email: String,
}

/// Request a password reset email
///
/// # Arguments
///
/// * `post_data` - A JSON embedded EmailAddress data type
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/request_reset \
///   --header 'content-type: application/json' \
///   --data '{
/// 	"email": "info@example.com"
/// }'
/// ```
///
#[post("/request_reset", data = "<post_data>")]
fn request_reset(post_data: Result<Json<EmailAddress>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted Form data is a correct EmailAddress object
    match post_data {
        // the submitted data is in correct format
        Ok(post_data) => {
            // find the user with the requested email address in the database
            match User::by_email(&post_data.email, &connection.0) {
                // A user is found. Provide as mutable because we want to modify it later
                Some(mut u) => {
                    // generate a random 8 digit alphanumeric reset code for completing the password reset later
                    let reset_code: String = rand::thread_rng().sample_iter(&Alphanumeric).take(8).collect();
                    // set the reset code
                    u.reset_code = Some(reset_code);
                    // update the user
                    User::update(&u, &connection.0);
                    // create a mutable Context for the email template
                    let mut context = Context::new();
                    // insert the reset code into the context for displaying in the email template
                    context.insert("reset_code", &u.reset_code);
                    // the name of the tera template to load
                    let template = String::from("resetPassword");
                    // Send the password reset email
                    let _ = mailer::sendmail(&u, context, template, String::from("web_application - Password reset"), None);
                    // return a successful result
                    Ok(Json(json!({"status": {"code": 200,"text": "Password reset email sent"}})))
                }
                // No user with this email address was found
                None => {
                    // Return an error that no user could be found
                    Err(CustomResponder::NotFound(Json(json!({ "status": {"code": 404, "text": "User not found" }}))))
                }
            }
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

/// POST data object for completing a password reset
// Deserialize from Serde is derived to enable deserialization from JSON data to the specific data type
#[derive(Serialize, Deserialize)]
struct ResetForm {
    /// The reset code
    pub reset_code: String,
    // The password to set for the user
    pub password: String,
}


/// Fulfill a password reset
///
/// # Arguments
///
/// * `resetform` - A JSON embedded ResetForm data type
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/reset_password \
///   --header 'content-type: application/json' \
///   --data '{
/// 	"reset_code": "12345678",
/// 	"password": "example_password"
/// }'
/// ```
///
#[post("/reset_password", data = "<resetform>")]
fn reset_password(resetform: Result<Json<ResetForm>, JsonError>, mut cookies: Cookies, config: ApplicationConfig, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted data is a correct EmailAddress object
    match resetform {
        // Deserialization returned a correct formatted
        Ok(resetform) => {
            // Check if the submitted new password fulfills the required complexity (min 8 chars)
            if resetform.password.chars().count() < 8 {
                // required complexity is not met. exit
                return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Password is too short. Minimum 8 characters!" }}))));
            }
            // find a user by the submitted reset code.
            let mut user = match User::by_reset_code(resetform.reset_code.clone(), &connection.0) {
                // a user is found. set to "user"
                Some(u) => u,
                // no user is found. exit.
                None => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 400, "text": "A user with this reset code could not be found" }}))))
            };
            // find the secret key for password encryption in the configuration file
            let secretkey = match config.0.get_str("secretkey") {
                Ok(x) => { x }
                Err(_) => { return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Secret key for JWT missing" }})))); }
            };
            // create a new varkey from the secretkey for token
            let key: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_ref()).unwrap();
            // create the claims object for the JWT
            let mut claims = BTreeMap::new();
            // insert the userid into the claims as "sub" as specified in the JWT standard
            claims.insert("sub", user.id.unwrap().to_string());
            // sign the token with the varkey
            match claims.sign_with_key(&key) {
                // signing was succesful
                Ok(message) => {
                    // create a cookie with the newly generated token
                    let cookie = Cookie::build("token", message.clone()).path("/").secure(false).finish();
                    // add the cookie to the existing tokens
                    cookies.add(cookie);
                    // update the user with the newly set password
                    user.password = hash(&resetform.password, DEFAULT_COST).unwrap();
                    // Set reset code to null because we have a successful reset
                    user.reset_code = None;
                    // since a user reset was successful, it's also fine to set regestration code to null
                    user.registration_code = None;
                    // Update the user
                    User::update(&user, &connection.0);
                    // return the freshly generated token
                    Ok(Json(json!({ "data" : {"token":message}, "status": {"code":200, "text": "Password reset successful"}})))
                }
                Err(_) => {
                    // the token could not be signed
                    Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Token could not be created" }}))))
                }
            }
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

/// Activate a user with a given registration_code
///
/// # Arguments
///
/// * `registration_code` - The registration code
/// * `connection` - Database connection
/// * `config` - Application configuration
/// * `cookies` - Cookies
///
/// # Example
///
/// ```text
/// curl --request GET \
///   --url http://localhost:8000/user/activate/123456
/// ```
///
#[get("/activate/<registration_code>")]
fn activate(registration_code: String, connection: DbConn, config: ApplicationConfig, mut cookies: Cookies) -> Result<Json<JsonValue>, CustomResponder> {
    // find the user with the given registration code
    let mut user = match User::by_registration_code(registration_code.clone(), &connection.0) {
        // user was found
        Some(u) => u,
        // no user could be found. exit
        None => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 400, "text": "A User with this registration code could not be found" }}))))
    };
    // find the secret key for password encryption in the configuration file
    let secretkey = match config.0.get_str("secretkey") {
        Ok(x) => { x }
        Err(_) => { return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Secret key for JWT missing" }})))); }
    };
    // create a new varkey from the secretkey for token
    let key: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_ref()).unwrap();
    // create the claims object for the JWT
    let mut claims = BTreeMap::new();
    // insert the userid into the claims as "sub" as specified in the JWT standard
    claims.insert("sub", user.id.unwrap().to_string());
    // sign the token with the varkey
    match claims.sign_with_key(&key) {
        // signing was succesful
        Ok(message) => {
            // create a cookie with the newly generated token
            let cookie = Cookie::build("token", message.clone()).path("/").secure(false).finish();
            // add the cookie to the existing tokens
            cookies.add(cookie);
            //Set reset code to null because we have a successful login
            user.registration_code = None;
            // Update the user
            User::update(&user, &connection.0);
            // return the freshly generated token
            Ok(Json(json!({ "data" : {"token":message}, "status": {"code":200, "text": "User activated"}})))
        }
        Err(_) => {
            // the token could not be signed
            Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Token could not be created" }}))))
        }
    }
}

/// POST data object for resending an activation request
// Deserialize from Serde is derived to enable deserialization from JSON data to the specific data type
#[derive(Deserialize)]
struct ResendActivation {
    pub email: String,
}

/// Resend an already created activation email again
///
/// # Arguments
///
/// * `resend_activation` - A JSON embedded ResendActivation data type
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/request_reset \
///   --header 'content-type: application/json' \
///   --data '{
/// 	"email": "info@example.com"
/// }'
/// ```
///
#[post("/resend_activation", data = "<resend_activation>")]
fn resend_activation(resend_activation: Result<Json<ResendActivation>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted data is a correct ResendActivation object
    match resend_activation {
        Ok(activation_email) => {
            // find the user with the requested email address in the database
            let user = match User::by_email(&activation_email.email, &connection.0) {
                // A user is found. Provide as mutable because we want to modify it later
                Some(u) => u,
                None => return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 400, "text": "User could not be found" }}))))
            };
            // The user has an active registration code.
            if user.registration_code.is_some() {
                // create a mutable Context for the email template
                let mut context = Context::new();
                // insert the activation code into the context for displaying in the email template
                context.insert("registration_code", &user.registration_code);
                // the name of the tera template to load
                let template = "createUser".to_string();
                // Send the password reset email
                let _ = mailer::sendmail(&user, context, template, String::from("web_application - Registration successful"), None);
                // return a successful result
                Ok(Json(json!({"status": {"code": 200,"text": "Activation email resent"}})))
            } else {
                // No active registration code was found on the requested user
                Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "User already activated" }}))))
            }
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}


/// POST data object for updating a users password
// Deserialize from Serde is derived to enable deserialization from JSON data to the specific data type
#[derive(Deserialize)]
struct UpdatePassword {
    pub oldpassword: String,
    pub newpassword: String,
    pub repeatpassword: String,
}

/// Update the user's password
///
/// # Arguments
///
/// * `updatepassword` - A JSON embedded UpdatePassword data type
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request PUT \
///   --url http://localhost:8000/user/password \
///   --header 'content-type: application/json' \
///   --header 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A' \
///   --data '{
/// 	"oldpassword": "testtest",
/// 	"newpassword": "test123",
/// 	"repeatpassword": "test123"
/// }'
/// ```
///
#[put("/password", data = "<updatepassword>")]
fn update_password(user: &User, updatepassword: Result<Json<UpdatePassword>, JsonError>, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted data is a correct UpdatePassword object
    match updatepassword {
        Ok(updatepassword) => {
            // Check if the submitted new password fulfills the required complexity (min 8 chars)
            if updatepassword.newpassword.chars().count() < 8 {
                // required complexity is not met. exit
                return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Password is too short. Minimum 8 characters!" }}))));
            }
            // Check if the submitted newpassword equals the repeatpassword
            if &updatepassword.newpassword != &updatepassword.repeatpassword {
                // submitted passwords do not match
                return Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": "Passwords do not match"}}))));
            }
            // check if the submitted old password matches the logged in users password
            match verify(&updatepassword.oldpassword, &user.password.clone()).unwrap() {
                // old password is correct
                true => {
                    // create a new password hash
                    let hashed_pw = hash(&updatepassword.newpassword, DEFAULT_COST).unwrap();
                    // create an updated user and update the saved password with the newly hashed one. Derive all other fields from the current user
                    let update = User {
                        password: hashed_pw,
                        ..user.clone()
                    };
                    // update the user in the database
                    User::update(&update, &connection.0);
                    // return a successful result
                    Ok(Json(json!({"status": {"code":200, "text": "Password changed"}})))
                }
                false => {
                    // prodided password doesn't match
                    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Invalid password"}}))))
                }
            }
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

/// Error route for updating a user's password. Is executed when no user is provided
#[put("/password", rank = 999)]
fn update_password_error() -> Result<Json<JsonValue>, CustomResponder> {
    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Not authorized"}}))))
}

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

/// Login
///
/// # Arguments
///
/// * `credentials` - A JSON embedded UpdatePassword data type
/// * `connection` - Database connection
/// * `config` - Application configuration
/// * `cookies` - Cookies
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/login \
///   --header 'content-type: application/json' \
///   --header 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A' \
///   --data '{
/// 	"email": "info@example.com",
/// 	"password": "example_password"
/// }'
/// ```
///
#[post("/login", data = "<credentials>")]
fn login(credentials: Result<Json<Credentials>, JsonError>, connection: DbConn, config: ApplicationConfig, mut cookies: Cookies) -> Result<Json<JsonValue>, CustomResponder> {
    // Check if the submitted data is a correct Credentials object
    match credentials {
        Ok(credentials) => {
            // Find the user by the provided email and password
            match User::by_email_and_password(&credentials.email, &credentials.password, &connection.0) {
                // no User was found. Exit.
                None => {
                    Err(CustomResponder::Unauthorized(Json(json!({ "status": {"code": 401, "text":"User not found or wrong Password." }}))))
                }
                // A user is found. proceed
                Some(mut user) => {
                    // find the secret key for password encryption in the configuration file
                    let secretkey = match config.0.get_str("secretkey") {
                        Ok(x) => { x }
                        Err(_) => { return Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Secret key for JWT missing" }})))); }
                    };
                    // create a new varkey from the secretkey for token
                    let key: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_ref()).unwrap();
                    // create the claims object for the JWT
                    let mut claims = BTreeMap::new();
                    // insert the userid into the claims as "sub" as specified in the JWT standard
                    claims.insert("sub", user.id.unwrap().to_string());
                    // sign the token with the varkey
                    match claims.sign_with_key(&key) {
                        // signing was succesful
                        Ok(message) => {
                            // create a cookie with the newly generated token
                            let cookie = Cookie::build("token", message.clone()).path("/").secure(false).finish();
                            // add the cookie to the existing tokens
                            cookies.add(cookie);
                            //Set reset code to null because we have a successful login
                            user.reset_code = None;
                            // Update user in the database
                            User::update(&user, &connection.0);
                            // return the token
                            Ok(Json(json!({ "data" : {"token":message}, "status" : { "code": 200, "text":"Login successful"}})))
                        }
                        Err(_) => {
                            // the token could not be signed
                            Err(CustomResponder::InternalServerError(Json(json!({ "status": {"code": 500, "text": "Token could not be created" }}))))
                        }
                    }
                }
            }
        }
        // The submitted Post data could not be deserialized. We now handle that error
        Err(jsonerror) => {
            // Differentiate between different error types
            let errorstring = match jsonerror {
                // Result was an IO error. Return an empty String
                JsonError::Io(_) => { String::from("") }
                // Result was a parse error. Return the error message as String
                JsonError::Parse(_, e) => { e.to_string() }
            };
            // Return a 422 Error code with a detailed description of the format error.
            Err(CustomResponder::UnprocessableEntity(Json(json!({"status": {"code": 422,"text": errorstring}}))))
        }
    }
}

/// Logout.
/// Only removes the cookie
///
/// # Arguments
///
/// * `cookies` - Cookies
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/login \
///   --header 'content-type: application/json' \
///   --header 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A' \
///   --data '{
/// 	"email": "info@example.com",
/// 	"password": "example_password"
/// }'
/// ```
///
#[post("/logout")]
fn logout(mut cookies: Cookies) -> Result<Json<JsonValue>, CustomResponder> {
    // remove the token cookie
    cookies.remove(Cookie::build("token", "").path("/").secure(false).finish());
    // return a successful
    Ok(Json(json!({ "status" : { "code": 200, "text": "Logout successful" }})))
}

/// Logout.
/// Only removes the cookie
///
/// # Arguments
///
/// * `user` - Logged in user
/// * `content_type` - Content Type of the request
/// * `data` - Raw Request Data
/// * `connection` - Database connection
///
/// # Example
///
/// ```text
/// curl --request POST \
///   --url http://localhost:8000/user/login \
///   --header 'content-type: application/json' \
///   --header 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ.................XnFVfzxstncqTlDkHisaiyj26A' \
///   --data '{
/// 	"email": "info@example.com",
/// 	"password": "example_password"
/// }'
/// ```
///
#[post("/profile_image", data = "<data>")]
fn update_photo(user: &User, content_type: &ContentType, data: Data, connection: DbConn) -> Result<Json<JsonValue>, CustomResponder>
{
    // get the currently logged in user as a mutable clone
    let mut mut_user = user.clone();
    // crate a new template for the multipart form into which the request data is parsed into
    let mut options = MultipartFormDataOptions::new();
    // set the "file" field as a possible multipart field and allow Image mime types
    options.allowed_fields.push(MultipartFormDataField::file("file").content_type_by_string(Some(mime::IMAGE_STAR)).unwrap());
    // parse the request data into the multipart form data
    let multipart_form_data = MultipartFormData::parse(content_type, data, options).unwrap();
    // get the files field from the multipart form.
    let photo = multipart_form_data.files.get("file");
    // the photo field contains a vector with files
    if let Some(files) = photo {
        // iterate over the vector of file fields (could only be one)
        for file in files {
            // get the file name
            let file_name = &file.file_name;
            // get the file path
            let path = &file.path;
            // get a buffered reader for the file
            let fin = BufReader::new(File::open(path).unwrap());
            // get a path buffer for the filename on the file
            let pathbuf = PathBuf::from(file_name.clone().unwrap().as_str());
            // get the imageformat from the delivered file
            let imageformat = match image::ImageFormat::from_path(pathbuf) {
                Ok(i) => i,
                Err(_) => return Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Unrecognized File type."}}))))
            };
            // load the image
            let image = image::load(fin, imageformat).unwrap();
            // prepare a bytearray for database storage
            let mut image_as_bytes: Vec<u8> = Vec::new();
            // create a new thumbnail and write it to the bytevector
            let _ = image.thumbnail(100, 100).write_to(&mut image_as_bytes, ImageFormat::Jpeg);
            // set the image bytevector as the new user image
            mut_user.image = Some(image_as_bytes.clone());
            // update the user in the database
            let _ = User::update(&mut_user, &connection.0);
        }
        // return a successful result
        return Ok(Json(json!({"data": mut_user,"status": {"code": 200,"text": "Image uploaded successfully"}})));
    } else {
        return Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 500,"text": "Image not found. Please use multipart/form with exactly one 'file' parameter being an image"}}))));
    }
}

/// Error route for updating a user's image. Is executed when no user is provided
#[post("/profile_image", rank = 999)]
fn update_photo_error() -> Result<Json<JsonValue>, CustomResponder> {
    Err(CustomResponder::Unauthorized(Json(json!({"status": {"code": 401,"text": "Not authorized"}}))))
}