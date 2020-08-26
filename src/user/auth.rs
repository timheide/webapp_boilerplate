//! Auth module
use rocket::Outcome;
use rocket::request::{self, Request, FromRequest};

pub extern crate crypto;
pub extern crate jwt;
pub extern crate rustc_serialize;

use sha2::Sha256;
use crate::user::model::User;
use crate::DbConn;
use hmac::{Hmac, NewMac};
use std::collections::BTreeMap;
use self::jwt::{VerifyWithKey, Error};

/// Read the secret key from configuration file and verify against delivered token
pub fn read_token(token: &str) -> Result<String, String> {
    let mut settings = config::Config::default();
    let merged = match settings.merge(config::File::with_name("Config")) {
        Ok(config) => { config }
        Err(_) => { return Err("Configuration file not found".to_string()); }
    };
    let secretkey = match merged.get_str("secretkey") {
        Ok(x) => { x }
        Err(_) => { return Err("Could not find secret key".to_string()); }
    };

    let newkey: Hmac<Sha256> = Hmac::new_varkey(secretkey.as_ref()).unwrap();
    let claims: Result<BTreeMap<String, String>, Error> = VerifyWithKey::verify_with_key(token, &newkey);
    match claims {
        Ok(t) => {
            if t.contains_key("sub") {
                Ok(t["sub"].clone())
            } else {
                Err("Token not valid".to_string())
            }
        }
        Err(_) => {
            Err("Token not valid".to_string())
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for &'a User {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<&'a User, ()> {
        let mut token: Option<String> = None;
        match request.cookies().get("token") {
            Some(c) => {
                token = Some(c.value().to_string());
            }
            None => ()
        };
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        if keys.len() == 1 {
            let bearer: Vec<&str> = keys[0].split_whitespace().collect();
            if bearer.len() == 2 {
                token = Some(bearer.last().unwrap().to_string());
            }
        }

        match token {
            Some(t) => {
                let userid = match read_token(&t) {
                    Ok(claim) => claim,
                    Err(_) => return Outcome::Forward(())
                };
                let user_result = request.local_cache(|| {
                    let db = request.guard::<DbConn>().succeeded().unwrap();
                    User::read(userid.parse::<i32>().unwrap(), &db.0)
                });
                match user_result {
                    Ok(u) => { Outcome::Success(u) }
                    Err(_) => { Outcome::Forward(()) }
                }
            }
            None => Outcome::Forward(())
        }
    }
}
