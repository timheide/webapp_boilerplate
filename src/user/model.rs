use diesel;
use diesel::prelude::*;
use diesel::mysql::MysqlConnection;
use crate::user::schema::users;
use bcrypt::{verify};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use crate::user::NewUser;
use rand::Rng;
use rand::distributions::Alphanumeric;
use std::time::SystemTime;

#[table_name = "users"]
#[changeset_options(treat_none_as_null = "true")]
#[derive(AsChangeset, Deserialize, Queryable, Insertable, QueryableByName, Debug, PartialEq, Clone, Default)]
pub struct User {
    pub id: Option<i32>,
    pub firstname: String,
    pub email: String,
    pub password: String,
    pub registration_code: Option<String>,
    pub reset_code: Option<String>,
    pub image: Option<Vec<u8>>,
    pub create_date: u64
}

impl Serialize for User {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        // Prepare user for serialization
        // return is_activated == true if regcode is empty
        let is_confirmed = match &self.registration_code {
            Some(_) => false,
            None => true
        };

        let userimage = match &self.image {
            Some(image) => {
                Some(String::from("data:image/jpeg;base64,") + &base64::encode(&image))
            }
            None => None
        };

        // 13 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("User", 15)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("email", &self.email)?;
        state.serialize_field("firstname", &self.firstname)?;
        state.serialize_field("is_confirmed", &is_confirmed)?;
        state.serialize_field("image", &userimage)?;
        state.end()
    }
}

impl From<NewUser> for User {
    fn from(newuser: NewUser) -> Self {
        // create an random alphanumeric code
        let registration_code: String = rand::thread_rng().sample_iter(&Alphanumeric).take(8).collect();
        User {
            email: newuser.email,
            password: bcrypt::hash(&newuser.password, bcrypt::DEFAULT_COST).unwrap(),
            registration_code: Some(registration_code),
            create_date: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            ..Default::default()
        }
    }
}


impl User {
    /// Find user by registration code
    pub fn by_registration_code(registration_code: String, connection: &MysqlConnection) -> Option<User> {
        users::table.filter(users::registration_code.eq(registration_code)).order(users::id).first::<User>(connection).ok()
    }
    /// Find user by registration code
    pub fn by_reset_code(reset_code: String, connection: &MysqlConnection) -> Option<User> {
        users::table.filter(users::reset_code.eq(reset_code)).order(users::id).first::<User>(connection).ok()
    }

    /// Find a user by Username and Password
    pub fn by_username_and_password(email: &str, password: &str, connection: &MysqlConnection) -> Option<User> {
        match users::table.filter(users::email.eq(email)).order(users::id).first::<User>(connection) {
            Ok(user) => {
                match verify(password, &user.password.clone()) {
                    Ok(x) if x == true => Some(user),
                    _ => None
                }
            }
            Err(_) => None
        }
    }

    /// Find user by email
    pub fn by_email(email: &str, connection: &MysqlConnection) -> Option<User> {
        users::table.filter(users::email.eq(email)).order(users::id).first::<User>(connection).ok()
    }

    pub fn create(user: User, connection: &MysqlConnection) -> QueryResult<User> {
        diesel::insert_into(users::table).values(&user).execute(connection)?;
        users::table.order(users::id.desc()).first(connection)
    }

    pub fn read(id: i32, connection: &MysqlConnection) -> QueryResult<User> {
        users::table.find(id).first::<User>(connection)
    }

    /// Find a user by Username and Password
    pub fn by_email_and_password(email: &str, password: &str, connection: &MysqlConnection) -> Option<User> {
        match users::table.filter(users::email.eq(email)).order(users::id).first::<User>(connection) {
            Ok(user) => {
                match verify(password, &user.password) {
                    Ok(x) if x == true => Some(user),
                    _ => None
                }
            }
            Err(_) => None
        }
    }

    pub fn update(user: &User, connection: &MysqlConnection) -> bool {
        diesel::update(users::table.find(user.id.unwrap())).set(user).execute(connection).is_ok()
    }

    pub fn delete(id: i32, connection: &MysqlConnection) -> bool {
        diesel::delete(users::table.find(id)).execute(connection).is_ok()
    }
}