//! Module for Mailings
extern crate lettre;
extern crate lettre_email;
extern crate native_tls;

use std::borrow::Borrow;
use std::env;
use std::string::ToString;

use lettre::{
    ClientSecurity, ClientTlsParameters, SmtpClient, Transport,
};
use lettre::smtp::authentication::{Credentials, Mechanism};
use lettre::smtp::ConnectionReuseParameters;
use mime::Mime;
use native_tls::{Protocol, TlsConnector};
use rocket_contrib::templates::tera::{Context, Tera};

use crate::user::model::User;

use self::lettre::smtp::error::SmtpResult;
use self::lettre_email::Email;

#[derive(Default)]
struct SmtpCredentials {
    username: String,
    password: String,
    hostname: String,
    port: i32,
    sending_address: String,
}

///email attached file
pub struct AttachedFile {
    /// Body of the file
    pub body: Vec<u8>,
    /// File name
    pub filename: String,
    /// Content type
    pub content_type: Mime
}

/// Send a mail
pub fn sendmail(user: &User, context: Context, template: String, subject: String, attachments: Option<Vec<AttachedFile>>) -> Result<SmtpResult, String> {
    let mut smtp_settings: SmtpCredentials = { Default::default() };
    let mut settings = config::Config::default();
    let full_configuration = match settings.merge(config::File::with_name("Config")) {
        Ok(config) => { config }
        Err(_) => { return Err("Configuration file not found".to_string()); }
    };
    let configuration = match full_configuration.get_table("email") {
        Ok(x) => {x},
        Err(_) => {return Err("Configuration entries not found".to_string())},
    };

    if configuration.contains_key("smtp_username") &&
        configuration.contains_key("smtp_password") &&
        configuration.contains_key("smtp_hostname") &&
        configuration.contains_key("smtp_port") &&
        configuration.contains_key("smtp_sending_address") {
        smtp_settings.username = configuration.get("smtp_username").cloned().unwrap().into_str().unwrap().clone();
        smtp_settings.password = configuration.get("smtp_password").cloned().unwrap().into_str().unwrap().clone();
        smtp_settings.hostname = configuration.get("smtp_hostname").cloned().unwrap().into_str().unwrap().clone();
        smtp_settings.port = configuration.get("smtp_port").cloned().unwrap().into_int().unwrap().clone() as i32;
        smtp_settings.sending_address = configuration.get("smtp_sending_address").cloned().unwrap().into_str().unwrap().clone();
    } else {
        return Err("Could not find Configuration in Config.toml".to_string());
    }

    let project_root = env::current_dir().unwrap();
    let templates = format!("{}/templates_mail/*.tera", project_root.to_str().unwrap());
    let tera = Tera::new(&templates);

    let text = tera.unwrap().render(&(template + ".html.tera"), &context).unwrap();

    let mut email = Email::builder()
        .to(user.email.as_ref())
        .from(smtp_settings.sending_address)
        .subject(subject)
        .html(text);
    if attachments.is_some() {
        for attachment in attachments.unwrap() {
           email = email.attachment(attachment.body.as_ref(), attachment.filename.as_ref(), attachment.content_type.borrow()).unwrap()
        }
    }

    let finished_email = email
        .build()
        .unwrap();

    let mut tls_builder = TlsConnector::builder();
    tls_builder.min_protocol_version(Some(Protocol::Tlsv10));
    let tls_parameters =
        ClientTlsParameters::new(
            smtp_settings.hostname.clone(),
            tls_builder.build().unwrap(),
        );


    let mut mailer = SmtpClient::new(
        (smtp_settings.hostname.as_str(), 465), ClientSecurity::Wrapper(tls_parameters),
    ).unwrap()
        .authentication_mechanism(Mechanism::Login)
        .credentials(Credentials::new(
            smtp_settings.username, smtp_settings.password,
        ))
        .connection_reuse(ConnectionReuseParameters::ReuseUnlimited)
        .transport();

    let result = mailer.send(finished_email.into());

    mailer.close();

    Ok(result)
}
