# Rust Rocket RESTful API backend boilerplate template

<img src="https://img.shields.io/github/workflow/status/tserowski/webapp_boilerplate/Rust">

This is an example project for building a modern RESTful API driven backend using rust, rocket and diesel.

This boilerplate template gives examples for various use cases and solutions for some caveats that could occur during the implementation of a backend with rust, diesel and rocket. This example template is not recommended to be used for production puproses!

Some features:
* MySQL/MariaDB integration
* User registration with random registration codes for activation
* User activation with activation emails using lettre email with tera html templates
* User authentication using JWT (JSON web token) and/or Cookies
* Configurable application settings using .toml config file
* HTML templating for emails powered by tera
* Image upload with multipart/form, database stored files and base64 encoding for JSON inline delivery

## Run
### .env
Create an environment file ```.env``` to specify the connection to your database. 
For example:
```
ROCKET_DATABASES='{webapp_boilerplate={url="mysql://boilerplate:boilerplate@localhost:3306/boilerplate"}}'
```
### Config.toml
Before running the template make sure to create a file ```Config.toml```. You can create a copy of ```Config_template.toml```.
Make sure to fill in the required configuration parameters:
```
secretkey = ""  # Secret key for JWT encryption

[email]
smtp_username = ""
smtp_password = ""
smtp_hostname = ""
smtp_port = 465
smtp_sending_address = ""
```


This template uses Rocket which only works with nightly rust. To build this project with the latest 
rust nightly run:

``` cargo +nightly build --release ```

And to run the server:

``` cargo +nightly run --release ```

For further information about running software with rust nightly consider the [documentation](https://doc.rust-lang.org/edition-guide/rust-2018/rustup-for-managing-rust-versions.html)