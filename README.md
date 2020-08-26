# Rust Rocket RESTful API backend boilerplate template

<img src="https://img.shields.io/github/workflow/status/tserowski/webapp_boilerplate/Rust">

This is an example project for building a RESTful API backend with JWT authentication using Rust, Rocket and Diesel.

This boilerplate template gives examples for various use cases and solutions for some caveats that could occur during the implementation of a backend with rust, diesel and rocket. This example template is not recommended to be used for production puproses!

Some features:
* MySQL/MariaDB integration
* User registration / activation / forgot password / update / image upload / etc.
* HTML emails using tera templates
* User authentication using JWT (JSON web token) auth headers and/or Cookies
* Configurable application settings using .toml config file
* Examples for basic HTML templating using tera
* Image upload with multipart/form, thumbnail generation, database stored files and base64 encoding for JSON inline delivery

This example backend works with minimal configuration on a vue / nuxt.js project with enabled ```@nuxtjs/auth``` module.

## Prepare
### .env
Create an environment file ```.env``` to specify the connection to your database. 
For example:
```
ROCKET_DATABASES='{webapp_boilerplate={url="mysql://boilerplate:boilerplate@localhost:3306/boilerplate"}}'
```
### Config.toml
Before running the template make sure to create a file ```Config.toml```. You can create a copy of ```Config_template.toml```.
Make sure to fill in **all of the following** configuration parameters:
```
secretkey = ""  # Secret key for JWT encryption

[email]
smtp_username = ""
smtp_password = ""
smtp_hostname = ""
smtp_port = 465
smtp_sending_address = ""
```

## Build & Run

This template uses Rocket which only works with nightly rust. To build this project with the latest 
rust nightly run:

``` cargo +nightly build --release ```

And to run the server:

``` cargo +nightly run --release ```

For further information about running software with the Rust nightly toolchain consider the [documentation](https://doc.rust-lang.org/edition-guide/rust-2018/rustup-for-managing-rust-versions.html)