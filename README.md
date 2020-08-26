Rust Rocket RESTful API backend boilerplate template
===================================

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