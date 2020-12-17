# saml-rs

This project implements a SAML workflow I needed to implement. At the moment only one authentication method is supported, which
is Symantec VIP Access Tokens.

# Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
saml = { git = "https://github.com/mttrbit/saml-rs", branch = "main"}
```

Vip is built with Rust 1.48.

```rust,ignore
use saml::Idp;
use reqwest::blocking::Client;
let client = Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
let rc_client = std::rc::Rc::new(client);
match IdP::with_client(&rc_client).authenticate(
    "https://your.saml.protected.service",
    "your_username",
    "your_password",
) {
    Ok(()) => {
        // do something, e.g. call a protected service 
    }
    Err(e) => println!("Error {:?}", e),
};
```
