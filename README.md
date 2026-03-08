# bsv-auth-actix-middleware

[![Crates.io](https://img.shields.io/crates/v/bsv-auth-actix-middleware.svg)](https://crates.io/crates/bsv-auth-actix-middleware)
[![Documentation](https://docs.rs/bsv-auth-actix-middleware/badge.svg)](https://docs.rs/bsv-auth-actix-middleware)
[![CI](https://github.com/b1narydt/auth-actix-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/b1narydt/auth-actix-middleware/actions)
[![License: Open BSV](https://img.shields.io/badge/license-Open%20BSV-blue.svg)](https://github.com/b1narydt/auth-actix-middleware/blob/main/LICENSE)

BSV BRC-31 (Authrite) mutual authentication middleware for Actix-web. This crate
translates the TypeScript `@bsv/auth-express-middleware` into idiomatic Rust,
implementing request signing, response verification, and certificate exchange
as an Actix-web middleware layer.

## What is BRC-31?

[BRC-31](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0031.md)
defines the Authrite mutual authentication protocol for BSV applications. It
enables both client and server to prove their identity through public key
cryptography without shared secrets or session cookies. Each request is signed
by the sender and verified by the receiver, and each response is signed in
return, providing end-to-end authentication for every HTTP exchange.

## Installation

Add the crate to your project:

```sh
cargo add bsv-auth-actix-middleware
```

Or add it manually to your `Cargo.toml`:

```toml
[dependencies]
bsv-auth-actix-middleware = "0.1"
```

You will also need the BSV SDK for wallet and peer types:

```toml
[dependencies]
bsv-sdk = { version = "0.1.3", features = ["network"] }
```

## Quick Start

```rust,no_run
use std::sync::Arc;
use actix_web::{web, App, HttpServer, HttpResponse};
use bsv_auth_actix_middleware::{
    AuthMiddlewareConfigBuilder, AuthMiddlewareFactory, Authenticated,
};
use bsv_auth_actix_middleware::transport::ActixTransport;

// Handler that receives verified identity via the Authenticated extractor
async fn hello(auth: Authenticated) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Hello, authenticated user!",
        "identity_key": auth.identity_key
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. Create or obtain a wallet implementing WalletInterface.
    //    For example, wrap a ProtoWallet from the BSV SDK.
    // let wallet = your_wallet_implementation();

    // 2. Build the middleware configuration.
    // let config = AuthMiddlewareConfigBuilder::new()
    //     .wallet(wallet.clone())
    //     .build()
    //     .expect("valid config");

    // 3. Create the transport and peer, then build the middleware.
    // let transport = Arc::new(ActixTransport::new());
    // let peer = Arc::new(tokio::sync::Mutex::new(
    //     Peer::new(wallet, transport.clone()),
    // ));
    // let middleware = AuthMiddlewareFactory::new(config, peer, transport).await;

    // 4. Attach the middleware to your Actix-web app.
    HttpServer::new(move || {
        App::new()
            // .wrap(middleware.clone())
            .route("/hello", web::get().to(hello))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration

Use `AuthMiddlewareConfigBuilder` to configure the middleware:

```rust,ignore
let config = AuthMiddlewareConfigBuilder::new()
    .wallet(wallet)                              // Required: WalletInterface impl
    .allow_unauthenticated(false)                // Optional: reject unauth requests (default)
    .certificates_to_request(certificate_set)    // Optional: request certs from peers
    .session_manager(session_mgr)                // Optional: track authenticated sessions
    .on_certificates_received(callback)          // Optional: handle received certificates
    .build()
    .expect("valid config");
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `wallet` | `W: WalletInterface` | *required* | Wallet used for signing, verification, and key operations |
| `allow_unauthenticated` | `bool` | `false` | When `true`, requests without auth headers pass through to the handler |
| `certificates_to_request` | `RequestedCertificateSet` | `None` | Certificate types to request from peers after handshake |
| `session_manager` | `SessionManager` | `None` | Manages authenticated sessions for repeat connections |
| `on_certificates_received` | `OnCertificatesReceived` | `None` | Async callback invoked when certificates arrive from a peer |

## Authentication Flow

The middleware implements the full BRC-31 mutual authentication handshake:

1. **Client initiates handshake** -- sends a request to `/.well-known/auth` with
   its public key and a nonce. The middleware responds with the server's public
   key and nonce, establishing a session.

2. **Client sends authenticated request** -- includes `x-bsv-auth-*` headers
   containing the identity key, nonce, and a cryptographic signature over the
   request body.

3. **Middleware verifies request** -- checks the signature against the request
   body and headers, confirming the sender's identity. If verification fails,
   the request is rejected with a 401 response.

4. **Handler receives identity** -- the `Authenticated` extractor provides the
   verified `identity_key` and optional `certificate_set` to route handlers.

5. **Middleware signs response** -- before sending the response back, the
   middleware signs it with the server's key, completing mutual authentication.

## Certificate Exchange

For advanced identity verification, BRC-31 supports certificate exchange after
the initial handshake. Use `CertificateGate` and the `certificates_to_request`
configuration option to require specific certificates from peers:

```rust,ignore
use std::collections::HashMap;

let mut certs: HashMap<String, Vec<String>> = HashMap::new();
certs.insert("certifier_id".into(), vec!["field_name".into()]);

let config = AuthMiddlewareConfigBuilder::new()
    .wallet(wallet)
    .certificates_to_request(certs)
    .on_certificates_received(Box::new(|identity_key, certificates| {
        Box::pin(async move {
            // Process received certificates
            println!("Received {} certs from {}", certificates.len(), identity_key);
        })
    }))
    .build()
    .expect("valid config");
```

The middleware will gate authenticated requests until the required certificates
are received, using `CertificateGate` to coordinate the asynchronous exchange.

## API Reference

Full API documentation is available on [docs.rs](https://docs.rs/bsv-auth-actix-middleware).

## License

This project is licensed under the [Open BSV License](https://github.com/b1narydt/auth-actix-middleware/blob/main/LICENSE).
