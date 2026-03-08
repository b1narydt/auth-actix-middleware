//! BSV BRC-31 authentication middleware for Actix-web.
//!
//! Translates the TypeScript `@bsv/auth-express-middleware` into an idiomatic
//! Rust Actix-web middleware crate, implementing the BRC-31 Authrite mutual
//! authentication protocol.

pub mod certificate;
pub mod config;
pub mod error;
pub mod extractor;
pub mod helpers;
pub mod middleware;
pub mod payload;
pub mod transport;

pub use certificate::CertificateGate;
pub use config::{AuthMiddlewareConfig, AuthMiddlewareConfigBuilder, OnCertificatesReceived};
pub use error::AuthMiddlewareError;
pub use extractor::Authenticated;
pub use helpers::{extract_auth_headers, AuthHeaders};
pub use middleware::AuthMiddlewareFactory;
