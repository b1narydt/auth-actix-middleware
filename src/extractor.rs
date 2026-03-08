//! Authenticated request extractor for downstream handlers.
//!
//! The `Authenticated` struct is inserted into request extensions by the auth
//! middleware after successful BRC-31 signature verification. Handlers extract
//! it via the standard Actix-web `FromRequest` trait, e.g.:
//!
//! ```ignore
//! async fn handler(auth: Authenticated) -> impl Responder {
//!     format!("Hello, {}", auth.identity_key)
//! }
//! ```

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use std::future::{ready, Ready};

/// Verified identity extracted from BRC-31 auth headers.
///
/// Inserted into request extensions by the auth middleware. When
/// `allow_unauthenticated` is true and no auth headers are present,
/// `identity_key` is set to `"unknown"`.
#[derive(Clone, Debug)]
pub struct Authenticated {
    /// Compressed hex public key of the authenticated caller.
    pub identity_key: String,
}

impl FromRequest for Authenticated {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<Authenticated>() {
            Some(auth) => ready(Ok(auth.clone())),
            None => ready(Err(actix_web::error::ErrorUnauthorized(
                serde_json::json!({
                    "status": "error",
                    "code": "ERR_NOT_AUTHENTICATED",
                    "description": "Authentication required"
                }),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use actix_web::FromRequest;

    #[actix_web::test]
    async fn test_from_request_with_authenticated() {
        let identity = "02abc123def456";
        let req = TestRequest::default().to_http_request();
        req.extensions_mut().insert(Authenticated {
            identity_key: identity.to_string(),
        });

        let mut payload = Payload::None;
        let result = Authenticated::from_request(&req, &mut payload).await;
        let auth = result.expect("should extract Authenticated");
        assert_eq!(auth.identity_key, identity);
    }

    #[actix_web::test]
    async fn test_from_request_without_authenticated() {
        let req = TestRequest::default().to_http_request();
        let mut payload = Payload::None;
        let result = Authenticated::from_request(&req, &mut payload).await;

        let err = result.expect_err("should return error without Authenticated");
        let resp = err.as_response_error().error_response();
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);

        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_NOT_AUTHENTICATED");
        assert_eq!(json["description"], "Authentication required");
    }

    #[test]
    fn test_authenticated_clone() {
        let auth = Authenticated {
            identity_key: "02abc123".to_string(),
        };
        let cloned = auth.clone();
        assert_eq!(auth.identity_key, cloned.identity_key);
    }
}
