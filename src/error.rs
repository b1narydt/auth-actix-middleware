//! Error types for the BSV auth middleware.
//!
//! Defines `AuthMiddlewareError` with variants for transport, configuration,
//! payload, and BSV SDK errors. Implements `actix_web::ResponseError` for
//! automatic HTTP response conversion with JSON error bodies matching the
//! TypeScript `auth-express-middleware` wire format exactly.
//!
//! Wire-contract notes (TS parity):
//! - 401 missing/invalid auth headers: `{"status":"error","code":"UNAUTHORIZED",
//!   "message":"Mutual-authentication failed!"}`
//! - 408 certificate request timeout: `{"status":"error","code":"CERTIFICATE_TIMEOUT",
//!   "message":"Certificate request timed out"}`
//! - 500 response signing failure: `{"status":"error","code":"ERR_RESPONSE_SIGNING_FAILED",
//!   "description":"<reason>"}` (TS uses `description` for this variant only)

use actix_web::http::StatusCode;
use actix_web::HttpResponse;

/// Unified error type for the BSV authentication middleware.
#[derive(Debug, thiserror::Error)]
pub enum AuthMiddlewareError {
    /// Transport-level error (connection, channel, etc.).
    #[error("transport error: {0}")]
    Transport(String),

    /// Configuration error (missing required fields, invalid values).
    #[error("configuration error: {0}")]
    Config(String),

    /// Payload serialization or deserialization error.
    #[error("payload error: {0}")]
    Payload(String),

    /// Error from the BSV SDK authentication layer.
    #[error("bsv sdk error: {0}")]
    BsvSdk(#[from] bsv::auth::AuthError),

    /// Middleware-level authentication failure: request lacked valid auth
    /// headers when `allow_unauthenticated` is false. Emits the fixed TS
    /// body `{"code":"UNAUTHORIZED","message":"Mutual-authentication failed!"}`.
    #[error("Mutual-authentication failed!")]
    Unauthorized,

    /// Certificate exchange timed out while waiting on the gate. Emits
    /// `{"code":"CERTIFICATE_TIMEOUT","message":"Certificate request timed out"}`.
    #[error("Certificate request timed out")]
    CertificateTimeout,

    /// Response signing failed during the general-message flow. Emits
    /// `{"code":"ERR_RESPONSE_SIGNING_FAILED","description":"<reason>"}`.
    /// The inner string is the underlying error's display text, surfaced
    /// verbatim to match TS behavior.
    #[error("{0}")]
    ResponseSigningFailed(String),
}

impl actix_web::error::ResponseError for AuthMiddlewareError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_)
                | bsv::auth::AuthError::AuthFailed(_)
                | bsv::auth::AuthError::InvalidSignature(_) => StatusCode::UNAUTHORIZED,
                bsv::auth::AuthError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::CertificateTimeout => StatusCode::REQUEST_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        // Variants that diverge from the standard `{status,code,description}`
        // shape are emitted explicitly below to match TS byte-for-byte.
        match self {
            Self::Unauthorized => {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "status": "error",
                    "code": "UNAUTHORIZED",
                    "message": "Mutual-authentication failed!",
                }));
            }
            Self::CertificateTimeout => {
                return HttpResponse::RequestTimeout().json(serde_json::json!({
                    "status": "error",
                    "code": "CERTIFICATE_TIMEOUT",
                    "message": "Certificate request timed out",
                }));
            }
            Self::ResponseSigningFailed(reason) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "code": "ERR_RESPONSE_SIGNING_FAILED",
                    "description": reason,
                }));
            }
            _ => {}
        }

        let code = match self {
            Self::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_) => "ERR_NOT_AUTHENTICATED",
                bsv::auth::AuthError::AuthFailed(_) => "ERR_AUTH_FAILED",
                bsv::auth::AuthError::InvalidSignature(_) => "ERR_INVALID_SIGNATURE",
                bsv::auth::AuthError::Timeout(_) => "ERR_TIMEOUT",
                _ => "ERR_INTERNAL_SERVER_ERROR",
            },
            Self::Transport(_) => "ERR_TRANSPORT",
            Self::Config(_) => "ERR_CONFIG",
            Self::Payload(_) => "ERR_PAYLOAD",
            // Already returned above:
            Self::Unauthorized | Self::CertificateTimeout | Self::ResponseSigningFailed(_) => {
                unreachable!("handled in match above")
            }
        };
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "status": "error",
            "code": code,
            "description": self.to_string()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::error::ResponseError;

    #[test]
    fn test_transport_display() {
        let err = AuthMiddlewareError::Transport("msg".to_string());
        assert_eq!(err.to_string(), "transport error: msg");
    }

    #[test]
    fn test_config_display() {
        let err = AuthMiddlewareError::Config("msg".to_string());
        assert_eq!(err.to_string(), "configuration error: msg");
    }

    #[test]
    fn test_payload_display() {
        let err = AuthMiddlewareError::Payload("msg".to_string());
        assert_eq!(err.to_string(), "payload error: msg");
    }

    #[test]
    fn test_bsvsdk_not_authenticated_returns_401() {
        let err =
            AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::NotAuthenticated("test".to_string()));
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_bsvsdk_auth_failed_returns_401() {
        let err = AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::AuthFailed("test".to_string()));
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_bsvsdk_invalid_signature_returns_401() {
        let err =
            AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::InvalidSignature("test".to_string()));
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_bsvsdk_timeout_returns_408() {
        let err = AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::Timeout("test".to_string()));
        assert_eq!(err.status_code(), StatusCode::REQUEST_TIMEOUT);
    }

    #[test]
    fn test_bsvsdk_other_returns_500() {
        let err =
            AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::TransportError("test".to_string()));
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_transport_variant_returns_500_and_err_transport() {
        let err = AuthMiddlewareError::Transport("broken".to_string());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_config_variant_returns_500_and_err_config() {
        let err = AuthMiddlewareError::Config("bad config".to_string());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn test_error_response_body_format_transport() {
        let err = AuthMiddlewareError::Transport("connection refused".to_string());
        let resp = err.error_response();
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_TRANSPORT");
        assert_eq!(json["description"], "transport error: connection refused");
    }

    #[actix_web::test]
    async fn test_error_response_body_format_not_authenticated() {
        let err = AuthMiddlewareError::BsvSdk(bsv::auth::AuthError::NotAuthenticated(
            "no session".to_string(),
        ));
        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_NOT_AUTHENTICATED");
        assert_eq!(
            json["description"],
            "bsv sdk error: not authenticated: no session"
        );
    }

    #[actix_web::test]
    async fn test_error_response_body_format_config() {
        let err = AuthMiddlewareError::Config("wallet is required".to_string());
        let resp = err.error_response();
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_CONFIG");
        assert_eq!(
            json["description"],
            "configuration error: wallet is required"
        );
    }

    #[actix_web::test]
    async fn test_error_response_body_format_payload() {
        let err = AuthMiddlewareError::Payload("invalid bytes".to_string());
        let resp = err.error_response();
        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_PAYLOAD");
        assert_eq!(json["description"], "payload error: invalid bytes");
    }

    #[test]
    fn test_certificate_timeout_display() {
        let err = AuthMiddlewareError::CertificateTimeout;
        assert_eq!(err.to_string(), "Certificate request timed out");
    }

    #[test]
    fn test_certificate_timeout_returns_408() {
        let err = AuthMiddlewareError::CertificateTimeout;
        assert_eq!(err.status_code(), StatusCode::REQUEST_TIMEOUT);
    }

    // GAP G2: 408 certificate-timeout body must use `message` field (not
    // `description`) per TS `auth-express-middleware` lines 637-650.
    #[actix_web::test]
    async fn test_certificate_timeout_error_response_body_matches_ts() {
        let err = AuthMiddlewareError::CertificateTimeout;
        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "CERTIFICATE_TIMEOUT");
        assert_eq!(json["message"], "Certificate request timed out");
        // `description` must not be present on this variant.
        assert!(json.get("description").is_none());
    }

    #[test]
    fn test_from_bsv_auth_error() {
        let auth_err = bsv::auth::AuthError::AuthFailed("bad".to_string());
        let err: AuthMiddlewareError = auth_err.into();
        match err {
            AuthMiddlewareError::BsvSdk(_) => {}
            _ => panic!("expected BsvSdk variant"),
        }
    }

    // GAP G1: 401 Unauthorized body must be exactly
    // {"status":"error","code":"UNAUTHORIZED","message":"Mutual-authentication failed!"}.
    #[actix_web::test]
    async fn test_unauthorized_error_response_matches_ts_spec() {
        let err = AuthMiddlewareError::Unauthorized;
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);

        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "UNAUTHORIZED");
        assert_eq!(json["message"], "Mutual-authentication failed!");
        assert!(json.get("description").is_none());
    }

    #[test]
    fn test_unauthorized_display() {
        let err = AuthMiddlewareError::Unauthorized;
        assert_eq!(err.to_string(), "Mutual-authentication failed!");
    }

    // GAP G3: 500 response-signing failure emits code
    // ERR_RESPONSE_SIGNING_FAILED with the `description` field (TS is
    // inconsistent here but this matches auth-express-middleware:543-547).
    #[actix_web::test]
    async fn test_response_signing_failed_error_response_matches_ts_spec() {
        let err = AuthMiddlewareError::ResponseSigningFailed("wallet HSM offline".to_string());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "ERR_RESPONSE_SIGNING_FAILED");
        assert_eq!(json["description"], "wallet HSM offline");
        assert!(json.get("message").is_none());
    }

    #[test]
    fn test_response_signing_failed_display_is_inner_reason() {
        let err = AuthMiddlewareError::ResponseSigningFailed("boom".to_string());
        assert_eq!(err.to_string(), "boom");
    }
}
