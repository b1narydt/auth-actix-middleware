//! Error types for the BSV auth middleware.
//!
//! Defines `AuthMiddlewareError` with variants for transport, configuration,
//! payload, and BSV SDK errors. Implements `actix_web::ResponseError` for
//! automatic HTTP response conversion with JSON error bodies matching the
//! TypeScript middleware format.

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

    /// Middleware-level authentication failure (e.g., missing headers when
    /// `allow_unauthenticated` is false).
    #[error("authentication error: {0}")]
    Authentication(String),

    /// Certificate exchange timed out.
    #[error("certificate timeout: {0}")]
    CertificateTimeout(String),
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
            Self::Authentication(_) => StatusCode::UNAUTHORIZED,
            Self::CertificateTimeout(_) => StatusCode::REQUEST_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let code = match self {
            Self::BsvSdk(e) => match e {
                bsv::auth::AuthError::NotAuthenticated(_) => "ERR_NOT_AUTHENTICATED",
                bsv::auth::AuthError::AuthFailed(_) => "ERR_AUTH_FAILED",
                bsv::auth::AuthError::InvalidSignature(_) => "ERR_INVALID_SIGNATURE",
                bsv::auth::AuthError::Timeout(_) => "ERR_TIMEOUT",
                _ => "ERR_INTERNAL_SERVER_ERROR",
            },
            Self::Authentication(_) => "ERR_AUTHENTICATION",
            Self::Transport(_) => "ERR_TRANSPORT",
            Self::Config(_) => "ERR_CONFIG",
            Self::Payload(_) => "ERR_PAYLOAD",
            Self::CertificateTimeout(_) => "CERTIFICATE_TIMEOUT",
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
        let err = AuthMiddlewareError::CertificateTimeout("waited too long".to_string());
        assert_eq!(err.to_string(), "certificate timeout: waited too long");
    }

    #[test]
    fn test_certificate_timeout_returns_408() {
        let err = AuthMiddlewareError::CertificateTimeout("timeout".to_string());
        assert_eq!(err.status_code(), StatusCode::REQUEST_TIMEOUT);
    }

    #[actix_web::test]
    async fn test_certificate_timeout_error_response_body() {
        let err =
            AuthMiddlewareError::CertificateTimeout("Certificate request timed out".to_string());
        let resp = err.error_response();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);

        let body = to_bytes(resp.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["code"], "CERTIFICATE_TIMEOUT");
        assert_eq!(
            json["description"],
            "certificate timeout: Certificate request timed out"
        );
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
}
