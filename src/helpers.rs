//! Helper functions for the BRC-31 auth middleware.
//!
//! Provides header extraction, body reading, payload re-injection, and
//! AuthMessage construction utilities that the middleware Service will call.

use actix_web::dev::Payload;
use actix_web::web::{Bytes, BytesMut};
use actix_web::HttpRequest;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::types::{AuthMessage, MessageType};
use futures_util::StreamExt;

/// All six `x-bsv-auth-*` headers extracted from a request.
#[derive(Clone, Debug)]
pub struct AuthHeaders {
    /// Protocol version (e.g. "0.1").
    pub version: String,
    /// Compressed hex public key of the sender.
    pub identity_key: String,
    /// Base64-encoded nonce created by the sender.
    pub nonce: String,
    /// The other party's nonce (echoed back).
    pub your_nonce: String,
    /// Hex-encoded ECDSA signature over the message.
    pub signature: String,
    /// Base64-encoded request nonce bytes.
    pub request_id: String,
}

/// Extract all six `x-bsv-auth-*` headers from a request.
///
/// Returns `None` if ANY of the six headers is missing or contains
/// non-ASCII characters.
pub fn extract_auth_headers(req: &HttpRequest) -> Option<AuthHeaders> {
    let version = req
        .headers()
        .get("x-bsv-auth-version")?
        .to_str()
        .ok()?
        .to_string();
    let identity_key = req
        .headers()
        .get("x-bsv-auth-identity-key")?
        .to_str()
        .ok()?
        .to_string();
    let nonce = req
        .headers()
        .get("x-bsv-auth-nonce")?
        .to_str()
        .ok()?
        .to_string();
    let your_nonce = req
        .headers()
        .get("x-bsv-auth-your-nonce")?
        .to_str()
        .ok()?
        .to_string();
    let signature = req
        .headers()
        .get("x-bsv-auth-signature")?
        .to_str()
        .ok()?
        .to_string();
    let request_id = req
        .headers()
        .get("x-bsv-auth-request-id")?
        .to_str()
        .ok()?
        .to_string();

    Some(AuthHeaders {
        version,
        identity_key,
        nonce,
        your_nonce,
        signature,
        request_id,
    })
}

/// Read the entire request payload stream into bytes.
pub async fn read_body(mut payload: Payload) -> Result<Bytes, actix_web::Error> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        body.extend_from_slice(&chunk?);
    }
    Ok(body.freeze())
}

/// Create a new Actix `Payload` containing the given bytes.
///
/// Used to re-inject the request body after reading it for signature
/// verification, so downstream extractors (`web::Json`, `web::Bytes`, etc.)
/// still receive the original body.
pub fn payload_from_bytes(bytes: Bytes) -> Payload {
    let (_, mut h1_payload) = actix_http::h1::Payload::create(true);
    h1_payload.unread_data(bytes);
    Payload::from(h1_payload)
}

/// Construct an `AuthMessage` from a request, its body bytes, and extracted headers.
///
/// Decodes the base64 request ID to raw nonce bytes, serializes the request
/// payload via `payload::serialize_from_http_request`, decodes the hex
/// signature, and assembles the `AuthMessage`.
pub fn build_auth_message(
    req: &HttpRequest,
    body_bytes: &[u8],
    headers: &AuthHeaders,
) -> AuthMessage {
    let request_nonce_bytes = BASE64.decode(&headers.request_id).unwrap_or_default();

    let payload =
        crate::payload::serialize_from_http_request(&request_nonce_bytes, req, body_bytes);

    tracing::debug!(
        "build_auth_message: method={} path={} query={} body_len={} nonce_len={} request_id={} nonce={} your_nonce={} payload_len={}",
        req.method(),
        req.path(),
        req.query_string(),
        body_bytes.len(),
        request_nonce_bytes.len(),
        headers.request_id,
        headers.nonce,
        headers.your_nonce,
        payload.len(),
    );

    let signature_bytes = hex::decode(&headers.signature).unwrap_or_default();

    AuthMessage {
        version: headers.version.clone(),
        message_type: MessageType::General,
        identity_key: headers.identity_key.clone(),
        nonce: Some(headers.nonce.clone()),
        your_nonce: Some(headers.your_nonce.clone()),
        initial_nonce: None,
        certificates: None,
        requested_certificates: None,
        payload: Some(payload),
        signature: Some(signature_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn test_extract_auth_headers_all_present() {
        let req = TestRequest::default()
            .insert_header(("x-bsv-auth-version", "0.1"))
            .insert_header(("x-bsv-auth-identity-key", "02abc123"))
            .insert_header(("x-bsv-auth-nonce", "nonce1"))
            .insert_header(("x-bsv-auth-your-nonce", "nonce2"))
            .insert_header(("x-bsv-auth-signature", "deadbeef"))
            .insert_header(("x-bsv-auth-request-id", "AQIDBA=="))
            .to_http_request();

        let headers = extract_auth_headers(&req).expect("should extract all headers");
        assert_eq!(headers.version, "0.1");
        assert_eq!(headers.identity_key, "02abc123");
        assert_eq!(headers.nonce, "nonce1");
        assert_eq!(headers.your_nonce, "nonce2");
        assert_eq!(headers.signature, "deadbeef");
        assert_eq!(headers.request_id, "AQIDBA==");
    }

    #[test]
    fn test_extract_auth_headers_missing_one() {
        // Missing x-bsv-auth-nonce
        let req = TestRequest::default()
            .insert_header(("x-bsv-auth-version", "0.1"))
            .insert_header(("x-bsv-auth-identity-key", "02abc123"))
            .insert_header(("x-bsv-auth-your-nonce", "nonce2"))
            .insert_header(("x-bsv-auth-signature", "deadbeef"))
            .insert_header(("x-bsv-auth-request-id", "AQIDBA=="))
            .to_http_request();

        assert!(extract_auth_headers(&req).is_none());
    }

    #[test]
    fn test_extract_auth_headers_missing_all() {
        let req = TestRequest::default().to_http_request();
        assert!(extract_auth_headers(&req).is_none());
    }

    #[actix_web::test]
    async fn test_payload_from_bytes_roundtrip() {
        let original = Bytes::from_static(b"hello world");
        let payload = payload_from_bytes(original.clone());
        let recovered = read_body(payload).await.expect("should read body");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_build_auth_message_basic() {
        let req = TestRequest::default()
            .method(actix_web::http::Method::GET)
            .uri("/test")
            .to_http_request();

        let headers = AuthHeaders {
            version: "0.1".to_string(),
            identity_key: "02abc123".to_string(),
            nonce: "nonce1".to_string(),
            your_nonce: "nonce2".to_string(),
            signature: "deadbeef".to_string(),
            request_id: "AQIDBA==".to_string(), // base64 for [1,2,3,4]
        };

        let msg = build_auth_message(&req, b"", &headers);
        assert_eq!(msg.version, "0.1");
        assert_eq!(msg.identity_key, "02abc123");
        assert_eq!(msg.nonce, Some("nonce1".to_string()));
        assert_eq!(msg.your_nonce, Some("nonce2".to_string()));
        assert!(matches!(msg.message_type, MessageType::General));
        assert!(msg.payload.is_some());
        assert_eq!(msg.signature, Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }
}
