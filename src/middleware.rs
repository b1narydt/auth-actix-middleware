//! Core BRC-31 authentication middleware for Actix-web.
//!
//! Implements the Actix-web `Transform`/`Service` pattern to intercept all
//! requests and handle three branches:
//!
//! 1. **Handshake** (`/.well-known/auth`) -- feed incoming AuthMessage to Peer,
//!    wait for signed response, return with `x-bsv-auth-*` headers.
//! 2. **Authenticated** (requests with `x-bsv-auth-*` headers) -- verify
//!    request signature via Peer, call handler, buffer response, sign response.
//! 3. **Unauthenticated** (no auth headers) -- reject with 401 when
//!    `allow_unauthenticated` is false, or pass through with identity "unknown".

use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, HttpResponse};
use futures_util::future::LocalBoxFuture;
use futures_util::FutureExt;
use tracing::{debug, error, warn};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv::auth::peer::Peer;
use bsv::auth::types::AuthMessage;
use bsv::wallet::interfaces::WalletInterface;

use crate::certificate::{certificate_listener_task, CertificateGate};
use crate::config::AuthMiddlewareConfig;
use crate::error::AuthMiddlewareError;
use crate::extractor::Authenticated;
use crate::helpers::{build_auth_message, extract_auth_headers, payload_from_bytes, read_body};
use crate::transport::ActixTransport;

// ---------------------------------------------------------------------------
// AuthMiddlewareFactory (Transform)
// ---------------------------------------------------------------------------

/// Factory that produces [`AuthMiddlewareService`] wrappers for each worker.
///
/// Users register this via `.wrap()` on their Actix-web `App` or `Scope`.
pub struct AuthMiddlewareFactory<W: WalletInterface> {
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
    allow_unauthenticated: bool,
    certificate_gate: Option<CertificateGate>,
}

impl<W: WalletInterface + 'static> AuthMiddlewareFactory<W> {
    /// Create a new middleware factory from configuration.
    ///
    /// # Arguments
    /// * `config` - Middleware configuration including wallet, certificate
    ///   settings, and optional callbacks.
    /// * `peer` - Shared Peer instance for BRC-31 protocol processing.
    /// * `transport` - Channel-based transport for message correlation.
    ///
    /// When `config.certificates_to_request` is `Some`, this constructor:
    /// 1. Configures the Peer with the requested certificate set.
    /// 2. Takes the certificate receivers from the Peer (one-shot take).
    /// 3. Spawns a background `certificate_listener_task` that consumes
    ///    certificate events and releases the per-identity gate.
    pub async fn new(
        config: AuthMiddlewareConfig<W>,
        peer: Arc<tokio::sync::Mutex<Peer<W>>>,
        transport: Arc<ActixTransport>,
    ) -> Self {
        let certificate_gate = if let Some(ref certs_to_request) = config.certificates_to_request {
            // Lock peer to configure certificate exchange
            let (cert_rx, cert_req_rx) = {
                let mut peer_guard = peer.lock().await;
                peer_guard.set_certificates_to_request(certs_to_request.clone());

                let cert_rx = peer_guard.on_certificates();
                let cert_req_rx = peer_guard.on_certificate_request();

                if cert_rx.is_none() {
                    warn!("Peer::on_certificates() returned None -- receiver already taken");
                }
                if cert_req_rx.is_none() {
                    warn!("Peer::on_certificate_request() returned None -- receiver already taken");
                }

                (cert_rx, cert_req_rx)
            };
            // Peer lock dropped here

            // Only spawn if we got both receivers
            if let (Some(cert_rx), Some(cert_req_rx)) = (cert_rx, cert_req_rx) {
                let gate = CertificateGate::new();
                let gate_clone = gate.clone();
                let callback = config.on_certificates_received.clone();

                tokio::spawn(certificate_listener_task(
                    cert_rx,
                    cert_req_rx,
                    gate_clone,
                    callback,
                ));

                debug!("certificate listener task spawned");
                Some(gate)
            } else {
                warn!("certificate exchange configured but receivers unavailable -- gate disabled");
                None
            }
        } else {
            None
        };

        Self {
            peer,
            transport,
            allow_unauthenticated: config.allow_unauthenticated,
            certificate_gate,
        }
    }
}

impl<W: WalletInterface + Clone> Clone for AuthMiddlewareFactory<W> {
    fn clone(&self) -> Self {
        AuthMiddlewareFactory {
            peer: self.peer.clone(),
            transport: self.transport.clone(),
            allow_unauthenticated: self.allow_unauthenticated,
            certificate_gate: self.certificate_gate.clone(),
        }
    }
}

impl<S, B, W> Transform<S, ServiceRequest> for AuthMiddlewareFactory<W>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
    W: WalletInterface + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S, W>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            peer: self.peer.clone(),
            transport: self.transport.clone(),
            allow_unauthenticated: self.allow_unauthenticated,
            certificate_gate: self.certificate_gate.clone(),
        }))
    }
}

// ---------------------------------------------------------------------------
// AuthMiddlewareService (Service)
// ---------------------------------------------------------------------------

/// Per-worker middleware service that intercepts requests.
pub struct AuthMiddlewareService<S, W: WalletInterface> {
    service: Rc<S>,
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
    allow_unauthenticated: bool,
    certificate_gate: Option<CertificateGate>,
}

impl<S, B, W> Service<ServiceRequest> for AuthMiddlewareService<S, W>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
    W: WalletInterface + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let peer = self.peer.clone();
        let transport = self.transport.clone();
        let allow_unauth = self.allow_unauthenticated;
        let certificate_gate = self.certificate_gate.clone();

        async move {
            let path = req.path().to_string();

            // Branch 1: Handshake at /.well-known/auth
            if path == "/.well-known/auth" {
                debug!("BRC-31 handshake request at /.well-known/auth");
                return handle_handshake(req, peer, transport).await;
            }

            // Check for auth headers
            let auth_headers = extract_auth_headers(req.request());

            match auth_headers {
                Some(headers) => {
                    // Branch 2: Authenticated request -- verify signature, call
                    // handler, then sign the response.
                    debug!(
                        "Authenticated request detected (identity_key={})",
                        headers.identity_key
                    );

                    // 1. Decompose ServiceRequest to read the body
                    let (http_req, payload) = req.into_parts();

                    // 2. Read request body bytes
                    let body_bytes = read_body(payload).await?;

                    // 3. Build AuthMessage from request + body + headers
                    let auth_msg = build_auth_message(&http_req, &body_bytes, &headers);

                    // 4. Feed to Peer for signature verification.
                    //    For general messages, process_pending verifies inline
                    //    and returns Err(AuthError) on invalid signature.
                    transport.feed_incoming(auth_msg).await.map_err(|e| {
                        error!("Failed to feed auth message to Peer: {}", e);
                        e
                    })?;

                    {
                        let mut peer_guard = peer.lock().await;
                        peer_guard.process_pending().await.map_err(|e| {
                            warn!("Signature verification failed: {}", e);
                            AuthMiddlewareError::BsvSdk(e)
                        })?;
                    }

                    // 5. Verification passed -- insert identity into extensions
                    http_req.extensions_mut().insert(Authenticated {
                        identity_key: headers.identity_key.clone(),
                    });

                    // 5b. Certificate gating: first-time peers wait for certificates
                    if let Some(ref gate) = certificate_gate {
                        let has_session = {
                            let peer_guard = peer.lock().await;
                            peer_guard
                                .session_manager()
                                .has_session_by_identifier(&headers.identity_key)
                        };
                        // Peer lock dropped before awaiting gate

                        if !has_session {
                            let notify = gate.register(&headers.identity_key);
                            match tokio::time::timeout(
                                Duration::from_secs(30),
                                notify.notified(),
                            )
                            .await
                            {
                                Ok(()) => {
                                    debug!(
                                        identity_key = %headers.identity_key,
                                        "certificate gate released"
                                    );
                                }
                                Err(_) => {
                                    warn!(
                                        identity_key = %headers.identity_key,
                                        "certificate request timed out"
                                    );
                                    return Ok(ServiceResponse::new(
                                        http_req,
                                        HttpResponse::RequestTimeout()
                                            .json(serde_json::json!({
                                                "status": "error",
                                                "code": "CERTIFICATE_TIMEOUT",
                                                "message": "Certificate request timed out"
                                            }))
                                            .map_into_right_body(),
                                    ));
                                }
                            }
                        }
                    }

                    // 6. Re-inject body for downstream handlers
                    let new_payload = payload_from_bytes(body_bytes.clone());

                    // 7. Reassemble and call inner service
                    let service_req = ServiceRequest::from_parts(http_req, new_payload);
                    let service_resp = srv.call(service_req).await?;

                    // 8. Buffer response, sign, and return with auth headers
                    handle_response_signing(service_resp, peer, transport, &headers).await
                }
                None => {
                    // Branch 3: No auth headers
                    if allow_unauth {
                        debug!("No auth headers, allow_unauthenticated=true, passing through with identity 'unknown'");
                        req.extensions_mut().insert(Authenticated {
                            identity_key: "unknown".to_string(),
                        });
                        let res = srv.call(req).await?;
                        Ok(res.map_into_left_body())
                    } else {
                        debug!("No auth headers, allow_unauthenticated=false, rejecting with 401");
                        let (http_req, _payload) = req.into_parts();
                        Ok(ServiceResponse::new(
                            http_req,
                            HttpResponse::Unauthorized()
                                .json(serde_json::json!({
                                    "status": "error",
                                    "code": "ERR_UNAUTHORIZED",
                                    "description": "Mutual authentication required"
                                }))
                                .map_into_right_body(),
                        ))
                    }
                }
            }
        }
        .boxed_local()
    }
}

// ---------------------------------------------------------------------------
// Handshake handler
// ---------------------------------------------------------------------------

/// Handle a BRC-31 message at `/.well-known/auth`.
///
/// Parses the request body as an `AuthMessage` and dispatches based on type:
/// - InitialRequest: Full handshake flow with signed response
/// - CertificateResponse/CertificateRequest: Process and return 200 (no response body needed)
///
/// For handshake messages, feeds the message to the Peer via the transport,
/// triggers processing, and waits for the signed response.
async fn handle_handshake<B, W>(
    req: ServiceRequest,
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    B: MessageBody + 'static,
    W: WalletInterface + 'static,
{
    // Read the request body
    let (http_req, payload) = req.into_parts();
    let body_bytes = read_body(payload).await?;

    // Parse as AuthMessage
    let auth_msg: AuthMessage = serde_json::from_slice(&body_bytes).map_err(|e| {
        warn!("Failed to parse handshake body as AuthMessage: {}", e);
        AuthMiddlewareError::Payload(format!("invalid handshake body: {}", e))
    })?;

    debug!(
        "Auth message received at /.well-known/auth: type={:?}, identity_key={}",
        auth_msg.message_type, auth_msg.identity_key
    );

    // For certificate messages (CertificateResponse, CertificateRequest),
    // just feed to the Peer for processing and return 200 immediately.
    // These don't require a signed response back to the sender.
    match auth_msg.message_type {
        bsv::auth::types::MessageType::CertificateResponse
        | bsv::auth::types::MessageType::CertificateRequest => {
            debug!(
                "Processing certificate message: type={:?}",
                auth_msg.message_type
            );

            transport.feed_incoming(auth_msg).await.map_err(|e| {
                error!("Failed to feed certificate message to Peer: {}", e);
                e
            })?;

            {
                let mut peer_guard = peer.lock().await;
                peer_guard.process_pending().await.map_err(|e| {
                    error!("Peer processing failed for certificate message: {}", e);
                    AuthMiddlewareError::BsvSdk(e)
                })?;
            }

            return Ok(ServiceResponse::new(
                http_req,
                HttpResponse::Ok()
                    .json(serde_json::json!({"status": "ok"}))
                    .map_into_right_body(),
            ));
        }
        _ => {}
    }

    // Handshake flow (InitialRequest, InitialResponse, General)
    // Extract correlation nonce for the pending response
    let nonce = auth_msg.initial_nonce.clone().unwrap_or_default();

    // Register pending before feeding to ensure we catch the response
    let rx = transport.register_pending(nonce.clone()).await;

    // Feed the incoming message to the Peer's subscription channel
    transport.feed_incoming(auth_msg).await.map_err(|e| {
        error!("Failed to feed handshake message to Peer: {}", e);
        e
    })?;

    // Trigger Peer processing (lock briefly, drop before awaiting channel)
    {
        let mut peer_guard = peer.lock().await;
        peer_guard.process_pending().await.map_err(|e| {
            error!("Peer processing failed during handshake: {}", e);
            AuthMiddlewareError::BsvSdk(e)
        })?;
    }

    // Wait for the signed response with a timeout
    let response_msg = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| {
            error!("Handshake response timed out after 30s");
            AuthMiddlewareError::Transport("handshake response timed out".to_string())
        })?
        .map_err(|_| {
            error!("Handshake response channel dropped");
            AuthMiddlewareError::Transport("handshake response channel dropped".to_string())
        })?;

    debug!(
        "Handshake response ready: identity_key={}",
        response_msg.identity_key
    );

    // Build HTTP response with auth headers from the signed message
    let mut response = HttpResponse::Ok();

    response.insert_header(("x-bsv-auth-version", response_msg.version.as_str()));
    response.insert_header((
        "x-bsv-auth-identity-key",
        response_msg.identity_key.as_str(),
    ));

    if let Some(ref nonce_val) = response_msg.nonce {
        response.insert_header(("x-bsv-auth-nonce", nonce_val.as_str()));
    }

    if let Some(ref your_nonce_val) = response_msg.your_nonce {
        response.insert_header(("x-bsv-auth-your-nonce", your_nonce_val.as_str()));
    }

    if let Some(ref sig_bytes) = response_msg.signature {
        response.insert_header(("x-bsv-auth-signature", hex::encode(sig_bytes)));
    }

    // Return the AuthMessage JSON as the response body
    let http_response = response.json(&response_msg);

    Ok(ServiceResponse::new(
        http_req,
        http_response.map_into_right_body(),
    ))
}

// ---------------------------------------------------------------------------
// Response signing handler
// ---------------------------------------------------------------------------

/// Buffer the handler response, sign it via the Peer, and return with
/// `x-bsv-auth-*` headers appended.
///
/// Preserves the original response status code and headers through buffering.
async fn handle_response_signing<B, W>(
    service_resp: ServiceResponse<B>,
    peer: Arc<tokio::sync::Mutex<Peer<W>>>,
    transport: Arc<ActixTransport>,
    request_headers: &crate::helpers::AuthHeaders,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    B: MessageBody + 'static,
    W: WalletInterface + 'static,
{
    // 1. Extract response parts for buffering
    let status = service_resp.status();
    let response_headers = service_resp.headers().clone();
    let request = service_resp.request().clone();

    // 2. Buffer the response body
    let body_bytes = actix_web::body::to_bytes(service_resp.into_body())
        .await
        .map_err(|_| {
            actix_web::error::ErrorInternalServerError("failed to buffer response body")
        })?;

    // 3. Serialize response payload for signing
    let request_nonce_bytes = BASE64
        .decode(&request_headers.request_id)
        .unwrap_or_default();
    let response_payload = crate::payload::serialize_from_http_response(
        &request_nonce_bytes,
        status,
        &response_headers,
        &body_bytes,
    );

    // 4. Look up session to get the peer_nonce for correlation.
    //    The Peer's send_message sets your_nonce = session.peer_nonce on the
    //    outgoing message. We must register_pending with that same value so
    //    the transport can correlate the response.
    let rx = {
        let peer_guard = peer.lock().await;
        let session = peer_guard
            .session_manager()
            .get_session_by_identifier(&request_headers.identity_key)
            .ok_or_else(|| {
                error!(
                    "No session found for identity_key={} during response signing",
                    request_headers.identity_key
                );
                AuthMiddlewareError::Transport(format!(
                    "no session for identity_key: {}",
                    request_headers.identity_key
                ))
            })?;
        let peer_nonce = session.peer_nonce.clone();
        drop(peer_guard);
        transport.register_pending(peer_nonce).await
    };

    // 5. Sign response via Peer (lock briefly, drop before awaiting channel)
    {
        let mut peer_guard = peer.lock().await;
        peer_guard
            .send_message(&request_headers.identity_key, response_payload)
            .await
            .map_err(|e| {
                error!("Peer response signing failed: {}", e);
                AuthMiddlewareError::BsvSdk(e)
            })?;
    }

    // 6. Wait for signed response with timeout
    let signed_msg = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| {
            error!("Response signing timed out after 30s");
            actix_web::error::ErrorRequestTimeout("response signing timeout")
        })?
        .map_err(|_| {
            error!("Response signing channel dropped");
            actix_web::error::ErrorInternalServerError("response signing channel dropped")
        })?;

    debug!(
        "Response signed for identity_key={}",
        signed_msg.identity_key
    );

    // 7. Build final response preserving original status and headers
    let mut final_response = HttpResponse::build(status);
    for (key, value) in response_headers.iter() {
        final_response.insert_header((key.clone(), value.clone()));
    }

    // 8. Append auth headers from the signed message
    final_response.insert_header(("x-bsv-auth-version", signed_msg.version.as_str()));
    final_response.insert_header(("x-bsv-auth-identity-key", signed_msg.identity_key.as_str()));

    if let Some(ref nonce_val) = signed_msg.nonce {
        final_response.insert_header(("x-bsv-auth-nonce", nonce_val.as_str()));
    }

    if let Some(ref your_nonce_val) = signed_msg.your_nonce {
        final_response.insert_header(("x-bsv-auth-your-nonce", your_nonce_val.as_str()));
    }

    if let Some(ref sig_bytes) = signed_msg.signature {
        final_response.insert_header(("x-bsv-auth-signature", hex::encode(sig_bytes)));
    }

    // Include the request ID so the client can reconstruct the signed payload.
    // The request_id was sent by the client in the request headers; the server
    // echoes it back so the client can verify the response signature.
    final_response.insert_header(("x-bsv-auth-request-id", request_headers.request_id.as_str()));

    Ok(ServiceResponse::new(
        request,
        final_response.body(body_bytes).map_into_right_body(),
    ))
}
