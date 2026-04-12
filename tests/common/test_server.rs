//! Test server factory mirroring TS testExpressServer.ts routes.
//!
//! Creates an Actix test server with AuthMiddlewareFactory wrapping all routes.
//! Each route uses the `Authenticated` extractor to validate auth was applied.

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::web;
use actix_web::{HttpRequest, HttpResponse};

use bsv::auth::certificates::master::MasterCertificate;
use bsv::auth::peer::Peer;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::interfaces::WalletInterface;
use bsv::wallet::interfaces::{Certificate, CertificateType, GetPublicKeyArgs};
use bsv_auth_actix_middleware::config::OnCertificatesReceived;
use bsv_auth_actix_middleware::transport::ActixTransport;
use bsv_auth_actix_middleware::{
    AuthMiddlewareConfigBuilder, AuthMiddlewareFactory, Authenticated,
};

use super::mock_wallet::MockWallet;

/// Create a test server and return its base URL.
///
/// The TestServer is leaked (kept alive for the process lifetime) since
/// `actix_test::TestServer` is not Send+Sync and cannot live in a static.
/// With `--test-threads=1` and a shared `OnceCell<String>`, the server
/// is created once and reused across all tests.
pub async fn create_test_server() -> String {
    let server_key = PrivateKey::from_random().expect("failed to generate server key");
    let server_wallet = MockWallet::new(server_key);
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(
        server_wallet.clone(),
        transport.clone(),
    )));

    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server_wallet)
        .allow_unauthenticated(false)
        .build()
        .expect("failed to build middleware config");

    let middleware = AuthMiddlewareFactory::new(config, peer.clone(), transport.clone()).await;

    let server = actix_test::start(move || {
        actix_web::App::new()
            .wrap(middleware.clone())
            .route("/", web::get().to(handler_root))
            .route(
                "/other-endpoint",
                web::post().to(handler_other_endpoint_post),
            )
            .route("/other-endpoint", web::get().to(handler_other_endpoint_get))
            .route("/error-500", web::post().to(handler_error_500))
            .route("/put-endpoint", web::put().to(handler_put))
            .route("/delete-endpoint", web::delete().to(handler_delete))
            .route("/large-upload", web::post().to(handler_large_upload))
            .route("/query-endpoint", web::get().to(handler_query))
            .route("/custom-headers", web::get().to(handler_custom_headers))
    });

    let base_url = format!("http://{}", server.addr());
    println!("Test server started at {}", base_url);

    // Leak the server to keep it alive for the process lifetime.
    // Tests run with --test-threads=1, so this is safe.
    std::mem::forget(server);

    base_url
}

// ---------------------------------------------------------------------------
// Route handlers (matching TS testExpressServer.ts)
// ---------------------------------------------------------------------------

async fn handler_root(_auth: Authenticated) -> HttpResponse {
    println!("[handler] GET / -- Hello, world!");
    HttpResponse::Ok().body("Hello, world!")
}

async fn handler_other_endpoint_post(_auth: Authenticated, body: web::Bytes) -> HttpResponse {
    println!(
        "[handler] POST /other-endpoint -- body length: {}",
        body.len()
    );
    HttpResponse::Ok().json(serde_json::json!({"message": "This is another endpoint."}))
}

async fn handler_other_endpoint_get(_auth: Authenticated) -> HttpResponse {
    println!("[handler] GET /other-endpoint");
    HttpResponse::Ok().body("This is another endpoint.")
}

async fn handler_error_500(_auth: Authenticated) -> HttpResponse {
    println!("[handler] POST /error-500 -- returning 500");
    HttpResponse::InternalServerError().json(serde_json::json!({
        "status": "error",
        "code": "ERR_BAD_THING",
        "description": "A bad thing has happened."
    }))
}

async fn handler_put(_auth: Authenticated, body: web::Bytes) -> HttpResponse {
    println!("[handler] PUT /put-endpoint -- body length: {}", body.len());
    HttpResponse::Ok().json(serde_json::json!({"status": "updated"}))
}

async fn handler_delete(_auth: Authenticated) -> HttpResponse {
    println!("[handler] DELETE /delete-endpoint");
    HttpResponse::Ok().json(serde_json::json!({"status": "deleted"}))
}

async fn handler_large_upload(_auth: Authenticated, body: web::Bytes) -> HttpResponse {
    println!(
        "[handler] POST /large-upload -- body length: {}",
        body.len()
    );
    HttpResponse::Ok().json(serde_json::json!({
        "status": "upload received",
        "size": body.len()
    }))
}

async fn handler_query(_auth: Authenticated, req: HttpRequest) -> HttpResponse {
    println!(
        "[handler] GET /query-endpoint -- query: {}",
        req.query_string()
    );
    HttpResponse::Ok().json(serde_json::json!({
        "status": "query received",
        "query": req.query_string()
    }))
}

async fn handler_custom_headers(_auth: Authenticated, req: HttpRequest) -> HttpResponse {
    println!("[handler] GET /custom-headers");
    for (name, value) in req.headers() {
        println!("  header: {} = {:?}", name, value);
    }
    HttpResponse::Ok().json(serde_json::json!({"status": "headers received"}))
}

// ---------------------------------------------------------------------------
// Certificate test server (mirroring TS testCertExpressServer.ts)
// ---------------------------------------------------------------------------

/// Context returned by create_cert_test_server for test assertions.
pub struct CertTestContext {
    /// Base URL of the cert test server (e.g., "http://127.0.0.1:54321").
    pub server_base_url: String,
    /// Shared storage for certificates received via the onCertificatesReceived callback.
    pub certs_received: Arc<tokio::sync::Mutex<Vec<Certificate>>>,
}

/// Create a certificate-protected test server mirroring TS testCertExpressServer.ts.
///
/// The server:
/// 1. Has a server wallet with a MasterCertificate issued by a known certifier
/// 2. Configures certificatesToRequest to request certs from clients
/// 3. Has an onCertificatesReceived callback that stores received certs
/// 4. Serves /cert-protected-endpoint that checks if certs were received
///
/// The TestServer is leaked (like create_test_server) for static lifetime.
pub async fn create_cert_test_server() -> CertTestContext {
    let server_key = PrivateKey::from_random().expect("failed to generate server key");
    let server_wallet = MockWallet::new(server_key);

    // Issue a MasterCertificate to the server wallet.
    // Uses the same certifier key as the TS test suite.
    let certifier_key =
        PrivateKey::from_hex("5a4d867377bd44eba1cecd0806c16f24e293f7e218c162b1177571edaeeaecef")
            .expect("failed to parse certifier key");
    let certifier_wallet = MockWallet::new(certifier_key);

    // Decode the base64 certificate type to [u8; 32]
    let cert_type_b64 = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=";
    let cert_type_bytes = base64_decode_32(cert_type_b64);
    let certificate_type = CertificateType(cert_type_bytes);

    let fields = HashMap::from([
        ("firstName".to_string(), "Alice".to_string()),
        ("lastName".to_string(), "Doe".to_string()),
    ]);

    // Get server wallet's public key for cert issuance
    let server_pub_key_result = server_wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                privileged: false,
                privileged_reason: None,
                for_self: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .expect("failed to get server public key");

    let master_cert = MasterCertificate::issue_certificate_for_subject(
        &certificate_type,
        &server_pub_key_result.public_key,
        fields,
        &certifier_wallet,
    )
    .await
    .expect("failed to issue server certificate");

    server_wallet.add_master_certificate(master_cert).await;
    println!("[cert_server] Server wallet seeded with MasterCertificate");

    // Configure certificatesToRequest (HashMap<String, Vec<String>>)
    // Keys are base64-encoded certificate type, values are field names to request
    let mut certs_to_request = bsv::auth::types::RequestedCertificateSet::default();
    certs_to_request
        .types
        .insert(cert_type_b64.to_string(), vec!["firstName".to_string()]);

    // Shared storage for received certificates
    let certs_received = Arc::new(tokio::sync::Mutex::new(Vec::<Certificate>::new()));
    let certs_received_cb = certs_received.clone();

    // Build the onCertificatesReceived callback
    let on_certs_received: OnCertificatesReceived =
        Box::new(move |sender_key: String, certs: Vec<Certificate>| {
            let certs_store = certs_received_cb.clone();
            Box::pin(async move {
                println!(
                    "[cert_server] Certificates received from {}: count={}",
                    sender_key,
                    certs.len()
                );
                let mut store = certs_store.lock().await;
                store.extend(certs);
            })
        });

    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(
        server_wallet.clone(),
        transport.clone(),
    )));

    let config = AuthMiddlewareConfigBuilder::new()
        .wallet(server_wallet)
        .allow_unauthenticated(false)
        .certificates_to_request(certs_to_request)
        .on_certificates_received(on_certs_received)
        .build()
        .expect("failed to build cert middleware config");

    let middleware = AuthMiddlewareFactory::new(config, peer.clone(), transport.clone()).await;
    let certs_received_route = certs_received.clone();

    let server = actix_test::start(move || {
        let certs_check = certs_received_route.clone();
        actix_web::App::new()
            .wrap(middleware.clone())
            .app_data(web::Data::new(certs_check.clone()))
            .route("/", web::get().to(handler_root))
            .route(
                "/cert-protected-endpoint",
                web::post().to(handler_cert_protected),
            )
    });

    let base_url = format!("http://{}", server.addr());
    println!(
        "[cert_server] Certificate test server started at {}",
        base_url
    );

    // Leak the server to keep it alive
    std::mem::forget(server);

    CertTestContext {
        server_base_url: base_url,
        certs_received,
    }
}

/// Handler for /cert-protected-endpoint.
///
/// Waits briefly for certificates to arrive (via the background listener),
/// then checks if any certificates were received. Returns 200 if yes, 401 if no.
async fn handler_cert_protected(
    _auth: Authenticated,
    body: web::Bytes,
    certs: web::Data<Arc<tokio::sync::Mutex<Vec<Certificate>>>>,
) -> HttpResponse {
    println!(
        "[handler] POST /cert-protected-endpoint -- body length: {}",
        body.len()
    );

    // Wait briefly for certificate callback to fire
    // (the callback runs in a spawned task and may not have completed yet)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let store = certs.lock().await;
    if !store.is_empty() {
        println!(
            "[handler] Certificates present: {} certs received",
            store.len()
        );
        HttpResponse::Ok().json(serde_json::json!({"message": "You have certs!"}))
    } else {
        println!("[handler] No certificates received yet");
        HttpResponse::Unauthorized().json(serde_json::json!({"message": "You must have certs!"}))
    }
}

/// Decode a base64 string to a [u8; 32] array.
/// Panics if the decoded length is not 32 bytes.
fn base64_decode_32(s: &str) -> [u8; 32] {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("failed to decode base64");
    let mut arr = [0u8; 32];
    assert_eq!(bytes.len(), 32, "expected 32 bytes, got {}", bytes.len());
    arr.copy_from_slice(&bytes);
    arr
}
