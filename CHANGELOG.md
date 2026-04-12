# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-12

Parity pass against the authoritative TypeScript reference
(`@bsv/auth-express-middleware`), plus a full dependency refresh.

### Breaking

- **`bsv-sdk` bumped from `0.1.75` to `0.2`.** Pre-1.0 minor bumps are breaking
  under Cargo SemVer. The only source-visible consequence for this crate is
  that `CertificateResult.keyring` is now
  `Option<HashMap<String, String>>`; downstream code that constructs or
  destructures this field must adjust.
- **401 unauthorized response body is now TS-parity.** The code literal
  changed from `ERR_AUTHENTICATION` to `UNAUTHORIZED`, and the body field
  changed from `description` to `message` (value
  `"Mutual-authentication failed!"`). Clients parsing the prior format must
  update.
- **408 certificate-timeout response body** now uses `message` instead of
  `description`. Code literal (`CERTIFICATE_TIMEOUT`) and status are
  unchanged.
- **Response-signing failures surface as `ERR_RESPONSE_SIGNING_FAILED`**
  (500). Previously mapped to the generic `ERR_INTERNAL_SERVER_ERROR`.
- **Empty `certificateResponse` messages now return a 400** with the minimal
  body `{"status":"No certificates provided"}` (matches TS exactly).
  Previously forwarded to peer dispatch and failed further along.

### Added

- `AuthMiddlewareConfig::log_level: Option<tracing::Level>` and matching
  builder method. Defaults to `None` (caller owns `tracing` setup by
  default -- idiomatic library behavior).
- `AuthMiddlewareConfig::try_init_tracing()` helper that installs a
  `tracing_subscriber` at the configured level, or no-ops when `log_level`
  is `None`.
- `ActixTransport::with_timeout(Duration)` constructor,
  `pending_timeout()` accessor, and `transport::DEFAULT_PENDING_TIMEOUT`
  (30 s). Each pending message registration now spawns a timeout task
  that cleans up the entry if the peer never responds, and is aborted on
  successful delivery. Mirrors TS `openNextHandlerTimeouts` behaviour.
- `AuthMiddlewareError::Unauthorized` and
  `AuthMiddlewareError::ResponseSigningFailed(String)` variants.
- 14 new regression tests covering the above (106 total, up from 92).

### Changed

- All direct dependencies tightened to latest stable minor versions
  (`actix-web 4.13`, `actix-http 3.12`, `tokio 1.51`, `thiserror 2.0`,
  `tracing 0.1.44`, `serde 1.0.228`, `serde_json 1.0.149`, `dashmap 6.1`,
  among others).
- `reqwest` dev-dependency bumped to `0.13`.
- `tracing-subscriber` promoted from dev-dependency to main dependency to
  support `try_init_tracing()`.
- Certificate integration tests refactored to create per-test isolated
  servers. The previous shared-`OnceCell` pattern raced under `bsv-sdk`
  0.2's stricter concurrent-handshake semantics.

### Fixed

- `tests/common/mock_wallet.rs` updated for the `bsv-sdk` 0.2
  `CertificateResult.keyring: Option<_>` signature.

## [0.1.2] - 2026-03-19

### Fixed

- **Eliminated Peer Mutex deadlock under concurrent requests** -- Auth
  verification now calls `peer.dispatch_message()` directly for each request
  instead of feeding messages through a shared channel and draining with
  `process_pending()`. This prevents one request from consuming another's
  verification message and eliminates serialization of all concurrent requests.

- **Increased transport channel buffer** -- from 32 to 1024 to prevent
  `feed_incoming().await` from blocking when many handshake messages queue up.

### Changed

- Bumped `bsv-sdk` dependency to `0.1.74` (Peer deadlock fix).

## [0.1.1] - 2026-03-10

### Fixed
- **Varint encoding for negative values** -- negative values now encode as two's complement unsigned 64-bit (9-byte varint with `0xFF` prefix), matching TS SDK `writeVarIntNum(-1)` behavior. Previously wrote a single `0x00` byte, causing auth payload mismatch and handshake failure.
- **Auth payload serialization** -- corrected empty query string and absent body encoding to use 9-byte varint(-1) sentinel instead of single zero byte, aligning with TS SDK wire format
- **Debug logging in `build_auth_message`** -- added detailed tracing for method, path, query, body length, nonces, and payload size to aid handshake debugging

### Changed
- Bumped `bsv-sdk` dependency from `0.1.3` to `0.1.72`
- Bumped MSRV from 1.87 to 1.88

## [0.1.0] - 2026-03-08

### Added

- BRC-31 (Authrite) mutual authentication middleware for Actix-web
- `AuthMiddlewareFactory` with Transform/Service pattern for request/response auth
- `AuthMiddlewareConfig` builder with wallet, session manager, and certificate options
- `Authenticated` extractor for accessing verified identity in handlers
- `CertificateGate` for certificate exchange flow
- `ActixTransport` implementing BSV SDK Transport trait
- `allowUnauthenticated` mode for optional auth on endpoints
- Integration with `tracing` crate for structured logging
