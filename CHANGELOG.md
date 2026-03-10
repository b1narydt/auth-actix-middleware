# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
