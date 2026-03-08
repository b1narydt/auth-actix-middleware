# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
