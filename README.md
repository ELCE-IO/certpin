# CERTPIN SDKs

This repository contains a draft CERTPIN specification and reference helper SDKs.

## Folders

- `ios/` - Swift package for native iOS/macOS clients
- `android/` - Kotlin helper for native Android clients
- `rust/` - Rust crate
- `cpp/` - C++ library (OpenSSL-backed hashing)

All SDKs implement the same core helper behavior:

- Parse CERTPIN TXT record:
  - `v=CERTPIN1` required
  - one or more `fp=` tags required
  - `exp=` and `ttl=` optional
- Validate fingerprint list syntax strictly
- Compute `SHA-256(SPKI-DER)` and Base64 encode
- Evaluate policy outcomes:
  - no policy
  - match
  - mismatch
  - malformed record

These are intentionally low-level helpers designed for reliable delegation from higher-level networking/TLS code.
