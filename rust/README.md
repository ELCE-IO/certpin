# CERTPIN Rust SDK

Reference Rust helper crate implementing strict CERTPIN record parsing and decision helpers.

## Core functions

- `parse_record(record: &str) -> Result<CertPinPolicy, CertPinError>`
- `spki_fingerprint_base64(spki_der: &[u8]) -> String`
- `evaluate(record: Option<&str>, spki_der: &[u8], today_utc: NaiveDate) -> CertPinDecision`
- `evaluate_now_utc(record: Option<&str>, spki_der: &[u8]) -> CertPinDecision`

The crate intentionally excludes DNS and TLS transport logic, so it can be delegated to from any networking stack.
