# CERTPIN iOS SDK (Swift)

`CertPin` is a lightweight helper for enforcing the CERTPIN RFC logic.

## Includes

- Strict TXT parser (`v`, `fp`, `exp`, `ttl`)
- SPKI SHA-256 Base64 fingerprint helper
- Decision helper: `noPolicy`, `match`, `mismatch`, `malformed`

## Usage

```swift
import CertPin

let spkiDer: Data = ...
let txtRecord = "v=CERTPIN1; fp=..."
let decision = CertPin.evaluate(record: txtRecord, spkiDer: spkiDer)
```
