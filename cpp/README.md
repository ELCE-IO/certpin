# CERTPIN C++ SDK

Reference C++ helper implementation for CERTPIN.

## Build

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
```

This SDK uses OpenSSL (`OpenSSL::Crypto`) for SHA-256 and Base64 operations.

## API

- `certpin::ParseRecord(...)`
- `certpin::SpkiFingerprintBase64(...)`
- `certpin::Evaluate(...)`
- `certpin::UtcToday()`
