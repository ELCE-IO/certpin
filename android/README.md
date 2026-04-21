# CERTPIN Android SDK (Kotlin)

Native Android helper implementation of CERTPIN parsing and validation.

## API

- `CertPin.parse(record: String): CertPinPolicy`
- `CertPin.spkiFingerprintBase64(spkiDer: ByteArray): String`
- `CertPin.evaluate(record: String?, spkiDer: ByteArray, todayUtc: LocalDate): CertPinDecision`

## Behavior

- Strict tag parsing (`v`, `fp`, `exp`, `ttl`)
- Unknown tags fail parsing
- Expired policy resolves to `NoPolicy`
- Malformed policy resolves to `Malformed` when using `evaluate`
