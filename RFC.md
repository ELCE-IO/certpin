# CERTPIN: DNS-Based Certificate Pinning via TXT Records

**Internet-Draft**  
**Status:** Proposed Standard  
**Version:** 00

## Abstract

This document defines **CERTPIN**, a lightweight mechanism for domain owners to publish trusted TLS certificate fingerprints via DNS TXT records (optionally protected with DNSSEC).  
Clients that support CERTPIN perform a **hard fail** when the presented certificate does not match the published fingerprint set.  
If no CERTPIN record exists, clients proceed with normal TLS validation (**No-Policy**).

This enforcement model is intentionally inspired by DMARC ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)).

## 1. Introduction

Existing certificate validation and revocation mechanisms have known operational weaknesses:

- **CRL** ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)): large and often stale
- **OCSP** ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)): frequently soft-fail and privacy-sensitive
- **OCSP Stapling** ([RFC 6066](https://www.rfc-editor.org/rfc/rfc6066)): server-dependent and not sufficient against routing/DNS compromise
- **DANE/TLSA** ([RFC 6698](https://www.rfc-editor.org/rfc/rfc6698)): strong design, limited broad adoption

CERTPIN takes a pragmatic path:

- Use existing DNS infrastructure
- Use a simple TXT record format
- Use strict client-side enforcement when policy is present

## 2. Terminology

- **CERTPIN Record:** A DNS TXT record at `_certpin.<domain>` containing certificate fingerprints.
- **Fingerprint:** SHA-256 hash of DER-encoded `SubjectPublicKeyInfo` (SPKI), Base64-encoded.
- **Hard Fail:** Connection is terminated immediately with no fallback.
- **No-Policy:** No valid CERTPIN record exists for the domain; client proceeds normally.
- **Pinned Domain:** A domain with a valid CERTPIN record.

## 3. Record Format

CERTPIN records are published as DNS TXT records at:

```text
_certpin.<domain>
```

### 3.1 Tag Definitions

| Tag | Required | Description |
|---|---|---|
| `v` | Yes | Protocol version. Must be `CERTPIN1`. |
| `fp` | Yes (one or more) | Base64 SHA-256 SPKI fingerprint. Multiple `fp` tags are allowed. |
| `exp` | No | Expiry date in ISO format: `YYYY-MM-DD`. After expiry, treat as No-Policy. |
| `ttl` | No | DNS TTL hint in seconds (informational). |

### 3.2 Wire-Value Syntax

```text
v=CERTPIN1; fp=<base64-sha256-spki>[; fp=<base64-sha256-spki> ...][; exp=YYYY-MM-DD][; ttl=<seconds>]
```

### 3.3 ABNF (informative)

```abnf
certpin-record = version sep fp *(sep fp) [sep exp] [sep ttl]

version        = "v=CERTPIN1"
fp             = "fp=" base64-value
exp            = "exp=" date
ttl            = "ttl=" 1*DIGIT
date           = 4DIGIT "-" 2DIGIT "-" 2DIGIT
sep            = *WSP ";" *WSP

; RFC 4648 base64 charset
base64-value   = 1*(ALPHA / DIGIT / "+" / "/" / "=")
```

### 3.4 Examples

Minimal:

```dns
_certpin.example.com. 3600 IN TXT "v=CERTPIN1; fp=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
```

Rotation window:

```dns
_certpin.example.com. 3600 IN TXT "v=CERTPIN1; fp=<current>; fp=<next>; exp=2026-12-31; ttl=3600"
```

## 4. Client Behavior

### 4.1 Lookup Procedure

1. Before or during TLS handshake, resolve `_certpin.<domain>` TXT.
2. If no record exists: **No-Policy** (normal TLS validation only).
3. If record exists but is malformed: **Hard Fail**.
4. If record exists and is syntactically valid: continue to fingerprint validation.

### 4.2 Validation Procedure

1. Extract server certificate from TLS handshake.
2. Compute SHA-256 over certificate SPKI (DER).
3. Base64-encode the result.
4. Compare against all `fp` values in the CERTPIN record.
5. If any `fp` matches: proceed.
6. If none match: **Hard Fail**.

### 4.3 Decision Table

| Condition | Result |
|---|---|
| No CERTPIN record | Proceed (No-Policy) |
| Record exists, cert matches `fp` | Proceed |
| Record exists, cert does not match | Hard Fail |
| Record exists, malformed | Hard Fail |
| Record expired (`exp` exceeded) | No-Policy |
| DNSSEC validation fails (when enforced) | Hard Fail |

### 4.4 DNSSEC

Clients **SHOULD** validate CERTPIN records using DNSSEC when available.  
If DNSSEC is configured for the domain and validation fails, client **MUST** hard fail.

If DNSSEC is unavailable, clients **SHOULD** use multi-resolver consistency checks before trusting a new fingerprint set.

## 5. Certificate Rotation

Domain owners **MUST** publish new certificate fingerprints before rotation:

1. Compute fingerprint for the new certificate.
2. Add a new `fp` to the existing CERTPIN record.
3. Wait for DNS propagation/TTL window.
4. Rotate certificate on server.
5. Remove deprecated `fp` after old cert retirement.

During overlap, multiple `fp` tags are valid and expected.

## 6. Bootstrap and First-Connection Trust

DNS-only trust has first-connection risk. CERTPIN mitigations:

### 6.1 Application Bootstrap List

Applications **MAY** ship bootstrap pins for critical domains.  
Bootstrap pins take precedence on first connection.

### 6.2 Multi-Resolver Consensus

Clients **SHOULD** query at least two independent resolvers.  
Conflicting answers should hard fail unless resolved by bootstrap trust.

### 6.3 Cache Pinning

After successful validation, clients **SHOULD** cache accepted fingerprints for TTL duration and treat conflicting new DNS answers as suspicious.

## 7. Interaction with Existing Mechanisms

| Mechanism | CERTPIN Interaction |
|---|---|
| CA trust store | Independent. CA validation still required. |
| OCSP / CRL | Complementary revocation layer. |
| OCSP stapling | Complementary. Identity pinning + revocation proof. |
| HPKP ([RFC 7469](https://www.rfc-editor.org/rfc/rfc7469)) | CERTPIN is DNS-based and operationally simpler. |
| DANE/TLSA | Conceptually similar; CERTPIN uses TXT for compatibility. |
| Certificate Transparency | Complementary. CT detects issuance; CERTPIN enforces acceptance. |

## 8. Operational Guidance

### 8.1 For Domain Owners

- Keep at least two fingerprints during rotation (`current` + `next`)
- Set `exp` aligned with certificate lifecycle
- Enable DNSSEC where possible
- Monitor CERTPIN records like MX/DKIM-grade production config

### 8.2 For CDNs / Multi-Certificate Domains

- Publish all active edge certificate fingerprints
- Automate record generation and rollout
- Integrate CERTPIN into certificate lifecycle tooling

### 8.3 For Client Developers

- Perform CERTPIN lookup pre-handshake or in parallel
- Do not persist failed validation results as trusted state
- Log hard failures with domain, observed fingerprint, and timestamp

## 9. Security Considerations

### 9.1 DNS Poisoning

Without DNSSEC, attackers may inject malicious CERTPIN answers.  
Mitigations: DNSSEC, multi-resolver checks, bootstrap pins.

### 9.2 BGP / Path Hijacking

Attackers may attempt to control both DNS and TLS paths.  
Bootstrap pins + cache pinning + resolver diversity raise attack cost materially.

### 9.3 Misconfiguration Risk

Incorrect CERTPIN values can cause global hard failures.  
Operators should treat CERTPIN changes as high-risk production changes.

### 9.4 No Soft-Fail by Design

CERTPIN intentionally does not define soft-fail when policy exists.

## 10. Privacy Considerations

CERTPIN lookups are DNS lookups.  
Clients **SHOULD** prefer encrypted DNS transports (DoH/DoT) where feasible.

## 11. IANA Considerations

No new IANA registry is requested by this document.

## 12. Acknowledgements

CERTPIN draws inspiration from DMARC ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)), DANE ([RFC 6698](https://www.rfc-editor.org/rfc/rfc6698)), and HPKP ([RFC 7469](https://www.rfc-editor.org/rfc/rfc7469)).

## Appendix A: Quick Client Pseudo-Code

```python
fingerprint = base64(sha256(spki(server_cert)))
record = dns_txt("_certpin." + domain)

if record is None:
    return PROCEED  # No-Policy

if not record.is_valid:
    return HARD_FAIL

if fingerprint in record.fp:
    return PROCEED

return HARD_FAIL
```

---

**Draft Author:** Martin Jacobus de Klerk  
**Created:** April 2026  
**Note:** Individual submission; not an IETF-approved RFC.
