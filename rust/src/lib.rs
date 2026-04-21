use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{NaiveDate, Utc};
use sha2::{Digest, Sha256};
use std::fmt;

pub const EXPECTED_VERSION: &str = "CERTPIN1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPinPolicy {
    pub version: String,
    pub fingerprints: Vec<String>,
    pub exp: Option<NaiveDate>,
    pub ttl_seconds: Option<u32>,
}

impl CertPinPolicy {
    pub fn is_expired(&self, today_utc: NaiveDate) -> bool {
        match self.exp {
            Some(exp) => today_utc > exp,
            None => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertPinDecision {
    NoPolicy,
    Match,
    Mismatch,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertPinError {
    EmptyRecord,
    MalformedTag(String),
    UnknownTag(String),
    DuplicateTag(String),
    InvalidVersion(String),
    MissingVersion,
    MissingFingerprint,
    InvalidFingerprint(String),
    InvalidExpiration(String),
    InvalidTtl(String),
}

impl fmt::Display for CertPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertPinError::EmptyRecord => write!(f, "record is empty"),
            CertPinError::MalformedTag(raw) => write!(f, "malformed tag: {raw}"),
            CertPinError::UnknownTag(tag) => write!(f, "unknown tag: {tag}"),
            CertPinError::DuplicateTag(tag) => write!(f, "duplicate tag: {tag}"),
            CertPinError::InvalidVersion(value) => write!(f, "invalid version: {value}"),
            CertPinError::MissingVersion => write!(f, "missing required tag: v"),
            CertPinError::MissingFingerprint => write!(f, "missing required tag: fp"),
            CertPinError::InvalidFingerprint(value) => write!(f, "invalid fingerprint: {value}"),
            CertPinError::InvalidExpiration(value) => write!(f, "invalid expiration date: {value}"),
            CertPinError::InvalidTtl(value) => write!(f, "invalid ttl value: {value}"),
        }
    }
}

impl std::error::Error for CertPinError {}

pub fn parse_record(record: &str) -> Result<CertPinPolicy, CertPinError> {
    let normalized = normalize_record(record);
    if normalized.is_empty() {
        return Err(CertPinError::EmptyRecord);
    }

    let mut version: Option<String> = None;
    let mut fingerprints: Vec<String> = Vec::new();
    let mut exp: Option<NaiveDate> = None;
    let mut ttl_seconds: Option<u32> = None;

    for raw_part in normalized.split(';') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }

        let Some(sep_idx) = part.find('=') else {
            return Err(CertPinError::MalformedTag(part.to_string()));
        };

        let key = part[..sep_idx].trim().to_ascii_lowercase();
        let value = part[sep_idx + 1..].trim();
        if value.is_empty() {
            return Err(CertPinError::MalformedTag(part.to_string()));
        }

        match key.as_str() {
            "v" => {
                if version.is_some() {
                    return Err(CertPinError::DuplicateTag("v".to_string()));
                }
                if value != EXPECTED_VERSION {
                    return Err(CertPinError::InvalidVersion(value.to_string()));
                }
                version = Some(value.to_string());
            }
            "fp" => {
                let decoded = STANDARD
                    .decode(value)
                    .map_err(|_| CertPinError::InvalidFingerprint(value.to_string()))?;
                if decoded.len() != 32 {
                    return Err(CertPinError::InvalidFingerprint(value.to_string()));
                }
                fingerprints.push(STANDARD.encode(decoded));
            }
            "exp" => {
                if exp.is_some() {
                    return Err(CertPinError::DuplicateTag("exp".to_string()));
                }
                let parsed = NaiveDate::parse_from_str(value, "%Y-%m-%d")
                    .map_err(|_| CertPinError::InvalidExpiration(value.to_string()))?;
                exp = Some(parsed);
            }
            "ttl" => {
                if ttl_seconds.is_some() {
                    return Err(CertPinError::DuplicateTag("ttl".to_string()));
                }
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| CertPinError::InvalidTtl(value.to_string()))?;
                if parsed == 0 {
                    return Err(CertPinError::InvalidTtl(value.to_string()));
                }
                ttl_seconds = Some(parsed);
            }
            _ => return Err(CertPinError::UnknownTag(key)),
        }
    }

    let version = version.ok_or(CertPinError::MissingVersion)?;
    if fingerprints.is_empty() {
        return Err(CertPinError::MissingFingerprint);
    }

    Ok(CertPinPolicy {
        version,
        fingerprints,
        exp,
        ttl_seconds,
    })
}

pub fn spki_fingerprint_base64(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    STANDARD.encode(digest)
}

pub fn evaluate(record: Option<&str>, spki_der: &[u8], today_utc: NaiveDate) -> CertPinDecision {
    let Some(raw_record) = record else {
        return CertPinDecision::NoPolicy;
    };

    if normalize_record(raw_record).is_empty() {
        return CertPinDecision::NoPolicy;
    }

    let policy = match parse_record(raw_record) {
        Ok(policy) => policy,
        Err(_) => return CertPinDecision::Malformed,
    };

    if policy.is_expired(today_utc) {
        return CertPinDecision::NoPolicy;
    }

    let presented = spki_fingerprint_base64(spki_der);
    if policy.fingerprints.iter().any(|fp| fp == &presented) {
        CertPinDecision::Match
    } else {
        CertPinDecision::Mismatch
    }
}

pub fn evaluate_now_utc(record: Option<&str>, spki_der: &[u8]) -> CertPinDecision {
    evaluate(record, spki_der, Utc::now().date_naive())
}

fn normalize_record(record: &str) -> String {
    let trimmed = record.trim();
    if trimmed.starts_with('\"') && trimmed.ends_with('\"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_record() {
        let spki = b"spki";
        let fp = spki_fingerprint_base64(spki);
        let record = format!("v=CERTPIN1; fp={fp}; exp=2026-12-31; ttl=3600");

        let policy = parse_record(&record).unwrap();
        assert_eq!(policy.version, "CERTPIN1");
        assert_eq!(policy.fingerprints, vec![fp]);
        assert_eq!(policy.ttl_seconds, Some(3600));
        assert_eq!(policy.exp, Some(NaiveDate::from_ymd_opt(2026, 12, 31).unwrap()));
    }

    #[test]
    fn evaluate_match() {
        let spki = b"spki";
        let fp = spki_fingerprint_base64(spki);
        let record = format!("v=CERTPIN1; fp={fp}");
        let result = evaluate(Some(&record), spki, NaiveDate::from_ymd_opt(2026, 4, 21).unwrap());
        assert_eq!(result, CertPinDecision::Match);
    }

    #[test]
    fn evaluate_expired_no_policy() {
        let spki = b"spki";
        let fp = spki_fingerprint_base64(spki);
        let record = format!("v=CERTPIN1; fp={fp}; exp=2020-01-01");
        let result = evaluate(Some(&record), spki, NaiveDate::from_ymd_opt(2026, 4, 21).unwrap());
        assert_eq!(result, CertPinDecision::NoPolicy);
    }

    #[test]
    fn malformed_is_detected() {
        let result = evaluate(Some("v=CERTPIN1"), b"spki", NaiveDate::from_ymd_opt(2026, 4, 21).unwrap());
        assert_eq!(result, CertPinDecision::Malformed);
    }
}
