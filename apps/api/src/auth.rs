use axum::http::{HeaderMap, header::AUTHORIZATION};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DEVICE_TOKEN_DOMAIN: &[u8] = b"safeory:v1:device-bearer\0";
const REGISTRATION_TOKEN_DOMAIN: &[u8] = b"safeory:v1:deployment-registration\0";
const DEVICE_TOKEN_PREFIX: &str = "sfo_dev_v1_";

#[derive(Debug, Error)]
pub(crate) enum AuthMaterialError {
    #[error("secure random generation failed")]
    Random,
}

pub(crate) fn generate_device_token() -> Result<(String, [u8; 32]), AuthMaterialError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthMaterialError::Random)?;
    let token = format!("{DEVICE_TOKEN_PREFIX}{}", hex_encode(&bytes));
    let hash = device_token_hash(&token);
    Ok((token, hash))
}

pub(crate) fn device_token_hash(token: &str) -> [u8; 32] {
    hash_secret(DEVICE_TOKEN_DOMAIN, token)
}

pub(crate) fn is_valid_device_token(token: &str) -> bool {
    let Some(material) = token.strip_prefix(DEVICE_TOKEN_PREFIX) else {
        return false;
    };
    material.len() == 64
        && material
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn registration_token_hash(token: &str) -> [u8; 32] {
    hash_secret(REGISTRATION_TOKEN_DOMAIN, token)
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}

pub(crate) fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub(crate) fn parse_public_key_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    let bytes = value.as_bytes();
    for (index, slot) in output.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Some(output)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hash_secret(domain: &[u8], secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn generated_device_token_contains_256_bits_of_random_material() {
        let (first, first_hash) = generate_device_token().expect("first token");
        let (second, second_hash) = generate_device_token().expect("second token");

        assert!(first.starts_with(DEVICE_TOKEN_PREFIX));
        assert_eq!(first.len(), DEVICE_TOKEN_PREFIX.len() + 64);
        assert_ne!(first, second);
        assert_ne!(first_hash, second_hash);
        assert_eq!(first_hash, device_token_hash(&first));
    }

    #[test]
    fn token_hash_domains_are_separate() {
        let token = "same-high-entropy-input";
        assert_ne!(device_token_hash(token), registration_token_hash(token));
    }

    #[test]
    fn device_token_format_requires_canonical_256_bit_material() {
        assert!(is_valid_device_token(&format!(
            "{DEVICE_TOKEN_PREFIX}{}",
            "ab".repeat(32)
        )));
        assert!(!is_valid_device_token(&format!(
            "{DEVICE_TOKEN_PREFIX}{}",
            "AB".repeat(32)
        )));
        assert!(!is_valid_device_token(&format!(
            "{DEVICE_TOKEN_PREFIX}{}",
            "ab".repeat(31)
        )));
    }

    #[test]
    fn bearer_parser_rejects_whitespace_and_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), None);

        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer a b"));
        assert_eq!(bearer_token(&headers), None);

        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(bearer_token(&headers), Some("abc"));
    }

    #[test]
    fn public_key_parser_requires_exactly_32_bytes() {
        let key = [0xabu8; 32];
        assert_eq!(parse_public_key_hex(&hex_encode(&key)), Some(key));
        assert!(parse_public_key_hex("ab").is_none());
        assert!(parse_public_key_hex(&"gg".repeat(32)).is_none());
    }
}
