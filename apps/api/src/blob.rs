use std::time::Duration;

use axum::body::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{Method, Url, header};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::auth::hex_encode;

const SERVICE: &str = "s3";
const REQUEST_TERMINATOR: &str = "aws4_request";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(crate) struct S3BlobStore {
    client: reqwest::Client,
    endpoint: Url,
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
}

impl S3BlobStore {
    pub(crate) fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> Result<Self, BlobStoreError> {
        let endpoint = Url::parse(endpoint).map_err(|_| BlobStoreError::Configuration)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
            || bucket.is_empty()
            || bucket.contains('/')
            || region.is_empty()
            || access_key_id.is_empty()
            || secret_access_key.is_empty()
        {
            return Err(BlobStoreError::Configuration);
        }
        let client = reqwest::Client::builder()
            .timeout(CLIENT_TIMEOUT)
            .build()
            .map_err(|_| BlobStoreError::Configuration)?;
        Ok(Self {
            client,
            endpoint,
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            access_key_id: access_key_id.to_owned(),
            secret_access_key: secret_access_key.to_owned(),
        })
    }

    pub(crate) async fn ready(&self) -> Result<(), BlobStoreError> {
        self.request(Method::HEAD, None, Bytes::new()).await?;
        Ok(())
    }

    pub(crate) async fn put(&self, key: &str, bytes: Bytes) -> Result<(), BlobStoreError> {
        self.request(Method::PUT, Some(key), bytes).await?;
        Ok(())
    }

    pub(crate) async fn get(&self, key: &str) -> Result<Bytes, BlobStoreError> {
        self.request(Method::GET, Some(key), Bytes::new()).await
    }

    pub(crate) async fn delete(&self, key: &str) -> Result<(), BlobStoreError> {
        self.request(Method::DELETE, Some(key), Bytes::new())
            .await?;
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        key: Option<&str>,
        body: Bytes,
    ) -> Result<Bytes, BlobStoreError> {
        let canonical_uri = self.canonical_uri(key)?;
        let url = self.request_url(&canonical_uri)?;
        let host = host_header(&url)?;
        let payload_hash = hex_encode(&Sha256::digest(&body));
        let now = OffsetDateTime::now_utc();
        let date = format!(
            "{:04}{:02}{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        );
        let amz_date = format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );
        let authorization = authorization_header(SigningInput {
            method: method.as_str(),
            canonical_uri: &canonical_uri,
            host: &host,
            payload_hash: &payload_hash,
            amz_date: &amz_date,
            date: &date,
            region: &self.region,
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
        })?;

        let mut request = self
            .client
            .request(method, url)
            .header(header::HOST, host)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", amz_date)
            .header(header::AUTHORIZATION, authorization);
        if !body.is_empty() {
            request = request
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(body);
        }

        let response = request.send().await.map_err(|_| BlobStoreError::Request)?;
        if !response.status().is_success() {
            return Err(BlobStoreError::Status(response.status().as_u16()));
        }
        response.bytes().await.map_err(|_| BlobStoreError::Request)
    }

    fn canonical_uri(&self, key: Option<&str>) -> Result<String, BlobStoreError> {
        if let Some(key) = key {
            if key.is_empty()
                || key.starts_with('/')
                || key.contains("..")
                || !key.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.')
                })
            {
                return Err(BlobStoreError::InvalidKey);
            }
            Ok(format!("/{}/{}", self.bucket, key))
        } else {
            Ok(format!("/{}", self.bucket))
        }
    }

    fn request_url(&self, canonical_uri: &str) -> Result<Url, BlobStoreError> {
        let mut url = self.endpoint.clone();
        url.set_path(canonical_uri);
        Ok(url)
    }
}

struct SigningInput<'a> {
    method: &'a str,
    canonical_uri: &'a str,
    host: &'a str,
    payload_hash: &'a str,
    amz_date: &'a str,
    date: &'a str,
    region: &'a str,
    access_key_id: &'a str,
    secret_access_key: &'a str,
}

fn authorization_header(input: SigningInput<'_>) -> Result<String, BlobStoreError> {
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        input.host, input.payload_hash, input.amz_date
    );
    let canonical_request = format!(
        "{}\n{}\n\n{}\n{}\n{}",
        input.method, input.canonical_uri, canonical_headers, signed_headers, input.payload_hash
    );
    let canonical_request_hash = hex_encode(&Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!(
        "{}/{}/{}/{}",
        input.date, input.region, SERVICE, REQUEST_TERMINATOR
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{}\n{}\n{}",
        input.amz_date, credential_scope, canonical_request_hash
    );

    let date_key = hmac(
        format!("AWS4{}", input.secret_access_key).as_bytes(),
        input.date.as_bytes(),
    )?;
    let region_key = hmac(&date_key, input.region.as_bytes())?;
    let service_key = hmac(&region_key, SERVICE.as_bytes())?;
    let signing_key = hmac(&service_key, REQUEST_TERMINATOR.as_bytes())?;
    let signature = hex_encode(&hmac(&signing_key, string_to_sign.as_bytes())?);

    Ok(format!(
        "{ALGORITHM} Credential={}/{}, SignedHeaders={}, Signature={}",
        input.access_key_id, credential_scope, signed_headers, signature
    ))
}

fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], BlobStoreError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| BlobStoreError::Signing)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn host_header(url: &Url) -> Result<String, BlobStoreError> {
    let host = url.host_str().ok_or(BlobStoreError::Configuration)?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[derive(Debug, Error)]
pub(crate) enum BlobStoreError {
    #[error("S3-compatible object store configuration is invalid")]
    Configuration,
    #[error("S3-compatible object store key is invalid")]
    InvalidKey,
    #[error("S3-compatible object store signing failed")]
    Signing,
    #[error("S3-compatible object store request failed")]
    Request,
    #[error("S3-compatible object store returned HTTP status {0}")]
    Status(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_style_urls_keep_bucket_and_opaque_key_in_the_path() {
        let store = S3BlobStore::new(
            "http://garage:3900",
            "garage",
            "safeory-dev",
            "access",
            "secret",
        )
        .expect("store");
        let key = "accounts/00000000-0000-0000-0000-000000000001/objects/00000000-0000-0000-0000-000000000002/00000000-0000-0000-0000-000000000003";
        let uri = store.canonical_uri(Some(key)).expect("canonical uri");
        assert_eq!(uri, format!("/safeory-dev/{key}"));
        let url = store.request_url(&uri).expect("url");
        assert_eq!(
            url.as_str(),
            format!("http://garage:3900/safeory-dev/{key}")
        );
        assert_eq!(host_header(&url).expect("host"), "garage:3900");
    }

    #[test]
    fn signer_is_deterministic_and_payload_bound() {
        fn input(payload_hash: &str) -> SigningInput<'_> {
            SigningInput {
                method: "PUT",
                canonical_uri: "/safeory-dev/accounts/a/objects/b/c",
                host: "garage:3900",
                payload_hash,
                amz_date: "20260919T101500Z",
                date: "20260919",
                region: "garage",
                access_key_id: "GKEXAMPLE",
                secret_access_key: "example-secret",
            }
        }
        let empty = hex_encode(&Sha256::digest([]));
        let data = hex_encode(&Sha256::digest(b"ciphertext"));
        let first = authorization_header(input(&empty)).expect("signature");
        let repeat = authorization_header(input(&empty)).expect("repeat signature");
        let changed = authorization_header(input(&data)).expect("changed signature");
        assert_eq!(first, repeat);
        assert_ne!(first, changed);
        assert!(
            first.starts_with(
                "AWS4-HMAC-SHA256 Credential=GKEXAMPLE/20260919/garage/s3/aws4_request"
            )
        );
        assert!(first.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn endpoint_and_key_validation_fail_closed() {
        assert!(S3BlobStore::new("file:///tmp", "garage", "bucket", "a", "b").is_err());
        let store =
            S3BlobStore::new("http://garage:3900", "garage", "bucket", "a", "b").expect("store");
        assert!(store.canonical_uri(Some("../secret")).is_err());
        assert!(store.canonical_uri(Some("contains space")).is_err());
    }
}
