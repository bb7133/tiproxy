// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bounded HTTP client for topology, health, and metrics reads.

use std::fmt;
use std::time::Duration;

use control_plane::OwnerToken;
use futures_util::StreamExt;
use reqwest::{Certificate, Client, Identity, StatusCode, Url};
use thiserror::Error;

/// Maximum allowed response-body bound.
pub const MAX_HTTP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum accepted dependency URL byte length.
pub const MAX_HTTP_URL_BYTES: usize = 8 * 1024;
const MAX_HTTP_TIMEOUT: Duration = Duration::from_secs(300);

/// Validated HTTP mTLS material.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpTlsConfig {
    ca_certificate_pem: Vec<u8>,
    identity_pem: Option<Vec<u8>>,
}

impl fmt::Debug for HttpTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTlsConfig")
            .field("ca_certificate_pem", &"<redacted>")
            .field("client_identity_configured", &self.identity_pem.is_some())
            .finish()
    }
}

impl HttpTlsConfig {
    /// Creates trust and optional client-identity material.
    ///
    /// `identity_pem` follows reqwest/rustls convention and contains the
    /// certificate chain followed by its private key.
    ///
    /// # Errors
    ///
    /// Rejects empty configured material.
    pub fn new(
        ca_certificate_pem: Vec<u8>,
        identity_pem: Option<Vec<u8>>,
    ) -> Result<Self, HttpConfigError> {
        if ca_certificate_pem.is_empty() {
            return Err(HttpConfigError::EmptyCaCertificate);
        }
        if identity_pem.as_deref().is_some_and(<[u8]>::is_empty) {
            return Err(HttpConfigError::EmptyIdentity);
        }
        Ok(Self {
            ca_certificate_pem,
            identity_pem,
        })
    }
}

/// Validated timeout, body, and TLS policy for HTTP dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpClientConfig {
    connect_timeout: Duration,
    request_timeout: Duration,
    max_response_bytes: usize,
    tls: Option<HttpTlsConfig>,
}

impl HttpClientConfig {
    /// Creates one bounded policy.
    ///
    /// # Errors
    ///
    /// Rejects zero/over-five-minute deadlines and zero/over-16MiB bodies.
    pub fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        max_response_bytes: usize,
        tls: Option<HttpTlsConfig>,
    ) -> Result<Self, HttpConfigError> {
        if connect_timeout.is_zero() || connect_timeout > MAX_HTTP_TIMEOUT {
            return Err(HttpConfigError::InvalidConnectTimeout(connect_timeout));
        }
        if request_timeout.is_zero() || request_timeout > MAX_HTTP_TIMEOUT {
            return Err(HttpConfigError::InvalidRequestTimeout(request_timeout));
        }
        if !(1..=MAX_HTTP_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(HttpConfigError::InvalidResponseBound(max_response_bytes));
        }
        Ok(Self {
            connect_timeout,
            request_timeout,
            max_response_bytes,
            tls,
        })
    }
}

/// Invalid HTTP dependency policy.
#[derive(Debug, Error)]
pub enum HttpConfigError {
    /// Connect timeout is zero or over-bound.
    #[error("invalid HTTP connect timeout {0:?}")]
    InvalidConnectTimeout(Duration),
    /// Request timeout is zero or over-bound.
    #[error("invalid HTTP request timeout {0:?}")]
    InvalidRequestTimeout(Duration),
    /// Response body bound is zero or over-bound.
    #[error("invalid HTTP response bound {0}")]
    InvalidResponseBound(usize),
    /// TLS requires a trust anchor.
    #[error("HTTP TLS CA certificate is empty")]
    EmptyCaCertificate,
    /// Configured client identity is empty.
    #[error("HTTP TLS client identity is empty")]
    EmptyIdentity,
    /// TLS material or the immutable client could not be constructed.
    #[error("invalid HTTP TLS/client configuration")]
    Build(#[source] reqwest::Error),
}

/// Stable HTTP failure classes.
#[derive(Debug, Error)]
pub enum HttpError {
    /// The exact control owner is no longer current.
    #[error("stale control owner")]
    StaleOwner,
    /// URL is not bounded HTTP or HTTPS without credentials.
    #[error("invalid HTTP dependency URL")]
    InvalidUrl,
    /// Request transport or deadline failure.
    #[error("HTTP dependency request failed")]
    Request(#[source] reqwest::Error),
    /// Only successful HTTP 200 responses are accepted.
    #[error("HTTP dependency returned status {0}")]
    Status(StatusCode),
    /// Content-Length or streamed bytes exceeded the configured cap.
    #[error("HTTP dependency response exceeded {maximum} bytes")]
    ResponseTooLarge {
        /// Configured response cap.
        maximum: usize,
    },
}

/// Immutable HTTP client that disables connection reuse like the Go topology
/// client and fences every request by owner generation.
#[derive(Clone)]
pub struct BoundedHttpClient {
    owner: OwnerToken,
    client: Client,
    max_response_bytes: usize,
}

impl BoundedHttpClient {
    /// Builds an immutable client from validated policy.
    ///
    /// # Errors
    ///
    /// Returns a typed build failure for malformed PEM or TLS policy.
    pub fn new(owner: OwnerToken, config: HttpClientConfig) -> Result<Self, HttpConfigError> {
        let mut builder = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .no_proxy()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(tls) = config.tls {
            let certificate =
                Certificate::from_pem(&tls.ca_certificate_pem).map_err(HttpConfigError::Build)?;
            builder = builder.add_root_certificate(certificate);
            if let Some(identity) = tls.identity_pem {
                builder = builder
                    .identity(Identity::from_pem(&identity).map_err(HttpConfigError::Build)?);
            }
        }
        let client = builder.build().map_err(HttpConfigError::Build)?;
        Ok(Self {
            owner,
            client,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// Fetches an exact HTTP 200 response under the configured byte cap.
    ///
    /// # Errors
    ///
    /// Returns stable stale-owner, URL, transport, status, or size failures.
    pub async fn get(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        if !self.owner.is_current() {
            return Err(HttpError::StaleOwner);
        }
        if url.is_empty() || url.len() > MAX_HTTP_URL_BYTES {
            return Err(HttpError::InvalidUrl);
        }
        let parsed = Url::parse(url).map_err(|_| HttpError::InvalidUrl)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(HttpError::InvalidUrl);
        }
        let response = self.client.get(parsed).send().await;
        if !self.owner.is_current() {
            return Err(HttpError::StaleOwner);
        }
        let response = response.map_err(HttpError::Request)?;
        if response.status() != StatusCode::OK {
            return Err(HttpError::Status(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(HttpError::ResponseTooLarge {
                maximum: self.max_response_bytes,
            });
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            if !self.owner.is_current() {
                return Err(HttpError::StaleOwner);
            }
            let chunk = chunk.map_err(HttpError::Request)?;
            let next_len = body.len().saturating_add(chunk.len());
            if next_len > self.max_response_bytes {
                return Err(HttpError::ResponseTooLarge {
                    maximum: self.max_response_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
        if !self.owner.is_current() {
            return Err(HttpError::StaleOwner);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use control_plane::{OwnerScope, OwnershipRegistry};

    use super::{
        BoundedHttpClient, HttpClientConfig, HttpError, HttpTlsConfig, MAX_HTTP_URL_BYTES,
    };

    #[test]
    fn tls_debug_redacts_certificate_and_private_key_material() {
        let tls = HttpTlsConfig::new(
            b"secret-ca-certificate".to_vec(),
            Some(b"secret-client-certificate-and-private-key".to_vec()),
        )
        .unwrap_or_else(|error| unreachable!("TLS policy: {error}"));
        let rendered = format!("{tls:?}");

        assert!(rendered.contains("client_identity_configured: true"));
        assert!(!rendered.contains("secret-ca-certificate"));
        assert!(!rendered.contains("secret-client-certificate-and-private-key"));
    }

    #[tokio::test]
    async fn stale_owner_rejects_before_url_or_network_work() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let client = BoundedHttpClient::new(
            lease.token(),
            HttpClientConfig::new(Duration::from_secs(1), Duration::from_secs(1), 1024, None)
                .unwrap_or_else(|error| unreachable!("config: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        drop(lease);
        assert!(matches!(
            client.get("not a URL").await,
            Err(HttpError::StaleOwner)
        ));
    }

    #[tokio::test]
    async fn over_bound_url_is_rejected_before_network_work() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let client = BoundedHttpClient::new(
            lease.token(),
            HttpClientConfig::new(Duration::from_secs(1), Duration::from_secs(1), 1024, None)
                .unwrap_or_else(|error| unreachable!("config: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("client: {error}"));
        let url = format!("http://localhost/{}", "a".repeat(MAX_HTTP_URL_BYTES));

        assert!(matches!(client.get(&url).await, Err(HttpError::InvalidUrl)));
    }
}
