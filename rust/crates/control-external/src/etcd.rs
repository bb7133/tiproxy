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

//! Fenced `etcd-client` construction for PD's etcd v3 API.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use control_plane::OwnerToken;
use etcd_client::{Certificate, Client, ConnectOptions, Identity, TlsOptions};
use http::Uri;
use thiserror::Error;

/// Maximum configured PD endpoints for one client.
pub const MAX_ETCD_ENDPOINTS: usize = 32;
/// Maximum byte length of one configured endpoint.
pub const MAX_ETCD_ENDPOINT_BYTES: usize = 2_048;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// Validated mTLS material for an etcd connection.
#[derive(Clone, PartialEq, Eq)]
pub struct EtcdTlsConfig {
    ca_certificate_pem: Vec<u8>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
    domain_name: Option<String>,
}

impl fmt::Debug for EtcdTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtcdTlsConfig")
            .field("ca_certificate_pem", &"<redacted>")
            .field("client_identity_configured", &self.identity.is_some())
            .field("domain_name", &self.domain_name)
            .finish()
    }
}

impl EtcdTlsConfig {
    /// Creates TLS options from one CA bundle and an optional client identity.
    ///
    /// # Errors
    ///
    /// Rejects empty CA material, incomplete client identities, and empty
    /// explicit domain names.
    pub fn new(
        ca_certificate_pem: Vec<u8>,
        client_certificate_pem: Option<Vec<u8>>,
        client_key_pem: Option<Vec<u8>>,
        domain_name: Option<String>,
    ) -> Result<Self, EtcdConfigError> {
        if ca_certificate_pem.is_empty() {
            return Err(EtcdConfigError::EmptyCaCertificate);
        }
        let identity = match (client_certificate_pem, client_key_pem) {
            (Some(certificate), Some(key)) if !certificate.is_empty() && !key.is_empty() => {
                Some((certificate, key))
            }
            (None, None) => None,
            _ => return Err(EtcdConfigError::IncompleteClientIdentity),
        };
        if domain_name.as_deref().is_some_and(str::is_empty) {
            return Err(EtcdConfigError::EmptyDomainName);
        }
        Ok(Self {
            ca_certificate_pem,
            identity,
            domain_name,
        })
    }

    fn connect_options(&self) -> TlsOptions {
        let mut options = TlsOptions::new()
            .ca_certificate(Certificate::from_pem(self.ca_certificate_pem.clone()));
        if let Some((certificate, key)) = &self.identity {
            options = options.identity(Identity::from_pem(certificate.clone(), key.clone()));
        }
        if let Some(domain_name) = &self.domain_name {
            options = options.domain_name(domain_name.clone());
        }
        options
    }
}

/// Validated production connection policy shared by later control modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtcdClientConfig {
    endpoints: Vec<String>,
    connect_timeout: Duration,
    request_timeout: Duration,
    keep_alive_interval: Duration,
    keep_alive_timeout: Duration,
    tcp_keep_alive: Duration,
    tls: Option<EtcdTlsConfig>,
}

impl EtcdClientConfig {
    /// Creates the Go-parity connection policy for a bounded endpoint set.
    ///
    /// Bare `host:port` entries are supported because `TiProxy`'s existing
    /// `proxy.pd-addrs` uses that form. A TLS configuration upgrades bare
    /// entries to HTTPS; explicit HTTP/HTTPS schemes must agree with it.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, malformed, path-bearing, or policy-mismatched
    /// endpoints.
    pub fn new(
        endpoints: impl IntoIterator<Item = String>,
        tls: Option<EtcdTlsConfig>,
    ) -> Result<Self, EtcdConfigError> {
        let endpoints = normalize_endpoints(endpoints, tls.is_some())?;
        Ok(Self {
            endpoints,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            keep_alive_interval: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(3),
            tcp_keep_alive: Duration::from_secs(30),
            tls,
        })
    }

    /// Replaces all bounded timeout and keepalive values.
    ///
    /// # Errors
    ///
    /// Rejects zero or over-five-minute values and keepalive timeouts greater
    /// than their interval.
    pub fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        request_timeout: Duration,
        keep_alive_interval: Duration,
        keep_alive_timeout: Duration,
        tcp_keep_alive: Duration,
    ) -> Result<Self, EtcdConfigError> {
        for (name, value) in [
            ("connect_timeout", connect_timeout),
            ("request_timeout", request_timeout),
            ("keep_alive_interval", keep_alive_interval),
            ("keep_alive_timeout", keep_alive_timeout),
            ("tcp_keep_alive", tcp_keep_alive),
        ] {
            if value.is_zero() || value > MAX_TIMEOUT {
                return Err(EtcdConfigError::InvalidDuration { name, value });
            }
        }
        if keep_alive_timeout > keep_alive_interval {
            return Err(EtcdConfigError::KeepAliveTimeoutExceedsInterval);
        }
        self.connect_timeout = connect_timeout;
        self.request_timeout = request_timeout;
        self.keep_alive_interval = keep_alive_interval;
        self.keep_alive_timeout = keep_alive_timeout;
        self.tcp_keep_alive = tcp_keep_alive;
        Ok(self)
    }

    /// Returns normalized endpoints in deterministic order.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Returns the per-operation request deadline.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    fn connect_options(&self) -> ConnectOptions {
        let mut options = ConnectOptions::new()
            .with_connect_timeout(self.connect_timeout)
            .with_timeout(self.request_timeout)
            .with_keep_alive(self.keep_alive_interval, self.keep_alive_timeout)
            .with_keep_alive_while_idle(false)
            .with_tcp_keepalive(self.tcp_keep_alive);
        if let Some(tls) = &self.tls {
            options = options.with_tls(tls.connect_options());
        }
        options
    }
}

/// Configuration rejection at the external boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EtcdConfigError {
    /// At least one endpoint is required.
    #[error("at least one etcd endpoint is required")]
    EmptyEndpoints,
    /// The configured endpoint count is bounded.
    #[error("too many etcd endpoints: {count} exceeds {maximum}")]
    TooManyEndpoints {
        /// Observed endpoint count.
        count: usize,
        /// Maximum endpoint count.
        maximum: usize,
    },
    /// One endpoint is empty, malformed, or over its byte bound.
    #[error("invalid etcd endpoint at index {index}: {reason}")]
    InvalidEndpoint {
        /// Zero-based endpoint index.
        index: usize,
        /// Payload-free rejection reason.
        reason: &'static str,
    },
    /// Duplicate normalized endpoint.
    #[error("duplicate etcd endpoint at index {index}")]
    DuplicateEndpoint {
        /// Zero-based endpoint index.
        index: usize,
    },
    /// Explicit endpoint scheme disagrees with the TLS policy.
    #[error("etcd endpoint scheme and TLS policy disagree at index {index}")]
    TlsSchemeMismatch {
        /// Zero-based endpoint index.
        index: usize,
    },
    /// TLS requires at least one trust anchor.
    #[error("etcd TLS CA certificate is empty")]
    EmptyCaCertificate,
    /// Client certificate and key must be configured together.
    #[error("etcd TLS client certificate and key must both be configured")]
    IncompleteClientIdentity,
    /// An explicit TLS server name cannot be empty.
    #[error("etcd TLS domain name is empty")]
    EmptyDomainName,
    /// Timeout and keepalive values are bounded.
    #[error("invalid {name} duration {value:?}")]
    InvalidDuration {
        /// Duration role.
        name: &'static str,
        /// Rejected duration.
        value: Duration,
    },
    /// HTTP/2 keepalive timeout cannot exceed its interval.
    #[error("etcd keepalive timeout exceeds its interval")]
    KeepAliveTimeoutExceedsInterval,
}

/// Runtime connection failure with stable public classes.
#[derive(Debug, Error)]
pub enum EtcdConnectError {
    /// The originating control owner is no longer current.
    #[error("stale control owner")]
    StaleOwner,
    /// The external client rejected or could not reach the endpoint set.
    #[error("etcd dependency connection failed")]
    Dependency(#[source] etcd_client::Error),
}

/// A fenced semantic etcd operation failure.
#[derive(Debug, Error)]
pub enum EtcdOperationError {
    /// The originating control owner is no longer current.
    #[error("stale control owner")]
    StaleOwner,
    /// The etcd operation failed while the owner remained current.
    #[error("etcd dependency operation failed")]
    Dependency(#[source] etcd_client::Error),
}

/// Factory that can create clients only for its exact owner generation.
#[derive(Clone)]
pub struct EtcdConnector {
    owner: OwnerToken,
    config: EtcdClientConfig,
}

impl EtcdConnector {
    /// Binds a validated config to the unique process-local owner token.
    #[must_use]
    pub const fn new(owner: OwnerToken, config: EtcdClientConfig) -> Self {
        Self { owner, config }
    }

    /// Connects to PD's etcd API and rechecks the owner after the await point.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdConnectError::StaleOwner`] before or after connection if
    /// the exact generation was released; otherwise returns the typed client
    /// error without retrying forever.
    pub async fn connect(&self) -> Result<EtcdConnection, EtcdConnectError> {
        if !self.owner.is_current() {
            return Err(EtcdConnectError::StaleOwner);
        }
        let result =
            Client::connect(self.config.endpoints(), Some(self.config.connect_options())).await;
        if !self.owner.is_current() {
            return Err(EtcdConnectError::StaleOwner);
        }
        let client = result.map_err(EtcdConnectError::Dependency)?;
        Ok(EtcdConnection {
            owner: self.owner.clone(),
            client,
        })
    }
}

/// An etcd client that cannot be borrowed after its owner becomes stale.
pub struct EtcdConnection {
    owner: OwnerToken,
    client: Client,
}

impl EtcdConnection {
    /// Executes one semantic etcd operation for the current generation.
    ///
    /// The raw client never escapes this closure. Ownership is checked both
    /// before creating the operation future and after it resolves, so a result
    /// completed by a retired generation is discarded rather than committed by
    /// its caller.
    ///
    /// # Errors
    ///
    /// Returns a stale-owner failure before or after the await point, or the
    /// typed dependency failure from the operation itself.
    pub async fn execute<T, F>(&mut self, operation: F) -> Result<T, EtcdOperationError>
    where
        F: for<'client> FnOnce(
            &'client mut Client,
        ) -> Pin<
            Box<dyn Future<Output = Result<T, etcd_client::Error>> + Send + 'client>,
        >,
    {
        if !self.owner.is_current() {
            return Err(EtcdOperationError::StaleOwner);
        }
        let result = operation(&mut self.client).await;
        if !self.owner.is_current() {
            return Err(EtcdOperationError::StaleOwner);
        }
        result.map_err(EtcdOperationError::Dependency)
    }
}

fn normalize_endpoints(
    endpoints: impl IntoIterator<Item = String>,
    tls: bool,
) -> Result<Vec<String>, EtcdConfigError> {
    let collected: Vec<String> = endpoints.into_iter().collect();
    if collected.is_empty() {
        return Err(EtcdConfigError::EmptyEndpoints);
    }
    if collected.len() > MAX_ETCD_ENDPOINTS {
        return Err(EtcdConfigError::TooManyEndpoints {
            count: collected.len(),
            maximum: MAX_ETCD_ENDPOINTS,
        });
    }
    let mut seen = HashSet::with_capacity(collected.len());
    let mut normalized = Vec::with_capacity(collected.len());
    for (index, endpoint) in collected.into_iter().enumerate() {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() || endpoint.len() > MAX_ETCD_ENDPOINT_BYTES {
            return Err(EtcdConfigError::InvalidEndpoint {
                index,
                reason: "empty or over byte bound",
            });
        }
        let explicit_scheme = endpoint.contains("://");
        let candidate = if explicit_scheme {
            endpoint.to_owned()
        } else {
            format!("{}://{endpoint}", if tls { "https" } else { "http" })
        };
        let uri: Uri = candidate
            .parse()
            .map_err(|_| EtcdConfigError::InvalidEndpoint {
                index,
                reason: "malformed URI",
            })?;
        let Some(scheme) = uri.scheme_str() else {
            return Err(EtcdConfigError::InvalidEndpoint {
                index,
                reason: "missing scheme",
            });
        };
        if !matches!(scheme, "http" | "https") || uri.authority().is_none() {
            return Err(EtcdConfigError::InvalidEndpoint {
                index,
                reason: "unsupported scheme or missing authority",
            });
        }
        if uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(EtcdConfigError::InvalidEndpoint {
                index,
                reason: "credentials are not allowed",
            });
        }
        if uri
            .path_and_query()
            .is_some_and(|path| path.as_str() != "/")
        {
            return Err(EtcdConfigError::InvalidEndpoint {
                index,
                reason: "paths and queries are not allowed",
            });
        }
        if (scheme == "https") != tls {
            return Err(EtcdConfigError::TlsSchemeMismatch { index });
        }
        let normalized_endpoint = uri.to_string().trim_end_matches('/').to_owned();
        if !seen.insert(normalized_endpoint.clone()) {
            return Err(EtcdConfigError::DuplicateEndpoint { index });
        }
        normalized.push(normalized_endpoint);
    }
    normalized.sort_unstable();
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use control_plane::{OwnerScope, OwnershipRegistry};

    use super::{EtcdClientConfig, EtcdConfigError, EtcdTlsConfig};

    #[test]
    fn endpoints_are_bounded_normalized_and_tls_consistent() {
        let plain = EtcdClientConfig::new(
            [
                "127.0.0.1:2379".to_owned(),
                "http://localhost:2380".to_owned(),
            ],
            None,
        )
        .unwrap_or_else(|error| unreachable!("valid endpoints: {error}"));
        assert_eq!(
            plain.endpoints(),
            ["http://127.0.0.1:2379", "http://localhost:2380"]
        );
        assert_eq!(
            EtcdClientConfig::new(["https://localhost:2379".to_owned()], None),
            Err(EtcdConfigError::TlsSchemeMismatch { index: 0 })
        );
        assert_eq!(
            EtcdClientConfig::new(
                [
                    "localhost:2379".to_owned(),
                    "http://localhost:2379".to_owned()
                ],
                None,
            ),
            Err(EtcdConfigError::DuplicateEndpoint { index: 1 })
        );
    }

    #[test]
    fn tls_and_timeout_material_is_complete() {
        assert_eq!(
            EtcdTlsConfig::new(Vec::new(), None, None, None),
            Err(EtcdConfigError::EmptyCaCertificate)
        );
        assert_eq!(
            EtcdTlsConfig::new(vec![1], Some(vec![2]), None, None),
            Err(EtcdConfigError::IncompleteClientIdentity)
        );
        let config =
            EtcdClientConfig::new(["localhost:2379".to_owned()], None).and_then(|config| {
                config.with_timeouts(
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    Duration::from_secs(1),
                )
            });
        assert_eq!(
            config,
            Err(EtcdConfigError::KeepAliveTimeoutExceedsInterval)
        );
    }

    #[test]
    fn tls_debug_redacts_certificate_and_private_key_material() {
        let tls = EtcdTlsConfig::new(
            b"secret-ca-certificate".to_vec(),
            Some(b"secret-client-certificate".to_vec()),
            Some(b"secret-private-key".to_vec()),
            Some("etcd.internal".to_owned()),
        )
        .unwrap_or_else(|error| unreachable!("TLS policy: {error}"));
        let rendered = format!("{tls:?}");

        assert!(rendered.contains("client_identity_configured: true"));
        assert!(rendered.contains("etcd.internal"));
        for secret in [
            "secret-ca-certificate",
            "secret-client-certificate",
            "secret-private-key",
        ] {
            assert!(!rendered.contains(secret), "Debug leaked {secret}");
        }
    }

    #[test]
    fn endpoint_credentials_are_rejected() {
        assert!(matches!(
            EtcdClientConfig::new(["http://user:password@localhost:2379".to_owned()], None),
            Err(EtcdConfigError::InvalidEndpoint {
                reason: "credentials are not allowed",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn stale_owner_cannot_start_a_connection() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("owner claim: {error}"));
        let connector = super::EtcdConnector::new(
            lease.token(),
            EtcdClientConfig::new(["127.0.0.1:1".to_owned()], None)
                .unwrap_or_else(|error| unreachable!("config: {error}")),
        );
        drop(lease);
        assert!(matches!(
            connector.connect().await,
            Err(super::EtcdConnectError::StaleOwner)
        ));
    }
}
