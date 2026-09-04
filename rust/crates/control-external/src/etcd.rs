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

/// The minimum accepted TLS protocol version for an etcd connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtcdTlsVersion {
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
}

impl EtcdTlsVersion {
    /// Parses the CP-CFG `minimum-version` value: `""` (no floor), `"1.2"`, or
    /// `"1.3"`.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdConfigError::UnsupportedTlsVersion`] for any other value.
    pub fn parse(value: &str) -> Result<Option<Self>, EtcdConfigError> {
        match value {
            "" => Ok(None),
            "1.2" => Ok(Some(Self::V1_2)),
            "1.3" => Ok(Some(Self::V1_3)),
            _ => Err(EtcdConfigError::UnsupportedTlsVersion),
        }
    }
}

/// Advanced TLS verification policy for an etcd connection, mirroring the frozen
/// backend `cluster-tls` fields. The default verifies the server against the
/// configured CA with no version floor and no name pinning — the behavior the
/// config-persistence and election owners rely on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EtcdTlsPolicy {
    /// Minimum accepted TLS protocol version, or `None` for the default floor.
    pub minimum_version: Option<EtcdTlsVersion>,
    /// Exact-match allowlist of accepted server-certificate common names. Empty
    /// disables common-name pinning.
    pub allowed_common_names: Vec<String>,
    /// Skip CA-chain and hostname trust while still performing the TLS handshake
    /// signature check (mirrors Go `skip-ca`). A CA is not required when set;
    /// any configured `allowed_common_names` is still enforced.
    pub skip_ca_verification: bool,
}

/// Maximum accepted common-name pins, matching the serving TLS contract.
const MAX_TLS_COMMON_NAMES: usize = 1024;
/// Maximum accepted length of one common-name pin.
const MAX_TLS_COMMON_NAME_LEN: usize = 255;

/// Trims, bounds, sorts, and de-duplicates the common-name allowlist.
///
/// # Errors
///
/// Rejects an over-count list or an entry that is empty or over-length after
/// trimming.
fn normalized_common_names(names: Vec<String>) -> Result<Vec<String>, EtcdConfigError> {
    if names.len() > MAX_TLS_COMMON_NAMES {
        return Err(EtcdConfigError::TooManyCommonNames);
    }
    let mut normalized = Vec::with_capacity(names.len());
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(EtcdConfigError::EmptyCommonName);
        }
        if trimmed.len() > MAX_TLS_COMMON_NAME_LEN {
            return Err(EtcdConfigError::CommonNameTooLong);
        }
        normalized.push(trimmed.to_owned());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

/// Validated mTLS material and verification policy for an etcd connection.
#[derive(Clone, PartialEq, Eq)]
pub struct EtcdTlsConfig {
    ca_certificate_pem: Option<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
    domain_name: Option<String>,
    policy: EtcdTlsPolicy,
}

impl fmt::Debug for EtcdTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EtcdTlsConfig")
            .field(
                "ca_certificate_configured",
                &self.ca_certificate_pem.is_some(),
            )
            .field("client_identity_configured", &self.identity.is_some())
            .field("domain_name", &self.domain_name)
            .field("minimum_version", &self.policy.minimum_version)
            .field("common_name_pins", &self.policy.allowed_common_names.len())
            .field("skip_ca_verification", &self.policy.skip_ca_verification)
            .finish()
    }
}

impl EtcdTlsConfig {
    /// Creates TLS material and policy from an optional CA bundle, an optional
    /// client identity, an optional explicit server name, and a verification
    /// policy.
    ///
    /// A CA bundle is required unless [`EtcdTlsPolicy::skip_ca_verification`] is
    /// set; when it is set, the connection still performs the TLS handshake and
    /// enforces any `allowed_common_names`.
    ///
    /// # Errors
    ///
    /// Rejects a missing CA when CA verification is required, incomplete client
    /// identities, empty explicit domain names, and empty common-name entries.
    pub fn new(
        ca_certificate_pem: Option<Vec<u8>>,
        client_certificate_pem: Option<Vec<u8>>,
        client_key_pem: Option<Vec<u8>>,
        domain_name: Option<String>,
        policy: EtcdTlsPolicy,
    ) -> Result<Self, EtcdConfigError> {
        let EtcdTlsPolicy {
            minimum_version,
            allowed_common_names,
            skip_ca_verification,
        } = policy;
        let ca_certificate_pem = ca_certificate_pem.filter(|ca| !ca.is_empty());
        if !skip_ca_verification && ca_certificate_pem.is_none() {
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
        let allowed_common_names = normalized_common_names(allowed_common_names)?;
        Ok(Self {
            ca_certificate_pem,
            identity,
            domain_name,
            policy: EtcdTlsPolicy {
                minimum_version,
                allowed_common_names,
                skip_ca_verification,
            },
        })
    }

    fn connect_options(&self) -> TlsOptions {
        // NOTE: the advanced policy (minimum version, common-name pinning,
        // skip-CA) is not yet expressed here — `TlsOptions` (tonic
        // `ClientTlsConfig`) cannot carry it. It is consumed by the custom
        // rustls transport that replaces this path; today only the default
        // policy (CA verification, no floor, no pinning) reaches this builder.
        let mut options = TlsOptions::new();
        if let Some(ca_certificate_pem) = &self.ca_certificate_pem {
            options = options.ca_certificate(Certificate::from_pem(ca_certificate_pem.clone()));
        }
        if let Some((certificate, key)) = &self.identity {
            options = options.identity(Identity::from_pem(certificate.clone(), key.clone()));
        }
        if let Some(domain_name) = &self.domain_name {
            options = options.domain_name(domain_name.clone());
        }
        options
    }

    /// Builds the client TLS configuration for the custom etcd transport from
    /// the generation-bound material and verification policy (the advanced
    /// `minimum_version` / `allowed_common_names` / `skip_ca_verification` that
    /// the tonic `TlsOptions` path cannot express).
    ///
    /// # Errors
    ///
    /// Returns [`EtcdConfigError::TlsSetup`] when the material cannot form a
    /// client configuration.
    pub fn client_config(&self) -> Result<std::sync::Arc<rustls::ClientConfig>, EtcdConfigError> {
        crate::tls::build_client_config(
            self.ca_certificate_pem.as_deref(),
            self.identity
                .as_ref()
                .map(|(certificate, key)| (certificate.as_slice(), key.as_slice())),
            &self.policy,
        )
    }

    /// Returns the explicit TLS server-name override used for SNI, if set.
    pub(crate) fn domain_name(&self) -> Option<&str> {
        self.domain_name.as_deref()
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

    /// Returns the whole-connection establishment budget for the custom
    /// transport (single DNS + TCP + TLS deadline per endpoint).
    pub(crate) const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the HTTP/2 keepalive ping interval for the custom transport.
    pub(crate) const fn keep_alive_interval(&self) -> Duration {
        self.keep_alive_interval
    }

    /// Returns the HTTP/2 keepalive ping timeout for the custom transport.
    pub(crate) const fn keep_alive_timeout(&self) -> Duration {
        self.keep_alive_timeout
    }

    /// Returns the TCP keepalive idle time applied to each dialed socket.
    pub(crate) const fn tcp_keep_alive(&self) -> Duration {
        self.tcp_keep_alive
    }

    /// Returns the validated TLS material and policy, if TLS is configured.
    pub(crate) fn tls(&self) -> Option<&EtcdTlsConfig> {
        self.tls.as_ref()
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
    /// TLS requires at least one trust anchor unless CA verification is skipped.
    #[error("etcd TLS CA certificate is empty")]
    EmptyCaCertificate,
    /// Client certificate and key must be configured together.
    #[error("etcd TLS client certificate and key must both be configured")]
    IncompleteClientIdentity,
    /// An explicit TLS server name cannot be empty.
    #[error("etcd TLS domain name is empty")]
    EmptyDomainName,
    /// The minimum TLS version must be unset, `1.2`, or `1.3`.
    #[error("unsupported etcd TLS minimum version")]
    UnsupportedTlsVersion,
    /// An allowed common name entry cannot be empty.
    #[error("etcd TLS allowed common name is empty")]
    EmptyCommonName,
    /// An allowed common name entry exceeds its length bound.
    #[error("etcd TLS allowed common name is too long")]
    CommonNameTooLong,
    /// The allowed common name list exceeds its count bound.
    #[error("too many etcd TLS allowed common names")]
    TooManyCommonNames,
    /// The TLS material and policy could not form a client configuration.
    #[error("etcd TLS client configuration could not be built")]
    TlsSetup,
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

    use super::{EtcdClientConfig, EtcdConfigError, EtcdTlsConfig, EtcdTlsPolicy, EtcdTlsVersion};

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
            EtcdTlsConfig::new(None, None, None, None, EtcdTlsPolicy::default()),
            Err(EtcdConfigError::EmptyCaCertificate)
        );
        assert_eq!(
            EtcdTlsConfig::new(
                Some(vec![1]),
                Some(vec![2]),
                None,
                None,
                EtcdTlsPolicy::default()
            ),
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
    fn minimum_tls_version_parses_only_the_frozen_values() {
        assert_eq!(EtcdTlsVersion::parse(""), Ok(None));
        assert_eq!(EtcdTlsVersion::parse("1.2"), Ok(Some(EtcdTlsVersion::V1_2)));
        assert_eq!(EtcdTlsVersion::parse("1.3"), Ok(Some(EtcdTlsVersion::V1_3)));
        assert_eq!(
            EtcdTlsVersion::parse("1.1"),
            Err(EtcdConfigError::UnsupportedTlsVersion)
        );
        assert_eq!(
            EtcdTlsVersion::parse("tls1.3"),
            Err(EtcdConfigError::UnsupportedTlsVersion)
        );
    }

    #[test]
    fn skip_ca_verification_allows_a_tls_config_without_a_ca() {
        // skip-CA still enables TLS but does not require a trust anchor.
        let policy = EtcdTlsPolicy {
            skip_ca_verification: true,
            ..EtcdTlsPolicy::default()
        };
        assert!(EtcdTlsConfig::new(None, None, None, None, policy.clone()).is_ok());
        // An empty CA is treated as absent, which is fine when skipping.
        assert!(EtcdTlsConfig::new(Some(Vec::new()), None, None, None, policy).is_ok());
    }

    #[test]
    fn a_ca_is_required_when_not_skipping_verification() {
        // Default policy verifies the CA, so a missing or empty CA is rejected.
        assert_eq!(
            EtcdTlsConfig::new(None, None, None, None, EtcdTlsPolicy::default()),
            Err(EtcdConfigError::EmptyCaCertificate)
        );
        assert_eq!(
            EtcdTlsConfig::new(Some(Vec::new()), None, None, None, EtcdTlsPolicy::default()),
            Err(EtcdConfigError::EmptyCaCertificate)
        );
    }

    #[test]
    fn an_empty_allowed_common_name_is_rejected() {
        let policy = EtcdTlsPolicy {
            allowed_common_names: vec!["good".to_owned(), "  ".to_owned()],
            ..EtcdTlsPolicy::default()
        };
        assert_eq!(
            EtcdTlsConfig::new(Some(vec![1]), None, None, None, policy),
            Err(EtcdConfigError::EmptyCommonName)
        );
    }

    #[test]
    fn allowed_common_names_are_bounded() {
        let over_count = EtcdTlsPolicy {
            allowed_common_names: vec!["cn".to_owned(); 1025],
            ..EtcdTlsPolicy::default()
        };
        assert_eq!(
            EtcdTlsConfig::new(Some(vec![1]), None, None, None, over_count),
            Err(EtcdConfigError::TooManyCommonNames)
        );
        let over_length = EtcdTlsPolicy {
            allowed_common_names: vec!["a".repeat(256)],
            ..EtcdTlsPolicy::default()
        };
        assert_eq!(
            EtcdTlsConfig::new(Some(vec![1]), None, None, None, over_length),
            Err(EtcdConfigError::CommonNameTooLong)
        );
    }

    #[test]
    fn allowed_common_names_are_trimmed_sorted_and_deduped() {
        assert_eq!(
            super::normalized_common_names(vec![
                " beta ".to_owned(),
                "alpha".to_owned(),
                "alpha".to_owned(),
            ]),
            Ok(vec!["alpha".to_owned(), "beta".to_owned()])
        );
    }

    #[test]
    fn a_full_policy_with_ca_and_pins_is_accepted() {
        let policy = EtcdTlsPolicy {
            minimum_version: Some(EtcdTlsVersion::V1_3),
            allowed_common_names: vec!["etcd-server".to_owned()],
            skip_ca_verification: false,
        };
        assert!(EtcdTlsConfig::new(Some(vec![1, 2, 3]), None, None, None, policy).is_ok());
    }

    #[test]
    fn tls_debug_redacts_certificate_and_private_key_material() {
        let tls = EtcdTlsConfig::new(
            Some(b"secret-ca-certificate".to_vec()),
            Some(b"secret-client-certificate".to_vec()),
            Some(b"secret-private-key".to_vec()),
            Some("etcd.internal".to_owned()),
            EtcdTlsPolicy::default(),
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
