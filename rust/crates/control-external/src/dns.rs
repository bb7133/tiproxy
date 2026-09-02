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

//! Bounded DNS resolution using Tokio's system resolver.

use std::net::SocketAddr;
use std::time::Duration;

use control_plane::OwnerToken;
use thiserror::Error;

/// Maximum addresses retained from one lookup.
pub const MAX_RESOLVED_ADDRESSES: usize = 64;
const MAX_HOST_BYTES: usize = 253;
const MAX_DNS_TIMEOUT: Duration = Duration::from_secs(30);

/// Owner-fenced DNS resolver for external clients.
#[derive(Clone)]
pub struct DnsResolver {
    owner: OwnerToken,
    timeout: Duration,
}

impl DnsResolver {
    /// Creates a resolver with a nonzero timeout of at most 30 seconds.
    ///
    /// # Errors
    ///
    /// Rejects zero and over-bound timeouts.
    pub fn new(owner: OwnerToken, timeout: Duration) -> Result<Self, DnsError> {
        if timeout.is_zero() || timeout > MAX_DNS_TIMEOUT {
            return Err(DnsError::InvalidTimeout(timeout));
        }
        Ok(Self { owner, timeout })
    }

    /// Resolves and deterministically deduplicates all addresses.
    ///
    /// # Errors
    ///
    /// Returns a stable invalid-input, stale-owner, timeout, lookup, empty, or
    /// over-bound error.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
        if !self.owner.is_current() {
            return Err(DnsError::StaleOwner);
        }
        if host.is_empty() || host.len() > MAX_HOST_BYTES {
            return Err(DnsError::InvalidHost);
        }
        let lookup =
            tokio::time::timeout(self.timeout, tokio::net::lookup_host((host, port))).await;
        if !self.owner.is_current() {
            return Err(DnsError::StaleOwner);
        }
        let lookup = lookup
            .map_err(|_| DnsError::Timeout)?
            .map_err(DnsError::Lookup)?;
        let mut addresses: Vec<SocketAddr> = lookup.take(MAX_RESOLVED_ADDRESSES + 1).collect();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(DnsError::EmptyResult);
        }
        if addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(DnsError::TooManyAddresses(addresses.len()));
        }
        Ok(addresses)
    }
}

/// Stable DNS failure classes.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Hostname is empty or over its DNS byte bound.
    #[error("invalid DNS hostname")]
    InvalidHost,
    /// Timeout is zero or over-bound.
    #[error("invalid DNS timeout {0:?}")]
    InvalidTimeout(Duration),
    /// The originating owner is no longer current.
    #[error("stale control owner")]
    StaleOwner,
    /// Resolution exceeded its deadline.
    #[error("DNS resolution timed out")]
    Timeout,
    /// The system resolver failed.
    #[error("DNS resolution failed")]
    Lookup(#[source] std::io::Error),
    /// The resolver returned no addresses.
    #[error("DNS resolution returned no addresses")]
    EmptyResult,
    /// The result set exceeded its bound.
    #[error("DNS resolution returned too many addresses: {0}")]
    TooManyAddresses(usize),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use control_plane::{OwnerScope, OwnershipRegistry};

    use super::{DnsError, DnsResolver};

    #[tokio::test]
    async fn localhost_resolution_is_nonempty_and_deterministic() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let resolver = DnsResolver::new(lease.token(), Duration::from_secs(1))
            .unwrap_or_else(|error| unreachable!("resolver: {error}"));
        let addresses = resolver
            .resolve("localhost", 80)
            .await
            .unwrap_or_else(|error| unreachable!("resolve: {error}"));
        assert!(!addresses.is_empty());
        assert!(addresses.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[tokio::test]
    async fn stale_owner_rejects_before_input_or_resolution_work() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "owner-A")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let resolver = DnsResolver::new(lease.token(), Duration::from_secs(1))
            .unwrap_or_else(|error| unreachable!("resolver: {error}"));
        drop(lease);

        assert!(matches!(
            resolver.resolve("", 80).await,
            Err(DnsError::StaleOwner)
        ));
    }
}
