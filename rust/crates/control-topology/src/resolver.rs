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

//! Resolution of the advertised SQL endpoint a `TiProxy` instance registers.
//!
//! This owns the "how does a CP-CFG snapshot become the runtime registration
//! host" boundary that Go `GetIPPort` (`lib/config/proxy.go`) implements. The
//! configuration layer supplies only deterministic raw material (an explicit
//! advertise override, the bind host of the first serving listener, and the HA
//! virtual IP); the resolution — including any interface enumeration — happens
//! here so the config crate never has to enumerate network interfaces.

use std::net::IpAddr;
use std::sync::Arc;

use control_config::TopologyConfig;

/// Resolves the advertised SQL host a `TiProxy` instance publishes.
///
/// Injected from the composition root so the binary can supply real interface
/// enumeration while tests supply a fixed candidate list.
pub trait AdvertiseEndpointResolver: Send + Sync {
    /// Resolves the advertised host from a topology configuration's raw
    /// material.
    ///
    /// # Errors
    ///
    /// Returns a reason when the bind host requires interface fallback but no
    /// usable global-unicast candidate is available.
    fn resolve(&self, config: &TopologyConfig) -> Result<Arc<str>, String>;
}

/// The default resolver: an explicit override wins; otherwise a concrete bind
/// host is kept, and a wildcard/empty bind host falls back to the first
/// global-unicast interface candidate that is not the HA virtual IP.
///
/// Interface enumeration is injected as a candidate provider so the selection
/// logic stays deterministic and testable and this crate needs no
/// interface-enumeration dependency.
pub struct InterfaceAdvertiseResolver {
    candidates: Arc<dyn Fn() -> Vec<IpAddr> + Send + Sync>,
}

impl InterfaceAdvertiseResolver {
    /// Builds a resolver from a candidate-address provider (typically the
    /// binary's interface enumeration).
    #[must_use]
    pub fn new(candidates: Arc<dyn Fn() -> Vec<IpAddr> + Send + Sync>) -> Self {
        Self { candidates }
    }
}

impl AdvertiseEndpointResolver for InterfaceAdvertiseResolver {
    fn resolve(&self, config: &TopologyConfig) -> Result<Arc<str>, String> {
        // The candidate provider is called lazily so an override or a concrete
        // bind host never triggers an interface scan.
        select_advertise_host(
            config.advertise_host_override.as_deref(),
            &config.bind_sql_host,
            &config.ha_virtual_ip,
            || (self.candidates)(),
        )
    }
}

/// A fixed resolver that always advertises the same host, for tests and for a
/// composition that has already resolved its endpoint elsewhere.
pub struct StaticAdvertiseResolver {
    host: Arc<str>,
}

impl StaticAdvertiseResolver {
    /// Builds a resolver that always returns `host`.
    #[must_use]
    pub fn new(host: impl Into<Arc<str>>) -> Self {
        Self { host: host.into() }
    }
}

impl AdvertiseEndpointResolver for StaticAdvertiseResolver {
    fn resolve(&self, _config: &TopologyConfig) -> Result<Arc<str>, String> {
        Ok(Arc::clone(&self.host))
    }
}

/// Pure host selection, mirroring Go `GetIPPort`.
///
/// An explicit, non-empty override is used verbatim (a DNS advertise name is
/// never rewritten). Otherwise a concrete bind host is kept; an empty or
/// wildcard bind host (unspecified/broadcast/multicast) falls back to the first
/// global-unicast `candidate` whose address is not a prefix of the HA virtual
/// IP (Go's `HasPrefix(VirtualIP, candidateIP)` exclusion).
fn select_advertise_host(
    override_host: Option<&str>,
    bind_host: &str,
    ha_virtual_ip: &str,
    candidates: impl FnOnce() -> Vec<IpAddr>,
) -> Result<Arc<str>, String> {
    if let Some(override_host) = override_host {
        let override_host = override_host.trim();
        if !override_host.is_empty() {
            return Ok(Arc::from(override_host));
        }
    }
    let bind_host = bind_host.trim();
    if !bind_host.is_empty() && !is_wildcard_bind(bind_host) {
        return Ok(Arc::from(bind_host));
    }
    for candidate in candidates() {
        if !is_global_unicast(&candidate) {
            continue;
        }
        let text = candidate.to_string();
        if !ha_virtual_ip.is_empty() && ha_virtual_ip.starts_with(&text) {
            continue;
        }
        return Ok(Arc::from(text.as_str()));
    }
    Err("no global-unicast interface address available for advertising".to_owned())
}

/// Whether a bind host is a wildcard that Go replaces with an interface scan.
fn is_wildcard_bind(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            address.is_unspecified() || address.is_broadcast() || address.is_multicast()
        }
        Ok(IpAddr::V6(address)) => address.is_unspecified() || address.is_multicast(),
        // A DNS name or other non-IP host is a concrete advertise target.
        Err(_) => false,
    }
}

/// A global-unicast test matching Go `IsGlobalUnicast`'s intent: exclude
/// loopback, unspecified, multicast, broadcast, and link-local (both the IPv4
/// `169.254.0.0/16` and the IPv6 `fe80::/10` link-local ranges).
fn is_global_unicast(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !is_ipv6_unicast_link_local(address)
        }
    }
}

/// Whether an IPv6 address is in the `fe80::/10` link-local range.
///
/// Implemented directly on the leading segment because
/// `Ipv6Addr::is_unicast_link_local` is not yet stable.
fn is_ipv6_unicast_link_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::select_advertise_host;
    use std::net::IpAddr;

    fn ip(text: &str) -> IpAddr {
        text.parse()
            .unwrap_or_else(|_| unreachable!("test uses valid IPs"))
    }

    #[test]
    fn wildcard_bind_selects_first_global_unicast_candidate() {
        // 0.0.0.0 bind with a port range's first port handled elsewhere; here
        // the host resolves to the first global-unicast candidate.
        let host = select_advertise_host(None, "0.0.0.0", "", || {
            vec![ip("127.0.0.1"), ip("10.0.0.7"), ip("10.0.0.8")]
        })
        .unwrap_or_else(|_| unreachable!("a candidate is available"));
        assert_eq!(host.as_ref(), "10.0.0.7");
    }

    #[test]
    fn explicit_dns_override_is_not_rewritten_and_skips_interface_scan() {
        // The provider must not even run when an override is present.
        let host = select_advertise_host(Some("proxy.dns.local"), "0.0.0.0", "", || {
            unreachable!("override must not trigger an interface scan")
        })
        .unwrap_or_else(|_| unreachable!("override wins"));
        assert_eq!(host.as_ref(), "proxy.dns.local");
    }

    #[test]
    fn ha_virtual_ip_candidate_is_excluded() {
        // Go excludes a candidate that is a prefix of the HA virtual IP.
        let host = select_advertise_host(None, "::", "10.0.0.5/24", || {
            vec![ip("10.0.0.5"), ip("10.0.0.9")]
        })
        .unwrap_or_else(|_| unreachable!("a non-VIP candidate is available"));
        assert_eq!(host.as_ref(), "10.0.0.9");
    }

    #[test]
    fn ipv6_link_local_candidate_is_skipped() {
        // fe80::/10 is link-local, not global-unicast (Go IsGlobalUnicast).
        let host = select_advertise_host(None, "::", "", || vec![ip("fe80::1"), ip("2001:db8::1")])
            .unwrap_or_else(|_| unreachable!("a global candidate is available"));
        assert_eq!(host.as_ref(), "2001:db8::1");
    }

    #[test]
    fn concrete_bind_host_is_kept_and_skips_interface_scan() {
        let host = select_advertise_host(None, "192.168.1.10", "", || {
            unreachable!("concrete bind host must not trigger an interface scan")
        })
        .unwrap_or_else(|_| unreachable!("concrete bind host is kept"));
        assert_eq!(host.as_ref(), "192.168.1.10");
    }

    #[test]
    fn wildcard_bind_without_candidate_fails_closed() {
        assert!(select_advertise_host(None, "0.0.0.0", "", || vec![ip("127.0.0.1")]).is_err());
    }
}
