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

//! Self-registration data model and the etcd key/value contract.
//!
//! This is the parity-critical half of `TiProxy` self-registration: the exact
//! JSON body and the `/topology/tiproxy/<addr>/{info,ttl}` keys that peers and
//! PD read to discover live proxies. It mirrors Go
//! `infosync.TopologyInfo` and `storeTopologyInfo` /
//! `updateTopologyAliveness` (`pkg/manager/infosync/info.go`) exactly, so a
//! Go/Rust differential of the published bytes stays byte-identical.
//!
//! The async lease loop that actually writes and refreshes these keys lives
//! separately; it consumes this module's pure formatting so the wire contract
//! can be unit-tested without an etcd server.

use serde::Serialize;

/// etcd base path under which every `TiProxy` instance publishes itself.
/// Matches Go `tiproxyTopologyPath`.
pub const TIPROXY_TOPOLOGY_PATH: &str = "/topology/tiproxy";
/// Registration lease time-to-live, in seconds. Matches Go
/// `topologySessionTTL`.
pub const TOPOLOGY_SESSION_TTL_SECS: i64 = 45;
/// Interval between full re-publishes of the `info` and `ttl` keys, in
/// seconds. Matches Go `topologyRefreshIntvl` (the lease keepalive runs
/// independently on the shorter TTL cadence).
pub const TOPOLOGY_REFRESH_INTERVAL_SECS: u64 = 30;

/// Key leaf holding the JSON info blob.
const INFO_SUFFIX: &str = "info";
/// Key leaf holding the liveness heartbeat.
const TTL_SUFFIX: &str = "ttl";

/// The self-published topology record for one `TiProxy` instance.
///
/// Field order, names, and types match Go `infosync.TopologyInfo` so
/// [`serde_json`] reproduces `json.Marshal` byte-for-byte. Note two Go quirks
/// preserved deliberately: `port` and `status_port` are **strings** (they come
/// from `net.SplitHostPort`), and there is **no** `labels` field (labels exist
/// only on the discovered-backend record, not on a proxy's own info).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TopologyInfo {
    /// Build version string (`versioninfo.TiProxyVersion`; default `"None"`).
    pub version: String,
    /// Build git hash (`versioninfo.TiProxyGitHash`; default `"None"`).
    pub git_hash: String,
    /// Advertised SQL host (an IP or, with `advertise-addr`, a DNS name).
    pub ip: String,
    /// Advertised SQL port, as a decimal string.
    pub port: String,
    /// HTTP status port, as a decimal string.
    pub status_port: String,
    /// Directory of the running executable (`path.Dir(os.Executable())`).
    pub deploy_path: String,
    /// Process start time, in unix seconds.
    pub start_timestamp: i64,
}

impl TopologyInfo {
    /// Builds a record from resolved advertise coordinates and build identity.
    ///
    /// `sql_port` / `status_port` are rendered to their decimal-string form to
    /// match Go, which carries them as `net.SplitHostPort` strings.
    #[must_use]
    pub fn new(
        advertise_host: &str,
        sql_port: u16,
        status_port: u16,
        version: &str,
        git_hash: &str,
        deploy_path: &str,
        start_timestamp: i64,
    ) -> Self {
        Self {
            version: version.to_owned(),
            git_hash: git_hash.to_owned(),
            ip: advertise_host.to_owned(),
            port: sql_port.to_string(),
            status_port: status_port.to_string(),
            deploy_path: deploy_path.to_owned(),
            start_timestamp,
        }
    }

    /// The instance address `<ip>:<port>` used inside the etcd keys.
    ///
    /// Uses Go `net.JoinHostPort` semantics: an `ip` that already contains a
    /// colon (an IPv6 literal) is wrapped in brackets.
    #[must_use]
    pub fn registration_addr(&self) -> String {
        if self.ip.contains(':') {
            format!("[{}]:{}", self.ip, self.port)
        } else {
            format!("{}:{}", self.ip, self.port)
        }
    }

    /// Serializes the record to its published JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json`] error if serialization fails, which for this
    /// fixed, non-recursive struct is not reachable in practice.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// The `/topology/tiproxy/<addr>/info` key for the given instance address.
#[must_use]
pub fn info_key(addr: &str) -> String {
    format!("{TIPROXY_TOPOLOGY_PATH}/{addr}/{INFO_SUFFIX}")
}

/// The `/topology/tiproxy/<addr>/ttl` key for the given instance address.
#[must_use]
pub fn ttl_key(addr: &str) -> String {
    format!("{TIPROXY_TOPOLOGY_PATH}/{addr}/{TTL_SUFFIX}")
}

/// The `ttl` heartbeat value: a unix-nanoseconds decimal string.
///
/// Matches Go `fmt.Sprintf("%v", time.Now().UnixNano())`. The value is
/// recomputed on every refresh so a stale sibling never masquerades as live.
#[must_use]
pub fn ttl_value(unix_nanos: i128) -> String {
    unix_nanos.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        TIPROXY_TOPOLOGY_PATH, TOPOLOGY_REFRESH_INTERVAL_SECS, TOPOLOGY_SESSION_TTL_SECS,
        TopologyInfo, info_key, ttl_key, ttl_value,
    };

    fn sample() -> TopologyInfo {
        TopologyInfo::new(
            "10.0.0.7",
            4000,
            10080,
            "v8.0.0",
            "abcdef",
            "/deploy/bin",
            1_700_000_000,
        )
    }

    #[test]
    fn json_matches_go_field_shape() {
        let json = String::from_utf8(
            sample()
                .to_json()
                .unwrap_or_else(|_| unreachable!("fixed struct serializes")),
        )
        .unwrap_or_else(|_| unreachable!("serde emits utf8"));
        // Field order, snake_case names, string ports, no labels: exactly Go.
        assert_eq!(
            json,
            r#"{"version":"v8.0.0","git_hash":"abcdef","ip":"10.0.0.7","port":"4000","status_port":"10080","deploy_path":"/deploy/bin","start_timestamp":1700000000}"#
        );
    }

    #[test]
    fn ports_are_strings_not_numbers() {
        let info = sample();
        assert_eq!(info.port, "4000");
        assert_eq!(info.status_port, "10080");
    }

    #[test]
    fn addr_and_keys_for_ipv4() {
        let info = sample();
        assert_eq!(info.registration_addr(), "10.0.0.7:4000");
        assert_eq!(
            info_key(&info.registration_addr()),
            "/topology/tiproxy/10.0.0.7:4000/info"
        );
        assert_eq!(
            ttl_key(&info.registration_addr()),
            "/topology/tiproxy/10.0.0.7:4000/ttl"
        );
    }

    #[test]
    fn ipv6_host_is_bracketed_like_join_host_port() {
        let info = TopologyInfo::new("::1", 4000, 10080, "v", "h", "/d", 1);
        assert_eq!(info.registration_addr(), "[::1]:4000");
        assert_eq!(
            info_key(&info.registration_addr()),
            "/topology/tiproxy/[::1]:4000/info"
        );
    }

    #[test]
    fn advertise_dns_name_is_used_verbatim() {
        let info = TopologyInfo::new("proxy.host.local", 4000, 10080, "v", "h", "/d", 1);
        assert_eq!(info.registration_addr(), "proxy.host.local:4000");
    }

    #[test]
    fn ttl_value_is_unix_nanos_decimal() {
        assert_eq!(
            ttl_value(1_700_000_000_123_456_789_i128),
            "1700000000123456789"
        );
        assert_eq!(ttl_value(0), "0");
    }

    #[test]
    fn constants_match_go() {
        assert_eq!(TIPROXY_TOPOLOGY_PATH, "/topology/tiproxy");
        assert_eq!(TOPOLOGY_SESSION_TTL_SECS, 45);
        assert_eq!(TOPOLOGY_REFRESH_INTERVAL_SECS, 30);
        // Re-publish must be strictly more frequent than lease expiry.
        let refresh = i64::try_from(TOPOLOGY_REFRESH_INTERVAL_SECS)
            .unwrap_or_else(|_| unreachable!("refresh interval fits i64"));
        assert!(refresh < TOPOLOGY_SESSION_TTL_SECS);
    }
}
