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

//! Topology discovery data model and the poll parser.
//!
//! The parser mirrors Go `infosync.InfoSyncer.GetTiDBTopology`
//! (`pkg/manager/infosync/info.go`): it consumes the raw key/value pairs from a
//! prefix read of `/topology/tidb/` and `/keyspaces/tidb/`, extracts the
//! keyspace from the path, and keeps only the `info` records that have a
//! matching `ttl` sibling (the etcd-side liveness gate — a backend whose lease
//! expired loses its `ttl` key and is dropped).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// Classic (non-keyspace) `TiDB` topology prefix.
const TIDB_PREFIX: &str = "/topology/tidb/";
/// Keyspace-scoped `TiDB` topology prefix.
const KEYSPACE_PREFIX: &str = "/keyspaces/tidb/";
/// The relative segment inside a keyspace path that precedes `<addr>`.
const KEYSPACE_TIDB_SEGMENT: &str = "topology/tidb/";
/// Key leaf holding the JSON info blob.
const INFO_SUFFIX: &str = "info";
/// Key leaf holding the liveness heartbeat.
const TTL_SUFFIX: &str = "ttl";

/// One discovered, live `TiDB` backend, projected from its `/topology/tidb` (or
/// `/keyspaces/tidb`) `info` record after the liveness gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendInfo {
    /// The backend SQL address (`host:port`), taken from the etcd key.
    pub addr: String,
    /// The keyspace parsed from the etcd path; empty for classic topology.
    /// This is authoritative for cross-keyspace routing decisions and must be
    /// preferred over any operator-set label.
    pub keyspace: String,
    /// The backend's advertised IP (from the info blob; empty for static).
    pub ip: String,
    /// The backend's status (HTTP) port. Widened to `u64` to match Go's `uint`
    /// so record acceptance is identical for out-of-`u32`-range values.
    pub status_port: u64,
    /// The backend's build version string.
    pub version: String,
    /// The backend's build git hash.
    pub git_hash: String,
    /// The backend's deploy path.
    pub deploy_path: String,
    /// The backend's start timestamp (unix seconds).
    pub start_timestamp: i64,
    /// The backend's advertised labels, ordered by key for determinism.
    pub labels: BTreeMap<String, String>,
}

/// Typed projection of a `TiDB` `info` record used to match Go's
/// `json.Unmarshal` into the concrete `TiDBTopologyInfo` struct exactly.
///
/// Each field is `Option` with `#[serde(default)]` so a missing or `null`
/// value defaults (as Go leaves the zero value) while a wrong JSON type fails
/// the whole record (as Go's typed unmarshal does). Unknown fields are ignored,
/// also matching Go. `status_port` is `u64` to mirror Go's `uint`.
#[derive(Deserialize)]
struct RawBackendInfo {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    status_port: Option<u64>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    git_hash: Option<String>,
    #[serde(default)]
    deploy_path: Option<String>,
    #[serde(default)]
    start_timestamp: Option<i64>,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
}

impl BackendInfo {
    /// Parses one `info` record. Returns `None` when the record is not valid
    /// JSON or has a wrong-typed field, matching Go's concrete `json.Unmarshal`
    /// which rejects (and thus skips) the whole entry on a type mismatch.
    fn from_info_json(addr: &str, keyspace: &str, raw: &[u8]) -> Option<Self> {
        let parsed: RawBackendInfo = serde_json::from_slice(raw).ok()?;
        Some(Self {
            addr: addr.to_owned(),
            keyspace: keyspace.to_owned(),
            ip: parsed.ip.unwrap_or_default(),
            status_port: parsed.status_port.unwrap_or_default(),
            version: parsed.version.unwrap_or_default(),
            git_hash: parsed.git_hash.unwrap_or_default(),
            deploy_path: parsed.deploy_path.unwrap_or_default(),
            start_timestamp: parsed.start_timestamp.unwrap_or_default(),
            labels: parsed.labels.unwrap_or_default(),
        })
    }
}

/// An immutable, liveness-filtered view of the discovered backend topology,
/// deterministically ordered by backend address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopologySnapshot {
    /// The live backends, sorted by `addr`.
    pub backends: Vec<BackendInfo>,
}

/// Splits a topology key into `(keyspace, "<addr>/<suffix>")`.
///
/// Returns `None` for any key that is neither under the classic
/// `/topology/tidb/` prefix nor a well-formed `/keyspaces/tidb/<keyspace>/…`
/// path, so malformed or unrelated keys are skipped (Go `continue`).
fn split_topology_key(key: &str) -> Option<(String, &str)> {
    if let Some(rest) = key.strip_prefix(KEYSPACE_PREFIX) {
        // rest = "<keyspace>/topology/tidb/<addr>/<suffix>"
        let (keyspace, after) = rest.split_once('/')?;
        if keyspace.is_empty() {
            return None;
        }
        let relative = after.strip_prefix(KEYSPACE_TIDB_SEGMENT)?;
        Some((keyspace.to_owned(), relative))
    } else if let Some(relative) = key.strip_prefix(TIDB_PREFIX) {
        Some((String::new(), relative))
    } else {
        None
    }
}

/// Parses a prefix read of `/topology/tidb/` + `/keyspaces/tidb/` into a
/// liveness-filtered [`TopologySnapshot`].
///
/// An `info` record is retained only when a `ttl` sibling exists for the same
/// address (Go's liveness gate). Addresses are the sole identity key, matching
/// Go's `map[string]*TiDBTopologyInfo` — a duplicate address across keyspaces
/// resolves to the last-parsed record, as in Go.
#[must_use]
pub fn parse_tidb_topology(entries: &[(Vec<u8>, Vec<u8>)]) -> TopologySnapshot {
    let mut infos: BTreeMap<String, BackendInfo> = BTreeMap::new();
    let mut alive: BTreeSet<String> = BTreeSet::new();
    for (raw_key, raw_value) in entries {
        let Ok(key) = std::str::from_utf8(raw_key) else {
            continue;
        };
        let Some((keyspace, relative)) = split_topology_key(key) else {
            continue;
        };
        let Some((addr, suffix)) = relative.rsplit_once('/') else {
            continue;
        };
        if addr.is_empty() {
            continue;
        }
        match suffix {
            TTL_SUFFIX => {
                alive.insert(addr.to_owned());
            }
            INFO_SUFFIX => {
                if let Some(info) = BackendInfo::from_info_json(addr, &keyspace, raw_value) {
                    infos.insert(addr.to_owned(), info);
                }
            }
            _ => {}
        }
    }
    let mut backends: Vec<BackendInfo> = infos
        .into_iter()
        .filter_map(|(addr, info)| alive.contains(&addr).then_some(info))
        .collect();
    backends.sort_by(|left, right| left.addr.cmp(&right.addr));
    TopologySnapshot { backends }
}

#[cfg(test)]
mod tests {
    use super::{BackendInfo, parse_tidb_topology};

    fn kv(key: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
        (key.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    fn info_value(ip: &str, status_port: u32) -> String {
        format!(
            r#"{{"version":"v8","git_hash":"abc","ip":"{ip}","status_port":{status_port},"deploy_path":"/d","start_timestamp":42,"labels":{{"zone":"z1"}}}}"#
        )
    }

    #[test]
    fn classic_backend_with_ttl_is_kept() {
        let entries = [
            kv(
                "/topology/tidb/10.0.0.1:4000/info",
                &info_value("10.0.0.1", 10080),
            ),
            kv("/topology/tidb/10.0.0.1:4000/ttl", "173000000000"),
        ];
        let snapshot = parse_tidb_topology(&entries);
        assert_eq!(snapshot.backends.len(), 1);
        let backend = &snapshot.backends[0];
        assert_eq!(backend.addr, "10.0.0.1:4000");
        assert_eq!(backend.keyspace, "");
        assert_eq!(backend.ip, "10.0.0.1");
        assert_eq!(backend.status_port, 10080);
        assert_eq!(backend.start_timestamp, 42);
        assert_eq!(backend.labels.get("zone").map(String::as_str), Some("z1"));
    }

    #[test]
    fn info_without_ttl_is_dropped() {
        let entries = [kv(
            "/topology/tidb/10.0.0.1:4000/info",
            &info_value("10.0.0.1", 10080),
        )];
        assert!(parse_tidb_topology(&entries).backends.is_empty());
    }

    #[test]
    fn ttl_without_info_yields_nothing() {
        let entries = [kv("/topology/tidb/10.0.0.1:4000/ttl", "1")];
        assert!(parse_tidb_topology(&entries).backends.is_empty());
    }

    #[test]
    fn keyspace_path_is_parsed_and_carried() {
        let entries = [
            kv(
                "/keyspaces/tidb/ks1/topology/tidb/10.0.0.2:4000/info",
                &info_value("10.0.0.2", 10080),
            ),
            kv("/keyspaces/tidb/ks1/topology/tidb/10.0.0.2:4000/ttl", "1"),
        ];
        let snapshot = parse_tidb_topology(&entries);
        assert_eq!(snapshot.backends.len(), 1);
        assert_eq!(snapshot.backends[0].keyspace, "ks1");
        assert_eq!(snapshot.backends[0].addr, "10.0.0.2:4000");
    }

    #[test]
    fn malformed_and_unrelated_keys_are_skipped() {
        let entries = [
            kv("/topology/tidb/bad:4000/info", "{not json"),
            kv("/topology/tidb/bad:4000/ttl", "1"),
            kv("/keyspaces/tidb//topology/tidb/x:1/info", "{}"), // empty keyspace
            kv("/unrelated/key", "{}"),
            kv("/topology/tidb/", "1"), // no addr/suffix
        ];
        assert!(parse_tidb_topology(&entries).backends.is_empty());
    }

    #[test]
    fn output_is_sorted_by_addr() {
        let entries = [
            kv(
                "/topology/tidb/10.0.0.9:4000/info",
                &info_value("10.0.0.9", 1),
            ),
            kv("/topology/tidb/10.0.0.9:4000/ttl", "1"),
            kv(
                "/topology/tidb/10.0.0.1:4000/info",
                &info_value("10.0.0.1", 1),
            ),
            kv("/topology/tidb/10.0.0.1:4000/ttl", "1"),
        ];
        let snapshot = parse_tidb_topology(&entries);
        let addrs: Vec<&str> = snapshot.backends.iter().map(|b| b.addr.as_str()).collect();
        assert_eq!(addrs, vec!["10.0.0.1:4000", "10.0.0.9:4000"]);
    }

    #[test]
    fn missing_status_port_defaults_to_zero() {
        let info = BackendInfo::from_info_json("a:1", "", br#"{"ip":"1.2.3.4"}"#)
            .unwrap_or_else(|| unreachable!("valid info json parses"));
        assert_eq!(info.status_port, 0);
        assert_eq!(info.ip, "1.2.3.4");
    }

    #[test]
    fn wrong_type_field_rejects_whole_record() {
        // A string status_port is a type mismatch: Go's concrete unmarshal
        // rejects and skips the whole entry, so the parser must too.
        assert!(
            BackendInfo::from_info_json("a:1", "", br#"{"ip":"1.2.3.4","status_port":"nope"}"#)
                .is_none()
        );
    }

    #[test]
    fn wrong_type_label_value_rejects_whole_record() {
        assert!(BackendInfo::from_info_json("a:1", "", br#"{"labels":{"zone":5}}"#).is_none());
    }

    #[test]
    fn null_and_missing_fields_default() {
        let info = BackendInfo::from_info_json("a:1", "", br#"{"ip":null,"status_port":null}"#)
            .unwrap_or_else(|| unreachable!("null fields default like Go"));
        assert_eq!(info.ip, "");
        assert_eq!(info.status_port, 0);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let info = BackendInfo::from_info_json("a:1", "", br#"{"ip":"1.2.3.4","future":123}"#)
            .unwrap_or_else(|| unreachable!("unknown fields ignored like Go"));
        assert_eq!(info.ip, "1.2.3.4");
    }

    #[test]
    fn status_port_beyond_u32_is_accepted_like_go_uint() {
        let info = BackendInfo::from_info_json("a:1", "", br#"{"status_port":5000000000}"#)
            .unwrap_or_else(|| unreachable!("uint-range status_port is accepted"));
        assert_eq!(info.status_port, 5_000_000_000);
    }
}
