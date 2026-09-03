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
    /// The backend's status (HTTP) port.
    pub status_port: u32,
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

impl BackendInfo {
    /// Parses one `info` record. Returns `None` on any malformed JSON, matching
    /// Go's behaviour of logging and skipping an unparseable entry.
    fn from_info_json(addr: &str, keyspace: &str, raw: &[u8]) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
        let object = value.as_object()?;
        let string_field = |name: &str| -> String {
            object
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let labels = object
            .get("labels")
            .and_then(serde_json::Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            addr: addr.to_owned(),
            keyspace: keyspace.to_owned(),
            ip: string_field("ip"),
            status_port: object
                .get("status_port")
                .and_then(serde_json::Value::as_u64)
                .and_then(|port| u32::try_from(port).ok())
                .unwrap_or(0),
            version: string_field("version"),
            git_hash: string_field("git_hash"),
            deploy_path: string_field("deploy_path"),
            start_timestamp: object
                .get("start_timestamp")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            labels,
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
}
