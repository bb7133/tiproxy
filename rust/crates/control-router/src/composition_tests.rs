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

use super::*;
use control_config::{ConfigNamespaceSource, ConfigNamespaceStore};
use control_topology::BackendInfo;
use serde_json::Value;
use std::fmt::Write;
use std::path::Path;

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
}
fn string(value: &Value) -> &str {
    value.as_str().unwrap_or_else(|| unreachable!("string"))
}
fn array(value: &Value) -> &[Value] {
    value.as_array().unwrap_or_else(|| unreachable!("array"))
}
fn number(value: &Value) -> u64 {
    value.as_u64().unwrap_or_else(|| unreachable!("number"))
}

#[test]
fn shared_go_composition_observation() {
    let Ok(input) = std::env::var("CPROUTE_COMPOSITION_FIXTURE") else {
        return;
    };
    let fixture: Value = must(serde_json::from_slice(&must(std::fs::read(input))));
    let mut output = String::new();
    for scenario in array(&fixture["scenarios"]) {
        let store = must(ConfigNamespaceStore::from_toml(
            b"[balance]\npolicy=\"connection\"",
            None,
            Path::new("/tmp"),
        ));
        // Exercise the same production eligibility method that reserve calls.
        // This fixture tests policy inputs, not fabricated source authority.
        let mut state = State {
            ledger: Ledger::new(100),
            factors: BTreeMap::new(),
            schedules: BTreeMap::new(),
            backends: BTreeMap::new(),
            groups: BTreeMap::new(),
            ports: PortRoutes::default(),
            next_group: 1,
            observed: None,
        };
        for backend in array(&scenario["backends"]) {
            let id: Arc<str> = Arc::from(string(&backend["id"]));
            let addr = string(&backend["addr"]);
            state.backends.insert(
                Arc::clone(&id),
                Backend {
                    source: MergedBackend {
                        backend_id: id,
                        cluster_name: Arc::from("fixture"),
                        backend: BackendInfo {
                            addr: addr.into(),
                            keyspace: String::new(),
                            ip: String::new(),
                            status_port: 0,
                            version: String::new(),
                            git_hash: String::new(),
                            deploy_path: String::new(),
                            start_timestamp: 0,
                            labels: must(serde_json::from_value(backend["labels"].clone())),
                        },
                    },
                    routing_identity: RoutingIdentity::new(addr),
                    account: must(state.ledger.add_account()),
                    healthy: backend["healthy"].as_bool().unwrap_or(false),
                    group: Some(number(&backend["group"])),
                    failover_since: None,
                },
            );
        }
        for (index, row) in array(&scenario["steps"]).iter().enumerate() {
            must(store.apply_toml(
                string(&row["toml"]).as_bytes(),
                None,
                index as u64 + 2,
                Path::new("/tmp"),
            ));
            let policy = must(store.current().effective().routing());
            let excluded: Vec<&str> = array(&row["excluded"]).iter().map(string).collect();
            let ids: Vec<&str> = state
                .routeable(number(&row["group"]), &policy, &excluded)
                .iter()
                .map(|(backend, _)| backend.source.backend_id.as_ref())
                .collect();
            must(writeln!(
                output,
                "{}\t{}",
                string(&row["name"]),
                ids.join(",")
            ));
        }
    }
    for (index, addr) in array(&fixture["pods"]).iter().enumerate() {
        must(writeln!(
            output,
            "pod-{index}\t{}",
            crate::policy::pod_name(string(addr))
        ));
    }
    if let Ok(expected) = std::env::var("CPROUTE_COMPOSITION_EXPECTED") {
        assert_eq!(output, must(std::fs::read_to_string(expected)));
    }
    must(std::fs::write(
        must(std::env::var("CPROUTE_COMPOSITION_OUTPUT")),
        output,
    ));
}
