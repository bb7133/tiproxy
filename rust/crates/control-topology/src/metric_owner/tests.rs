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
fn record(key: &str, value: &str, lease: i64, created: i64) -> OwnerRecord {
    OwnerRecord {
        key: key.as_bytes().into(),
        value: value.as_bytes().into(),
        lease,
        created,
    }
}
#[test]
fn collector_owner_recipe_minimum_revision_and_observed_aba() {
    let prefix = cluster_prefix(" cluster-a ");
    let records = vec![
        record(&format!("{prefix}/owner/1"), "host:10080", 1, 4),
        record(&format!("{prefix}/owner/2"), "later:10080", 2, 9),
        record(&format!("{prefix}/east/owner/3"), "host:10080", 3, 7),
        record(&format!("{prefix}/west/owner/4"), "west:10080", 4, 8),
        record(&format!("{prefix}garbage/owner/5"), "bad:1", 5, 1),
        record(&format!("{prefix}/sessions/5"), "bad:2", 5, 1),
    ];
    let members = select_owners(&prefix, records);
    assert_eq!(members.len(), 3, "COLLECTOR_OWNER_RECIPE");
    assert_eq!(members[""].lease, 1, "COLLECTOR_OWNER_MIN_CREATE");
    let mut observation = PeerObservation::default();
    let (first, changed) = observation.observe(members.clone());
    assert!(changed);
    assert_eq!(
        first.addresses(),
        ["host:10080", "west:10080"],
        "COLLECTOR_OWNER_DEDUP"
    );
    assert_eq!(first.zones(), ["east", "west"]);
    assert!(Arc::ptr_eq(&first, &observation.observe(members.clone()).0));
    for field in ["key", "value", "lease", "created"] {
        let mut next = members.clone();
        let entry = next.get_mut("east").unwrap_or_else(|| unreachable!());
        match field {
            "key" => entry.key.push(b'0'),
            "value" => entry.value.push(b'0'),
            "lease" => entry.lease += 1,
            _ => entry.created += 1,
        }
        let old = observation.observe(members.clone()).0;
        let fresh = observation.observe(next).0;
        assert!(!old.is_live(), "COLLECTOR_PEER_{field}_REPLACEMENT");
        assert_eq!(old.with_current(|| 7), None, "COLLECTOR_PEER_FINAL_CHECK");
        observation.observe(members.clone());
        assert!(!fresh.is_live() && !old.is_live(), "COLLECTOR_PEER_ABA");
    }
    let retained = observation.observe(members).0;
    drop(observation);
    assert!(!retained.is_live(), "COLLECTOR_PEER_DROP");
}
