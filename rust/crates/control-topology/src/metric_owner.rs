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

//! Private owner enumeration and locally observed peer identities.

use control_external::{GenerationGate, IoFence};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

pub(crate) const OWNER_PREFIX: &str = "/tiproxy/metric_reader";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnerRecord {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub lease: i64,
    pub created: i64,
}

pub(crate) fn cluster_prefix(cluster: &str) -> String {
    match cluster.trim() {
        "" | "default" => OWNER_PREFIX.into(),
        name => format!("{OWNER_PREFIX}/{name}"),
    }
}

pub(crate) fn election_name(cluster: &str, zone: &str) -> String {
    let prefix = cluster_prefix(cluster);
    if zone.is_empty() {
        format!("{prefix}/owner")
    } else {
        format!("{prefix}/{zone}/owner")
    }
}

// Match Go's substring classification and minimum creation revision exactly;
// the full retained key/value/lease/create tuple supplies observed provenance.
pub(crate) fn select_owners(
    prefix: &str,
    records: Vec<OwnerRecord>,
) -> BTreeMap<String, OwnerRecord> {
    let mut owners: BTreeMap<String, OwnerRecord> = BTreeMap::new();
    for record in records {
        let Some(suffix) = record
            .key
            .strip_prefix(prefix.as_bytes())
            .and_then(|suffix| suffix.strip_prefix(b"/"))
        else {
            continue;
        };
        let zone = if suffix.starts_with(b"owner") {
            String::new()
        } else if let Some(end) = suffix.iter().position(|byte| *byte == b'/') {
            if end == 0 || !suffix[end + 1..].starts_with(b"owner") {
                continue;
            }
            let Ok(zone) = std::str::from_utf8(&suffix[..end]) else {
                continue;
            };
            zone.to_owned()
        } else {
            continue;
        };
        if owners
            .get(&zone)
            .is_none_or(|previous| previous.created > record.created)
        {
            owners.insert(zone, record);
        }
    }
    owners
}

pub(crate) struct PeerSet {
    pub members: BTreeMap<String, OwnerRecord>,
    gate: GenerationGate,
    boundary: Mutex<()>,
}
impl IoFence for PeerSet {
    fn is_live(&self) -> bool {
        self.gate.is_live()
    }
}
impl PeerSet {
    pub fn with_current<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let _guard = self.boundary.lock().unwrap_or_else(PoisonError::into_inner);
        self.is_live().then(action)
    }
    fn revoke(&self) {
        let _guard = self.boundary.lock().unwrap_or_else(PoisonError::into_inner);
        self.gate.revoke();
    }
    pub fn zones(&self) -> Vec<String> {
        self.members
            .keys()
            .filter(|zone| !zone.is_empty())
            .cloned()
            .collect()
    }
    pub fn addresses(&self) -> Vec<String> {
        self.members
            .values()
            .filter_map(|record| String::from_utf8(record.value.clone()).ok())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Default)]
pub(crate) struct PeerObservation {
    current: Option<Arc<PeerSet>>,
}
impl PeerObservation {
    pub fn observe(&mut self, members: BTreeMap<String, OwnerRecord>) -> (Arc<PeerSet>, bool) {
        if let Some(current) = &self.current
            && current.members == members
        {
            return (Arc::clone(current), false);
        }
        if let Some(previous) = self.current.take() {
            previous.revoke();
        }
        let current = Arc::new(PeerSet {
            members,
            gate: GenerationGate::new(),
            boundary: Mutex::new(()),
        });
        self.current = Some(Arc::clone(&current));
        (current, true)
    }
}
impl Drop for PeerObservation {
    fn drop(&mut self) {
        if let Some(current) = &self.current {
            current.revoke();
        }
    }
}

#[cfg(test)]
mod tests;
