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

//! Connection-policy eligibility, separate from retry exclusions and scores.

use control_config::RoutingConfig;
use std::collections::BTreeMap;
use std::net::IpAddr;

// Go's wrapper fixes Addr and PodName when the backend owner is created.
// Neither field is recovered from the opaque (possibly cluster-qualified) ID.
pub(crate) struct RoutingIdentity {
    address: String,
    pod: String,
}

impl RoutingIdentity {
    pub(crate) fn new(address: &str) -> Self {
        Self {
            address: address.into(),
            pod: pod_name(address).into(),
        }
    }

    pub(crate) fn failed(&self, policy: &RoutingConfig) -> bool {
        policy
            .failed_backends
            .iter()
            .any(|target| target.as_ref() == self.address || target.as_ref() == self.pod)
    }
}

pub(crate) fn label_matches(policy: &RoutingConfig, labels: &BTreeMap<String, String>) -> bool {
    // The real config manager merges TOML into the previous map: omission and
    // an empty table cannot turn a previously populated labels map into nil.
    // Missing/empty self values disable the factor, including its first use.
    let self_value = policy
        .proxy_labels
        .iter()
        .find(|(name, _)| name == &policy.label_name)
        .map(|(_, value)| value.as_ref())
        .unwrap_or_default();
    policy.label_name.is_empty()
        || self_value.is_empty()
        || labels
            .get(policy.label_name.as_ref())
            .is_some_and(|value| value == self_value)
}

pub(crate) fn pod_name(address: &str) -> &str {
    let host = split_host_port(address).unwrap_or(address);
    if host.parse::<IpAddr>().is_ok() {
        host
    } else {
        host.split('.').next().unwrap_or_default()
    }
}

// net.SplitHostPort checks brackets/colon structure but does not require a
// numeric/nonempty port. Health's dial-address parser is intentionally stricter.
fn split_host_port(address: &str) -> Option<&str> {
    let (host, port) = address.rsplit_once(':')?;
    if port.contains(['[', ']']) {
        return None;
    }
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.strip_suffix(']')?
    } else {
        if host.contains(':') {
            return None;
        }
        host
    };
    if host.contains(['[', ']']) {
        return None;
    }
    Some(host)
}
