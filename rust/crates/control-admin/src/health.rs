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

//! Go-compatible `/api/debug/health` decision and manual override state.
//!
//! The decision order, status codes, and JSON body mirror the Go handler
//! (`pkg/server/api/debug.go`): a manual override wins outright, then a
//! closing server, then a not-ready namespace owner, then a dataplane that
//! has never applied a configuration; otherwise `200` with the checksum only.

use std::sync::{Arc, RwLock};

/// Operator-supplied readiness override, stored per process and never
/// persisted or replicated (same as the Go `atomic.Pointer`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthOverride {
    /// Whether the operator forces the endpoint healthy or unhealthy.
    pub healthy: bool,
    /// Whitespace-trimmed reason reported while the override is unhealthy.
    pub reason: String,
}

/// Live inputs the wiring supplies for one health evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthInputs {
    /// The process has begun closing (`PreClose` in Go).
    pub closing: bool,
    /// The config/namespace owner has published its first complete view.
    pub namespaces_ready: bool,
    /// Latest configuration generation applied to SQL serving; `0` before
    /// the first apply or while the metering consumer is unhealthy.
    pub applied_generation: u64,
    /// CRC32-IEEE over the canonical effective TOML, identical to Go's.
    pub config_checksum: u32,
}

/// One evaluated health response: status code plus the exact JSON body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthResponse {
    /// `200` or `502`, exactly as Go answers.
    pub status: u16,
    /// Compact JSON `{"config_checksum":N}` with `unhealthy_reason` only
    /// when non-empty (Go `omitempty`).
    pub body: String,
}

/// Shared override slot.
#[derive(Clone, Debug, Default)]
pub struct HealthState {
    manual: Arc<RwLock<Option<HealthOverride>>>,
}

impl HealthState {
    /// Creates an empty override slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores an override; the reason is trimmed like the Go handler.
    pub fn set_override(&self, healthy: bool, reason: &str) {
        let value = HealthOverride {
            healthy,
            reason: reason.trim().to_owned(),
        };
        if let Ok(mut slot) = self.manual.write() {
            *slot = Some(value);
        }
    }

    /// Clears the override so the natural rules apply again.
    pub fn clear_override(&self) {
        if let Ok(mut slot) = self.manual.write() {
            *slot = None;
        }
    }

    /// Returns the current override, if any.
    #[must_use]
    pub fn current_override(&self) -> Option<HealthOverride> {
        self.manual.read().ok().and_then(|slot| slot.clone())
    }

    /// Evaluates the Go decision order against the supplied inputs.
    #[must_use]
    pub fn evaluate(&self, inputs: &HealthInputs) -> HealthResponse {
        let reason = match self.current_override() {
            Some(HealthOverride { healthy, reason }) => (!healthy).then_some(reason),
            None => natural_reason(inputs).map(str::to_owned),
        };
        render(inputs.config_checksum, reason)
    }
}

/// The Go rule order once no override is present.
fn natural_reason(inputs: &HealthInputs) -> Option<&'static str> {
    if inputs.closing {
        Some("server is closing")
    } else if !inputs.namespaces_ready {
        Some("server is not ready")
    } else if inputs.applied_generation == 0 {
        Some("Rust dataplane has no applied configuration")
    } else {
        None
    }
}

/// Renders the Go `config.HealthInfo` JSON. `unhealthy_reason` carries the
/// `omitempty` tag, so an unhealthy override with an empty reason still
/// answers `502` with the checksum alone.
fn render(checksum: u32, reason: Option<String>) -> HealthResponse {
    let status = if reason.is_some() { 502 } else { 200 };
    let body = match reason.filter(|reason| !reason.is_empty()) {
        Some(reason) => format!(
            "{{\"config_checksum\":{checksum},\"unhealthy_reason\":{}}}",
            serde_json::Value::String(reason)
        ),
        None => format!("{{\"config_checksum\":{checksum}}}"),
    };
    HealthResponse { status, body }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> HealthInputs {
        HealthInputs {
            closing: false,
            namespaces_ready: true,
            applied_generation: 4,
            config_checksum: 3_405_691_582,
        }
    }

    #[test]
    fn healthy_reports_only_the_checksum() {
        let state = HealthState::new();
        assert_eq!(
            state.evaluate(&ready()),
            HealthResponse {
                status: 200,
                body: "{\"config_checksum\":3405691582}".to_owned()
            }
        );
    }

    #[test]
    fn natural_rules_follow_the_go_order() {
        let state = HealthState::new();
        let mut inputs = ready();
        inputs.applied_generation = 0;
        assert_eq!(
            state.evaluate(&inputs).body,
            "{\"config_checksum\":3405691582,\"unhealthy_reason\":\"Rust dataplane has no applied configuration\"}"
        );
        inputs.namespaces_ready = false;
        assert!(state.evaluate(&inputs).body.contains("server is not ready"));
        inputs.closing = true;
        let response = state.evaluate(&inputs);
        assert_eq!(response.status, 502);
        assert!(
            response
                .body
                .contains("\"unhealthy_reason\":\"server is closing\"")
        );
    }

    #[test]
    fn override_wins_in_both_directions_and_trims_reason() {
        let state = HealthState::new();
        let mut inputs = ready();
        inputs.applied_generation = 0;
        state.set_override(true, "manual-restore");
        assert_eq!(state.evaluate(&inputs).status, 200);
        assert!(!state.evaluate(&inputs).body.contains("unhealthy_reason"));
        state.set_override(false, "  maintenance \n");
        assert_eq!(
            state.evaluate(&ready()).body,
            "{\"config_checksum\":3405691582,\"unhealthy_reason\":\"maintenance\"}"
        );
        state.set_override(false, "");
        let response = state.evaluate(&ready());
        assert_eq!(response.status, 502);
        assert_eq!(response.body, "{\"config_checksum\":3405691582}");
        state.clear_override();
        assert_eq!(state.evaluate(&ready()).status, 200);
    }

    #[test]
    fn reason_is_json_escaped() {
        let state = HealthState::new();
        state.set_override(false, "quote \" and \\ slash");
        assert_eq!(
            state.evaluate(&ready()).body,
            "{\"config_checksum\":3405691582,\"unhealthy_reason\":\"quote \\\" and \\\\ slash\"}"
        );
    }
}
