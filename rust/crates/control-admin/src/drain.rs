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

//! `/api/dataplane/drain` and `/api/dataplane/drain/{id}` (CP-ADMIN slice 3):
//! the Go handler's validation, status codes and bodies over a local drain
//! seam that the executable binds to the dispatch owner.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{AdminFuture, Schema};

/// Go `controlbridge.MaxDrainDeadlineAhead` in milliseconds (30 days).
pub const MAX_DRAIN_BUDGET_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Go `drainRequestBody`, tags lowercase, `drain_id` required.
pub const DRAIN_SCHEMA: Schema = Schema::Object(&[
    ("drain_id", Schema::Str),
    ("listener_names", Schema::StrList),
    ("backend_ids", Schema::StrList),
    ("graceful_wait_ms", Schema::Int),
    ("force_timeout_ms", Schema::Int),
]);

/// Validated operator drain request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainRequest {
    /// Operator label (Go `drain_id`).
    pub drain_id: String,
    /// Listener scope.
    pub listener_names: Vec<String>,
    /// Backend scope.
    pub backend_ids: Vec<String>,
    /// Safe-point close window.
    pub graceful_wait: Duration,
    /// Force-close window after the graceful deadline.
    pub force_timeout: Duration,
}

/// Go `Bridge.StartDrain` error classes, mapped by the handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainStartError {
    /// `400`: Go `ErrInvalidDrainBudget`.
    InvalidBudget,
    /// `503`: Go `ErrNoDataplaneSession`.
    NoSession,
    /// `503`: Go `ErrSnapshotNotReady`.
    SnapshotNotReady,
    /// `409`: Go `ErrDrainInProgress`.
    InProgress,
    /// `409`: Go `ErrForeignDrainActive`.
    ForeignActive,
    /// `500`: any other error, with its bounded message.
    Other(String),
}

impl DrainStartError {
    /// The Go error string for the JSON `error` member.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::InvalidBudget => {
                "drain budget is negative or exceeds the 30-day deadline cap".to_owned()
            }
            Self::NoSession => "no active Rust dataplane control session".to_owned(),
            Self::SnapshotNotReady => "no applied configuration generation yet".to_owned(),
            Self::InProgress => "a different drain is already in progress".to_owned(),
            Self::ForeignActive => {
                "a previous incarnation's drain is still active on the dataplane".to_owned()
            }
            Self::Other(message) => message.clone(),
        }
    }
}

/// Latest progress/terminal for one drain, in the Go response shape.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrainProgress {
    /// Matched population at admission.
    pub active_connections: u64,
    /// Sessions closed at a safe point.
    pub gracefully_closed: u64,
    /// Sessions force-closed.
    pub force_closed: u64,
    /// Whether this is the terminal.
    pub complete: bool,
    /// Proto enum name of the result code.
    pub code: String,
    /// Bounded detail.
    pub detail: String,
}

/// Local drain seam behind the endpoints.
pub trait DrainAdmin: Send + Sync {
    /// Starts or idempotently re-issues a drain.
    fn start(&self, request: DrainRequest) -> AdminFuture<'_, Result<(), DrainStartError>>;
    /// Latest observed progress for a label; `None` when unknown.
    fn status(&self, drain_id: String) -> AdminFuture<'_, Option<DrainProgress>>;
}

/// Shared handle type the router stores.
pub type SharedDrainAdmin = Arc<dyn DrainAdmin>;

/// Scripted [`DrainAdmin`] for tests and the differential replay: answers
/// `start` from a queue of outcomes and `status` from a map.
#[derive(Debug, Default)]
pub struct ScriptedDrainAdmin {
    state: Mutex<ScriptedState>,
}

#[derive(Debug, Default)]
struct ScriptedState {
    starts: std::collections::VecDeque<Result<(), DrainStartError>>,
    statuses: std::collections::BTreeMap<String, DrainProgress>,
    requests: Vec<DrainRequest>,
}

impl ScriptedDrainAdmin {
    /// Queues the answer for the next `start`.
    pub fn push_start(&self, outcome: Result<(), DrainStartError>) {
        if let Ok(mut state) = self.state.lock() {
            state.starts.push_back(outcome);
        }
    }

    /// Sets the status answered for `drain_id`.
    pub fn set_status(&self, drain_id: &str, progress: DrainProgress) {
        if let Ok(mut state) = self.state.lock() {
            state.statuses.insert(drain_id.to_owned(), progress);
        }
    }

    /// Requests that reached the seam, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<DrainRequest> {
        self.state
            .lock()
            .map(|state| state.requests.clone())
            .unwrap_or_default()
    }
}

impl DrainAdmin for ScriptedDrainAdmin {
    fn start(&self, request: DrainRequest) -> AdminFuture<'_, Result<(), DrainStartError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DrainStartError::Other("scripted drain poisoned".to_owned()))?;
            state.requests.push(request);
            state.starts.pop_front().unwrap_or(Ok(()))
        })
    }

    fn status(&self, drain_id: String) -> AdminFuture<'_, Option<DrainProgress>> {
        Box::pin(async move {
            self.state
                .lock()
                .ok()
                .and_then(|state| state.statuses.get(&drain_id).cloned())
        })
    }
}
