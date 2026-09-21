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

//! Stateful, process-local routing and exact reservation accounting.

mod authority;
mod backend_metric_history;
mod factors;
mod ledger;
mod migration_history;
mod namespace;
mod plane;
mod policy;
mod retry;
mod scheduler;
mod score_history;
mod selector;
mod simulation;

/// Observation-only routing ledger; never a production command authority.
pub mod shadow;

pub use authority::{Candidate, RouteError, Unsupported};
pub use factors::{
    BalanceAdvice, BalancePair, Factor, FactorAdvice, FactorReport, FactorScore, RedirectReason,
};
pub use ledger::{
    Accounting, ForceClose, Redirect, Reservation, RouteLedgerEvidence, Session, Settlement,
};
pub use namespace::{ResolvedNamespace, RouteCandidateValidator, UserNamespaceResolver};
pub use plane::{
    MigrationSnapshot, RouteAdmission, RouteInputEvidence, RoutePlane, RoutePlaneHandle,
};

/// Outcome of one management redirect sweep (Go `RedirectConnections`):
/// counts only, no authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RedirectAllSummary {
    /// Active sessions at the sweep.
    pub active: u64,
    /// Sessions offered a self-redirect (active minus those already pending).
    pub offered: u64,
    /// Offers the migration queue accepted.
    pub accepted: u64,
}

impl RedirectAllSummary {
    /// Sums another router's sweep into this one.
    pub fn add(&mut self, other: Self) {
        self.active += other.active;
        self.offered += other.offered;
        self.accepted += other.accepted;
    }
}
pub use backend_metric_history::{BackendMetric, BackendMetricHistory, BackendMetricSnapshot};
pub use ledger::{MigrationLabels, MigrationObservation, MigrationOutcome, MigrationTotals};
pub use migration_history::{
    DurationKey, DurationSeries, MAX_RETAINED_LABEL_SETS, MIGRATE_DURATION_BUCKETS,
    MigrationHistory, MigrationHistorySnapshot, TerminalKey,
};
pub use retry::Selector;
pub use score_history::{SCORE_METRIC_INTERVAL, ScoreHistory, ScoreSnapshot};
pub use selector::{MigrationSink, Router};
pub use simulation::{MigrationSimulation, PreparedBalance, PreparedRedirect};

#[cfg(test)]
mod tests;

pub use scheduler::{
    KeyspaceRefusal, MigrationCommand, MigrationProgress, RouteCommandDispatcher,
    RouteCommandEnvelope, RouteCommandReceiver, RouteCommandRegistration,
};
