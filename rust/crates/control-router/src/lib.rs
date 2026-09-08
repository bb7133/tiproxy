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
mod factors;
mod ledger;
mod policy;
mod retry;
mod scheduler;
mod selector;
mod simulation;

pub use authority::{Candidate, RouteError, Unsupported};
pub use factors::{BalanceAdvice, BalancePair, Factor, FactorAdvice, FactorReport, FactorScore};
pub use ledger::{Accounting, ForceClose, Redirect, Reservation, Session, Settlement};
pub use retry::Selector;
pub use selector::Router;
pub use simulation::{MigrationSimulation, PreparedBalance, PreparedRedirect};

#[cfg(test)]
mod tests;

pub use scheduler::{KeyspaceRefusal, MigrationCommand, MigrationProgress};
