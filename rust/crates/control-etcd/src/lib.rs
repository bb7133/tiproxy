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

//! PD-etcd session, lease, election, watch, and transaction ownership.
//!
//! This crate is the only stateful etcd owner in the Rust control plane.  It
//! builds on `control-external` for bounded TLS/multi-endpoint connectivity and
//! carries the exact process-owner generation from `control-plane` through
//! every state transition.  A transport failure makes ownership uncertain but
//! does not retire it; only a missing lease, a different election leader, an
//! expired process owner, or explicit shutdown crosses the retirement fence.

#![forbid(unsafe_code)]

mod config;
mod session;

pub use config::{ElectionConfig, ElectionConfigError};
pub use session::{
    ElectionError, ElectionSession, ElectionSnapshot, ElectionState, PersistentDeleteResult,
    PersistentPutMode, PersistentPutOutcome, PersistentPutResult, RecoveryOutcome,
    RetirementReason, WatchOutcome,
};
