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

//! Effectless migration harness. Its queue carries local tokens only, never
//! production session commands. Its owned worker has no production effect sink.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use control_config::ConfigNamespaceSource;
use control_plane::ModuleContext;
use control_routing::group::ClientInfo;
use control_topology::{MetricOverlayHandle, TopologyModuleHandle};

use crate::ledger::AccountIdentity;
use crate::{Candidate, Redirect, RouteError, Router, Session, Settlement};

/// A read-only preparation tied to this simulation's sources and physical owner.
/// Retaining it does not retain permission to admit a redirect.
#[derive(Clone)]
pub struct PreparedRedirect {
    pub(crate) session: Session,
    pub(crate) candidate: Candidate,
    pub(crate) source: Arc<AccountIdentity>,
    pub(crate) target: Arc<AccountIdentity>,
    pub(crate) target_id: Arc<str>,
}

/// A factor-selected pair and its source sessions in physical arrival order.
/// Every entry must still pass the original final offer fence; preparing this
/// plan changes no session counts and does not bypass pending/cooldown checks.
pub struct PreparedBalance {
    pub(crate) pair: crate::BalancePair,
    pub(crate) redirects: Vec<PreparedRedirect>,
}
impl PreparedBalance {
    /// Diagnostic pair chosen from all retained owners in the selected group.
    #[must_use]
    pub const fn pair(&self) -> &crate::BalancePair {
        &self.pair
    }

    /// Source physical order, including pending redirects. The later scheduler
    /// skips ineligible entries; incoming redirects are absent until success.
    #[must_use]
    pub fn redirects(&self) -> &[PreparedRedirect] {
        &self.redirects
    }
}

/// A fresh, isolated router with a bounded queue of simulated admissions.
///
/// No constructor accepts a production router, transport, callback or effect
/// sender. Initial reservations can be exercised through `router()`, but every
/// count and redirect belongs solely to this simulation. This is not the #222-3
/// observational shadow: that later API must advance only from observed events.
pub struct MigrationSimulation {
    router: Router,
    pub(crate) sender: crate::scheduler::CommandQueue,
    running: AtomicBool,
    #[cfg(test)]
    initialized: AtomicBool,
}

impl MigrationSimulation {
    /// Creates a new router incarnation and private queue. Zero queue capacity
    /// rejects every simulated offer without advancing accepted state.
    /// # Errors
    /// Returns the namespace/source errors from `Router::new_with_factors`.
    pub fn new(
        source: Arc<dyn ConfigNamespaceSource>,
        topology: &TopologyModuleHandle,
        context: &ModuleContext,
        namespace: &str,
        max_sessions: usize,
        queue_capacity: usize,
        metrics: Option<MetricOverlayHandle>,
    ) -> Result<Self, RouteError> {
        Ok(Self {
            router: Router::new_with_factors(
                source,
                topology,
                context,
                namespace,
                max_sessions,
                metrics,
            )?,
            sender: crate::scheduler::CommandQueue::new(queue_capacity),
            running: AtomicBool::new(false),
            #[cfg(test)]
            initialized: AtomicBool::new(false),
        })
    }

    /// The isolated router used to establish simulated physical sessions.
    #[must_use]
    pub const fn router(&self) -> &Router {
        &self.router
    }

    /// Prepares a manually chosen destination exclusively in this simulation.
    /// Both owners must be in the current group and the target must be routeable.
    /// # Errors
    /// Rejects invalid sources, non-active sessions and ineligible targets.
    pub fn prepare(
        &self,
        session: &Session,
        candidate: &Candidate,
        target_id: &str,
    ) -> Result<PreparedRedirect, RouteError> {
        self.router.prepare_redirect(session, candidate, target_id)
    }

    /// Selects the actual factor migration pair and captures physical source
    /// order using this simulation's real C/R/H and optional producer metrics.
    /// This is preparation only: no timer, quota or failover-close worker runs.
    /// # Errors
    /// Rejects stale sources, missing groups and cross-keyspace pairs.
    pub fn prepare_balance(
        &self,
        candidate: &Candidate,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<Option<PreparedBalance>, RouteError> {
        self.router
            .prepare_balance(candidate, client, listener_port)
    }

    /// Tries one synchronous bounded offer after final validation under the
    /// router lock. `false` means queue rejection and records failure cooldown.
    /// # Errors
    /// Stale authority, changed physical ownership, pending operations,
    /// cooldown, cross-keyspace targets and exhaustion admit nothing.
    pub fn offer(&self, prepared: &PreparedRedirect) -> Result<bool, RouteError> {
        self.offer_at(prepared, Instant::now())
    }

    pub(crate) fn offer_at(
        &self,
        prepared: &PreparedRedirect,
        now: Instant,
    ) -> Result<bool, RouteError> {
        self.router.offer_redirect(prepared, &self.sender, now)
    }

    /// Removes one local simulated admission, without performing any I/O.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn take_redirect(&self) -> Option<Redirect> {
        self.sender.take_redirect()
    }

    /// Removes the oldest local command. Unlike `take_redirect`, this can drain
    /// a close command; `take_redirect` preserves a close at the queue head.
    #[must_use]
    pub fn take_command(&self) -> Option<crate::MigrationCommand> {
        self.sender.take()
    }

    /// Observes physical closure after an admitted close, even after revocation
    /// or a pending redirect result. Duplicate/foreign tokens are ignored.
    pub fn observe_close(&self, close: &crate::ForceClose) -> Settlement {
        self.router.observe_close(close)
    }

    /// Supplies a simulated terminal. Revoked sources do not revoke the exact
    /// captured operation's right to settle its retained accounting owners.
    pub fn finish(&self, redirect: &Redirect, success: bool) -> Settlement {
        self.finish_at(redirect, success, Instant::now())
    }

    pub(crate) fn finish_at(&self, redirect: &Redirect, success: bool, now: Instant) -> Settlement {
        self.router.finish_redirect(redirect, success, now)
    }
}

#[path = "simulation_worker.rs"]
mod worker;
