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

//! The complete per-round selection/scan/admission boundary uses one router lock.
use super::{Arc, Candidate, RouteError, Router, State};
use crate::scheduler::{CommandQueue, MigrationProgress};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub(crate) fn stopped(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}
impl Router {
    pub(crate) fn observe_close(&self, close: &crate::ForceClose) -> crate::Settlement {
        self.lock().ledger.observe_close(close)
    }
    pub(crate) fn migration_updates(
        &self,
    ) -> (
        watch::Receiver<Arc<control_config::ConfigNamespaceSnapshot>>,
        control_topology::BackendSourceHandle,
        watch::Receiver<control_plane::LifecycleSnapshot>,
    ) {
        self.sources.updates()
    }

    pub(crate) fn keyspace_records(&self) -> BTreeMap<u64, crate::KeyspaceRefusal> {
        self.lock()
            .schedules
            .iter()
            .filter_map(|(group, schedule)| {
                schedule.last_refusal.clone().map(|record| (*group, record))
            })
            .collect()
    }
    pub(crate) fn migration_progress(&self) -> BTreeMap<u64, MigrationProgress> {
        self.lock()
            .schedules
            .iter()
            .map(|(id, schedule)| (*id, schedule.progress))
            .collect()
    }
    pub(crate) fn refresh_failover(
        &self,
        candidate: &Candidate,
        now: Instant,
    ) -> Result<(), RouteError> {
        let mut state = self.lock();
        self.sources.validate(candidate)?;
        state.refresh(candidate)?;
        self.sources.validate(candidate)?;
        state.update_failover(candidate, now, self.wall_now()?);
        Ok(())
    }

    pub(crate) fn migration_round(
        &self,
        candidate: &Candidate,
        sender: &CommandQueue,
        redirects_enabled: bool,
        stop: &watch::Receiver<bool>,
        clock: &crate::scheduler::RoundClock,
    ) -> Result<(), RouteError> {
        let mut state = self.lock();
        self.sources.validate(candidate)?;
        state.refresh(candidate)?;
        self.sources.validate(candidate)?;
        if stopped(stop) {
            return Ok(());
        }
        let groups: Vec<_> = state.groups.keys().copied().collect();
        if redirects_enabled && state.supports_redirection {
            for group in &groups {
                if stopped(stop) {
                    return Ok(());
                }
                let now = clock.balance_now();
                self.with_balance_group(
                    &mut state,
                    candidate,
                    *group,
                    clock.wall()?,
                    |state, prepared, pair| {
                        let plan = match prepared {
                            Ok(Some(plan)) => plan,
                            Ok(None) => return Ok(()),
                            Err(RouteError::CrossKeyspace) => {
                                if let Some(pair) = pair {
                                    let source = Arc::clone(&state.backends[&pair.from].account);
                                    state.record_keyspace_refusal(
                                        &source,
                                        &pair.to,
                                        Some(pair.reason),
                                        now,
                                    );
                                }
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        };
                        let budget = state.schedules.entry(*group).or_default().budget(
                            plan.pair.rate,
                            now,
                            plan.redirects.len(),
                        );
                        let mut accepted = 0;
                        for redirect in &plan.redirects {
                            if stopped(stop) || accepted >= budget {
                                break;
                            }
                            match self.offer_redirect_locked(state, redirect, sender, now) {
                                Ok(true) => {
                                    accepted += 1;
                                    state.schedules.entry(*group).or_default().accepted(now);
                                }
                                Ok(false)
                                | Err(
                                    RouteError::RedirectPending
                                    | RouteError::CoolingDown
                                    | RouteError::ForceClosing
                                    | RouteError::NotActive,
                                ) => (),
                                Err(error) => return Err(error),
                            }
                        }
                        Ok(())
                    },
                )?;
            }
        }
        self.close_timed_out(&mut state, candidate, sender, stop, clock)
    }

    // The caller retains the same router lock across every balance and close pass.
    fn close_timed_out(
        &self,
        state: &mut State,
        candidate: &Candidate,
        sender: &CommandQueue,
        stop: &watch::Receiver<bool>,
        clock: &crate::scheduler::RoundClock,
    ) -> Result<(), RouteError> {
        // Go runs timeout closure even when migration capability is disabled.
        for group in state.groups.keys().copied().collect::<Vec<_>>() {
            let now = clock.close_now();
            let owners: Vec<_> = state
                .backends
                .values()
                .filter(|backend| {
                    backend.group == Some(group)
                        && backend.failover_since.is_some_and(|since| {
                            now.saturating_duration_since(since)
                                >= Duration::from_secs(candidate.policy.failover_timeout_seconds)
                        })
                })
                .map(|backend| Arc::clone(&backend.account))
                .collect();
            for owner in owners {
                for session in state.ledger.physical_sessions(&owner) {
                    if stopped(stop) {
                        return Ok(());
                    }
                    let close = match state.ledger.prepare_close(&session) {
                        Ok(close) => close,
                        Err(crate::ledger::LedgerError::ForceClosing) => continue,
                        Err(error) => return Err(error.into()),
                    };
                    self.sources.validate(candidate)?;
                    if sender.try_send(close.clone()).is_ok() {
                        state.ledger.admit_close(close);
                        let progress = &mut state.schedules.entry(group).or_default().progress;
                        progress.closes = progress.closes.saturating_add(1);
                    }
                }
            }
        }
        Ok(())
    }
}
impl State {
    pub(super) fn record_keyspace_refusal(
        &mut self,
        source: &Arc<crate::ledger::AccountIdentity>,
        target_id: &str,
        reason: Option<crate::Factor>,
        now: Instant,
    ) {
        let Some(physical) = self
            .backends
            .values()
            .find(|b| Arc::ptr_eq(&b.account, source))
        else {
            return;
        };
        let Some(group) = physical.group else {
            return;
        };
        let Some(target) = self.backends.get(target_id) else {
            return;
        };
        let record = crate::KeyspaceRefusal {
            from: physical.source.backend_id.to_string(),
            to: target.source.backend_id.to_string(),
            from_keyspace: super::assignment(&physical.source, false).keyspace,
            to_keyspace: super::assignment(&target.source, false).keyspace,
            reason,
            physical_connections: self.ledger.counts(source).unwrap_or_default().active(),
            refusals: 0,
        };
        self.schedules
            .entry(group)
            .or_default()
            .refuse_keyspace(now, record);
    }

    fn update_failover(&mut self, candidate: &Candidate, now: Instant, wall: i64) {
        let mut effective = BTreeSet::new();
        let groups: Vec<_> = self.groups.keys().copied().collect();
        for group in groups {
            let inputs = self.factor_inputs(group, candidate);
            let routeable: Vec<_> = inputs
                .iter()
                .filter(|input| input.healthy && input.label_matches)
                .collect();
            let ignore = !routeable.is_empty()
                && routeable.iter().all(|input| {
                    self.backends[&input.id]
                        .routing_identity
                        .failed(&candidate.policy)
                });
            if candidate.policy.balance_policy == control_config::RoutingBalancePolicy::Connection {
                // Group.UpdateFailover scores all observed healthy members,
                // then the proposed mask, even when that mask is unchanged.
                // These passes reset/refresh Status history before Balance.
                let mut observed: Vec<_> = inputs
                    .iter()
                    .filter(|input| input.healthy)
                    .cloned()
                    .collect();
                if !observed.is_empty() {
                    let mut factors = self.prepare_factors(
                        group,
                        None,
                        &observed,
                        &candidate.config.resource_incarnation(),
                    );
                    let queries = crate::factors::Queries::new();
                    factors
                        .core
                        .evaluate(&observed, &candidate.policy, &queries, wall);
                    if !routeable.is_empty() {
                        for input in &mut observed {
                            input.healthy = !self.backends[&input.id]
                                .routing_identity
                                .failed(&candidate.policy);
                        }
                        factors
                            .core
                            .evaluate(&observed, &candidate.policy, &queries, wall);
                    }
                    self.factors.insert(group, factors);
                }
            }
            if !ignore {
                effective.extend(
                    inputs
                        .iter()
                        .filter(|input| {
                            self.backends[&input.id]
                                .routing_identity
                                .failed(&candidate.policy)
                        })
                        .map(|input| Arc::clone(&input.id)),
                );
            }
        }
        for (id, backend) in &mut self.backends {
            if effective.contains(id) {
                backend.failover_since.get_or_insert(now);
            } else {
                backend.failover_since = None;
            }
        }
    }
}

#[cfg(test)]
impl Router {
    pub(crate) fn worker_observation(
        &self,
        start: Instant,
        queue: &CommandQueue,
        label: &str,
    ) -> serde_json::Value {
        let state = self.lock();
        let (pending, closing, failed) = state.ledger.worker_observation(start);
        let mut counts = Vec::new();
        for addr in ["4000", "4001"] {
            let c = state
                .backends
                .values()
                .find(|b| b.source.backend_id.ends_with(addr))
                .and_then(|b| state.ledger.counts(&b.account))
                .unwrap_or_default();
            counts.extend([c.connection_score(), c.active()]);
        }
        let schedule = state.schedules.values().next();
        let watermark = schedule.and_then(|s| s.last_accepted).map_or(-1, |at| {
            i64::try_from(at.duration_since(start).as_nanos()).unwrap_or(i64::MAX)
        });
        let progress = schedule.map_or(MigrationProgress::default(), |s| s.progress);
        serde_json::json!({"label":label,"counts":counts,"pending":pending,"closing":closing,"failed":failed,"queue":queue.observation(),"watermark":watermark,"refusals":progress.keyspace_refusals,"records":progress.keyspace_records})
    }
    pub(crate) fn worker_backstop_for_test(
        &self,
        session: &crate::Session,
        candidate: &Candidate,
        sender: &CommandQueue,
        now: Instant,
    ) -> Result<bool, RouteError> {
        let mut state = self.lock();
        self.sources.validate(candidate)?;
        let source = Arc::clone(state.ledger.active_owner(session)?);
        let target = state
            .backends
            .values()
            .find(|b| b.source.backend_id.ends_with("4001"))
            .ok_or(RouteError::NoBackend)?;
        let prepared = crate::PreparedRedirect {
            session: session.clone(),
            candidate: candidate.clone(),
            source,
            target: Arc::clone(&target.account),
            target_id: Arc::clone(&target.source.backend_id),
        };
        self.offer_redirect_locked(&mut state, &prepared, sender, now)
    }
}
