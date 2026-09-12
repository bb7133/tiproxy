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

//! Factor migration preparation under the existing namespace ledger lock.

use super::{Arc, Candidate, ClientInfo, RouteError, Router, read_queries};

impl Router {
    pub(crate) fn prepare_balance(
        &self,
        candidate: &Candidate,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<Option<crate::PreparedBalance>, RouteError> {
        let mut state = self.lock();
        self.sources.validate(candidate)?;
        state.refresh(candidate)?;
        let group = state.factor_group(candidate, client, listener_port)?;
        self.with_balance_group(
            &mut state,
            candidate,
            group,
            self.wall_now()?,
            |_, prepared, _| prepared,
        )
    }

    pub(super) fn with_balance_group<T>(
        &self,
        state: &mut super::State,
        candidate: &Candidate,
        group: u64,
        now: i64,
        mut use_prepared: impl FnMut(
            &mut super::State,
            Result<Option<crate::PreparedBalance>, RouteError>,
            Option<&crate::BalancePair>,
        ) -> Result<T, RouteError>,
    ) -> Result<T, RouteError> {
        let mut select = |metrics: Option<&control_topology::MetricSnapshot>,
                          queries: &crate::factors::Queries| {
            self.sources.validate(candidate)?;
            // Balance sees unhealthy/draining owners too. Route's healthy-only
            // prefilter would lose the very physical sources needing evacuation.
            let mut inputs = state.factor_inputs(group, candidate);
            let routeable: Vec<_> = inputs
                .iter()
                .filter(|input| input.healthy && input.label_matches)
                .collect();
            let ignore_failed = !routeable.is_empty()
                && routeable.iter().all(|input| {
                    state.backends[&input.id]
                        .routing_identity
                        .failed(&candidate.policy)
                });
            for input in &mut inputs {
                input.healthy &= ignore_failed
                    || !state.backends[&input.id]
                        .routing_identity
                        .failed(&candidate.policy);
            }
            let mut factors = state.prepare_factors(
                group,
                metrics,
                &inputs,
                &candidate.config.resource_incarnation(),
            );
            let report = factors
                .core
                .evaluate(&inputs, &candidate.policy, queries, now);
            let diagnostic_pair = report.balance.clone();
            let prepared = (|| {
                if let Some(pair) = report.balance {
                    let source = &state.backends[&pair.from];
                    let target = state.redirect_target(&source.account, candidate, &pair.to)?;
                    let redirects = state
                        .ledger
                        .physical_sessions(&source.account)
                        .into_iter()
                        .map(|session| crate::PreparedRedirect {
                            session,
                            candidate: candidate.clone(),
                            source: Arc::clone(&source.account),
                            target: Arc::clone(&target.account),
                            target_id: Arc::clone(&pair.to),
                        })
                        .collect();
                    Ok(Some(crate::PreparedBalance { pair, redirects }))
                } else {
                    Ok(None)
                }
            })();
            self.sources.validate(candidate)?;
            // Go updates factor history before Group refuses a cross-keyspace
            // pair. Refusal must not reset its first Status migration rate.
            state.factors.insert(group, factors);
            use_prepared(state, prepared, diagnostic_pair.as_ref())
        };
        let metrics = match &candidate.metrics {
            crate::authority::MetricInputs::StaticEmpty => None,
            crate::authority::MetricInputs::Dynamic(snapshot) => snapshot.as_deref(),
        };
        #[allow(clippy::collapsible_if)] // Test-only retirement barrier precedes final fence.
        if let Some(metrics) =
            metrics.filter(|metrics| Arc::ptr_eq(&candidate.routing, metrics.source().routing()))
            && let Ok(queries) = read_queries(metrics)
        {
            #[cfg(test)]
            if let Some((signal, wait)) = self
                .next_metric_use
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = signal.send(queries.len());
                let _ = wait.recv();
            }
            if let Some(result) = metrics.with_current(|| select(Some(metrics), &queries)) {
                return result;
            }
        }
        select(None, &crate::factors::Queries::new())
    }
}
