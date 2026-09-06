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

//! The backend-health round loop and its generation-fenced scheduling
//! (CP-TOPO #213-2).
//!
//! One [`HealthGeneration`] pairs an exact [`RoutingSnapshot`] with the
//! per-cluster [`ClusterHealthNetwork`]s prepared for it (or `None` when health
//! is disabled). [`run_health_round`] probes every backend of that generation's
//! source under a bounded number of in-flight tasks and returns one whole verdict
//! map — or `None` when the round must be discarded (a probe panicked, or the
//! source/owner went stale mid-round). [`run_health_loop`] drives rounds on a
//! fixed start-to-start cadence, fails closed first on any rotation, and publishes
//! each whole round through the [`HealthOverlayPublisher`] only after a final
//! exact-source authority check.
//!
//! The concurrency bound and the per-backend probe are threaded in as parameters,
//! mirroring how [`run_refresh`](crate::TopologyModule)'s interval and seam are
//! injected: production passes [`HEALTH_CONCURRENCY`] and
//! [`probe_backend_in_generation`], while the tests inject a small bound and a
//! deterministic probe (a barrier, a drop guard, a paused-clock delay) so the
//! concurrency, cancellation, and cadence guarantees are exercised without real
//! sockets.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use control_plane::OwnerToken;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::backend_health::{BackendHealth, ClusterHealthNetwork};
use crate::health_feed::HealthGenerationFeed;
use crate::health_overlay::HealthOverlayPublisher;
use crate::merge::MergedBackend;
use crate::routing_snapshot::{RoutingSnapshot, RoutingSnapshotHandle};

/// The explicit ceiling on concurrently constructed probe futures per round.
///
/// Go's health check runs its probes on a fixed pool of 100 goroutines; that pool
/// is not a hard concurrency cap in Go, but here it is the explicit Rust safety
/// bound on the number of probe futures constructed (and sockets opened) at any
/// instant, so a large fleet can never spawn an unbounded burst of tasks.
pub(crate) const HEALTH_CONCURRENCY: usize = 100;

/// Go `healthCheckInterval`: the default start-to-start round cadence. Production
/// derives the cadence from the restart-pinned config (whose default matches);
/// this literal is used only by the test-only [`HealthPolicy::go_defaults`].
#[cfg(test)]
pub(crate) const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(3);

/// Go `healthCheckMaxRetries`: the default retries after the initial attempt.
#[cfg(test)]
pub(crate) const HEALTH_MAX_RETRIES: u32 = 3;

/// Go `healthCheckRetryInterval`: the default fixed delay between attempts.
#[cfg(test)]
pub(crate) const HEALTH_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// How often the loop polls the process owner while parked or waiting.
///
/// The [`OwnerToken`] is poll-only (no change future), so the loop cannot await
/// its retirement; instead every wait (the no-generation park, an in-flight round,
/// and the cadence sleep — which can be up to an hour) races this bounded poll, so
/// an owner retirement terminates the loop within one interval rather than only on
/// the next feed change or cadence expiry. (A published overlay already fails
/// closed synchronously via its embedded owner, independent of this poll.)
pub(crate) const OWNER_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on the validated round interval.
const MAX_HEALTH_INTERVAL: Duration = Duration::from_secs(3600);
/// Upper bound on the validated retry interval.
const MAX_HEALTH_RETRY_INTERVAL: Duration = Duration::from_secs(600);
/// Upper bound on the validated retry count.
const MAX_HEALTH_MAX_RETRIES: u32 = 100;

/// A startup-validated health-probe policy: the round cadence plus the per-probe
/// retry budget threaded into [`ClusterHealthNetwork::probe_backend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HealthPolicy {
    interval: Duration,
    max_retries: u32,
    retry_interval: Duration,
}

/// Why a [`HealthPolicy`] failed startup validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HealthPolicyError {
    /// The round interval was zero or above its bound.
    InvalidInterval,
    /// The retry interval was zero or above its bound.
    InvalidRetryInterval,
    /// The retry count was above its bound.
    TooManyRetries,
}

impl HealthPolicy {
    /// Validates and builds a policy: the round and retry intervals must be
    /// non-zero and within their bounds, and the retry count within its bound.
    pub(crate) fn new(
        interval: Duration,
        max_retries: u32,
        retry_interval: Duration,
    ) -> Result<Self, HealthPolicyError> {
        if interval.is_zero() || interval > MAX_HEALTH_INTERVAL {
            return Err(HealthPolicyError::InvalidInterval);
        }
        if retry_interval.is_zero() || retry_interval > MAX_HEALTH_RETRY_INTERVAL {
            return Err(HealthPolicyError::InvalidRetryInterval);
        }
        if max_retries > MAX_HEALTH_MAX_RETRIES {
            return Err(HealthPolicyError::TooManyRetries);
        }
        Ok(Self {
            interval,
            max_retries,
            retry_interval,
        })
    }

    /// The Go-default policy (3s cadence, 3 retries 1s apart), which is
    /// known-valid. Test-only: production builds the policy from the restart-pinned
    /// config through [`crate::health_config::HealthRuntime`].
    #[cfg(test)]
    pub(crate) fn go_defaults() -> Self {
        Self {
            interval: HEALTH_CHECK_INTERVAL,
            max_retries: HEALTH_MAX_RETRIES,
            retry_interval: HEALTH_RETRY_INTERVAL,
        }
    }

    /// The start-to-start round cadence.
    pub(crate) fn interval(self) -> Duration {
        self.interval
    }
}

/// One health generation: the exact routing source and the per-cluster probe
/// networks prepared for it. `networks == None` means health is DISABLED for this
/// generation, so every backend is reported healthy with zero network I/O.
///
/// The networks map (and the whole generation) is built by the module wiring in
/// CP-TOPO #213-3; #213-2 only consumes it through a crate-private `watch`.
pub(crate) struct HealthGeneration {
    /// The exact routing generation these probes belong to.
    pub(crate) source: Arc<RoutingSnapshot>,
    /// The per-cluster probe networks, or `None` when health is disabled.
    ///
    /// Held behind an `Arc` so several routing generations that share one exact
    /// discovery `client_epoch` (a same-epoch topology content refresh mints a new
    /// `Arc<RoutingSnapshot>` without rotating the material) reuse ONE resolver /
    /// TLS client set rather than rebuilding it per routing `Arc`. This is a
    /// #213-3 private composition shape; the round logic reads it identically.
    pub(crate) networks: Option<Arc<HashMap<Arc<str>, ClusterHealthNetwork>>>,
}

/// Whether the current owner and the exact routing source are both still live, so
/// a round may keep probing and its verdict may be published.
fn round_authoritative(
    routing: &RoutingSnapshotHandle,
    source: &Arc<RoutingSnapshot>,
    owner: &OwnerToken,
) -> bool {
    owner.is_current() && routing.still_current(source)
}

/// Aborts every in-flight probe and drains the set to empty, so each probe future
/// (and anything it holds) is dropped before the caller proceeds.
async fn abort_and_drain(set: &mut JoinSet<(Arc<str>, BackendHealth)>) {
    set.abort_all();
    while set.join_next().await.is_some() {}
}

/// The production per-backend probe: locates the backend's cluster network within
/// the generation and runs [`ClusterHealthNetwork::probe_backend`] with the
/// policy's retry budget. A backend whose cluster has no network in this
/// generation is unhealthy, keeping the round's map complete.
pub(crate) async fn probe_backend_in_generation(
    generation: Arc<HealthGeneration>,
    source: Arc<RoutingSnapshot>,
    routing: RoutingSnapshotHandle,
    backend: MergedBackend,
    policy: HealthPolicy,
) -> BackendHealth {
    if let Some(network) = generation
        .networks
        .as_ref()
        .and_then(|networks| networks.get(backend.cluster_name.as_ref()))
    {
        return network
            .probe_backend(
                &routing,
                &source,
                &backend,
                policy.max_retries,
                policy.retry_interval,
            )
            .await;
    }
    // No cluster network for this backend in this generation. Preserve the exact
    // routing/source admission, then mirror #213-1: a static backend (empty `ip`)
    // is healthy this stage with no I/O even without a network, while a DYNAMIC
    // backend whose cluster network is missing is unhealthy (keeps the map
    // complete without ever probing with the wrong or no material).
    if !routing.still_current(&source) {
        return BackendHealth {
            healthy: false,
            server_version: None,
        };
    }
    if backend.backend.ip.is_empty() {
        return BackendHealth {
            healthy: true,
            server_version: None,
        };
    }
    BackendHealth {
        healthy: false,
        server_version: None,
    }
}

/// The round-invariant context threaded through every round: the routing handle,
/// the owner, the validated policy, the concurrency bound, and the injected
/// per-backend probe. Built once per loop; the source and generation are the only
/// things that vary round to round.
pub(crate) struct HealthRoundConfig<'ctx, Probe> {
    routing: &'ctx RoutingSnapshotHandle,
    owner: &'ctx OwnerToken,
    policy: HealthPolicy,
    concurrency: usize,
    probe: &'ctx Probe,
}

/// Runs one health round over every backend of `source`, returning the whole
/// verdict map or `None` if the round must be discarded.
///
/// When `generation.networks` is `None` the round is DISABLED: it builds a
/// whole-map verdict of every `source.backends` id as healthy with no version,
/// constructing no network, spawning no task, and opening no socket.
///
/// Otherwise it probes every backend, keeping the number of constructed in-flight
/// probe futures at or below `config.concurrency` by refilling from
/// `source.backends` only while `set.len() < concurrency`, so a large fleet never
/// bursts. The map is keyed exactly by `source.backends`' ids. If any probe task
/// panics/returns a [`JoinError`](tokio::task::JoinError), or the owner/source
/// goes stale mid-round, the whole set is aborted and drained and `None` is
/// returned — never a partial map.
pub(crate) async fn run_health_round<Probe, Fut>(
    config: &HealthRoundConfig<'_, Probe>,
    source: &Arc<RoutingSnapshot>,
    generation: &Arc<HealthGeneration>,
    set: &mut JoinSet<(Arc<str>, BackendHealth)>,
) -> Option<HashMap<Arc<str>, BackendHealth>>
where
    Probe: Fn(
        Arc<HealthGeneration>,
        Arc<RoutingSnapshot>,
        RoutingSnapshotHandle,
        MergedBackend,
        HealthPolicy,
    ) -> Fut,
    Fut: Future<Output = BackendHealth> + Send + 'static,
{
    let routing = config.routing;
    let owner = config.owner;
    let policy = config.policy;
    let concurrency = config.concurrency;
    let probe = config.probe;
    // DISABLED: a whole-map all-healthy verdict with zero network/spawn/socket.
    if generation.networks.is_none() {
        let health = source
            .backends
            .backends
            .iter()
            .map(|backend| {
                (
                    Arc::clone(&backend.backend_id),
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    },
                )
            })
            .collect();
        return Some(health);
    }

    let mut health: HashMap<Arc<str>, BackendHealth> =
        HashMap::with_capacity(source.backends.backends.len());
    for backend in &source.backends.backends {
        // Keep the in-flight probe count bounded: collect a completed probe before
        // constructing the next, so at most `concurrency` futures ever exist.
        while set.len() >= concurrency {
            match set.join_next().await {
                Some(Ok((id, verdict))) => {
                    health.insert(id, verdict);
                }
                Some(Err(_join_error)) => {
                    abort_and_drain(set).await;
                    return None;
                }
                None => break,
            }
        }
        // Admit each probe only for the live owner and exact source.
        if !round_authoritative(routing, source, owner) {
            abort_and_drain(set).await;
            return None;
        }
        let backend_id = Arc::clone(&backend.backend_id);
        let future = probe(
            Arc::clone(generation),
            Arc::clone(source),
            routing.clone(),
            backend.clone(),
            policy,
        );
        set.spawn(async move {
            let verdict = future.await;
            (backend_id, verdict)
        });
    }

    // Drain the remaining in-flight probes into the whole-map verdict.
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((id, verdict)) => {
                health.insert(id, verdict);
            }
            Err(_join_error) => {
                abort_and_drain(set).await;
                return None;
            }
        }
    }

    // Never surface a verdict computed against a source that has since gone stale.
    if !round_authoritative(routing, source, owner) {
        return None;
    }
    Some(health)
}

/// The event that ended one round's foreground wait.
enum RoundEvent {
    /// The round completed with an optional whole-map verdict (`None` = discard).
    Completed(Option<HashMap<Arc<str>, BackendHealth>>),
    /// The feed's generation changed (set / withdraw / close / overflow) while the
    /// round was in flight, so the round is preempted.
    Rotated,
    /// The process owner retired while the round was in flight.
    OwnerRetired,
}

/// The outcome of a wait that races a feed change against an owner poll.
enum WaitOutcome {
    /// The feed's revision advanced (or it went terminal).
    Changed,
    /// The process owner retired while waiting.
    OwnerRetired,
}

/// The outcome of the cadence wait: a feed change, the cadence elapsing, or the
/// owner retiring mid-wait.
enum CadenceOutcome {
    /// The feed's generation changed while waiting for the next round.
    Changed,
    /// The cadence interval elapsed; run the next same-generation round.
    Elapsed,
    /// The process owner retired while waiting for the next round.
    OwnerRetired,
}

/// Waits for the feed to change (or go terminal), polling the owner every
/// [`OWNER_POLL_INTERVAL`] so an owner retirement is observed within one interval
/// even when no feed change ever arrives.
async fn wait_change_or_owner(
    feed: &HealthGenerationFeed,
    seen_revision: u64,
    owner: &OwnerToken,
) -> WaitOutcome {
    loop {
        tokio::select! {
            biased;
            () = feed.wait_change(seen_revision) => return WaitOutcome::Changed,
            () = tokio::time::sleep(OWNER_POLL_INTERVAL) => {
                if !owner.is_current() {
                    return WaitOutcome::OwnerRetired;
                }
            }
        }
    }
}

/// Terminally withdraws the overlay and drains every in-flight probe, in the fixed
/// teardown order `revoke/clear -> abort/drain`.
async fn terminate(guard: &mut HealthLoopGuard) {
    guard.publisher.revoke_and_clear();
    abort_and_drain(&mut guard.set).await;
}

/// Owns the overlay publisher and the round's `JoinSet` so a hard outer drop
/// (an aborted loop task) still terminal-clears the overlay and aborts every
/// in-flight probe — an unbypassable backstop against detached-task leaks and
/// leaked authority. Mirrors the module's `RefreshOwner`.
struct HealthLoopGuard {
    publisher: HealthOverlayPublisher,
    set: JoinSet<(Arc<str>, BackendHealth)>,
}

impl Drop for HealthLoopGuard {
    fn drop(&mut self) {
        self.publisher.revoke_and_clear();
        self.set.abort_all();
    }
}

/// Drives health rounds for a stream of generations, publishing each whole round
/// through `publisher` under a generation-fenced authority check.
///
/// Cadence is fixed start-to-start: a new (or first) generation runs a round
/// immediately, and the next round is anchored `policy.interval` after the round
/// started, so an over-running round re-anchors and never bursts a catch-up.
///
/// A rotation fails closed FIRST: on a new/withdrawn generation the overlay is
/// transiently cleared before the in-flight round is aborted and drained, so a
/// retained overlay loses authority the instant the source is superseded, and the
/// new generation starts no probe until the old round's tasks are collected. A
/// closed generation stream or a retired owner terminally withdraws the overlay,
/// drains, and returns.
// A single cohesive event loop: the park, in-flight round, and cadence waits each
// race a feed change and an owner poll, and share the guard/feed/generation state,
// so splitting it would fragment the fail-closed control flow rather than clarify it.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_health_loop<Probe, Fut>(
    feed: HealthGenerationFeed,
    routing: RoutingSnapshotHandle,
    publisher: HealthOverlayPublisher,
    policy: HealthPolicy,
    owner: OwnerToken,
    concurrency: usize,
    probe: Probe,
) where
    Probe: Fn(
        Arc<HealthGeneration>,
        Arc<RoutingSnapshot>,
        RoutingSnapshotHandle,
        MergedBackend,
        HealthPolicy,
    ) -> Fut,
    Fut: Future<Output = BackendHealth> + Send + 'static,
{
    let config = HealthRoundConfig {
        routing: &routing,
        owner: &owner,
        policy,
        concurrency,
        probe: &probe,
    };
    let mut guard = HealthLoopGuard {
        publisher,
        set: JoinSet::new(),
    };
    let (mut current, mut seen_revision, terminal) = feed.snapshot();
    if terminal {
        guard.publisher.revoke_and_clear();
        return;
    }

    loop {
        let Some(generation) = current.clone() else {
            // No active generation: fail-closed, parked until the feed changes or
            // the owner retires (polled within OWNER_POLL_INTERVAL, so the park is
            // never indefinite once the owner is gone).
            if !owner.is_current() {
                terminate(&mut guard).await;
                return;
            }
            match wait_change_or_owner(&feed, seen_revision, &owner).await {
                WaitOutcome::OwnerRetired => {
                    terminate(&mut guard).await;
                    return;
                }
                WaitOutcome::Changed => {}
            }
            let (next, revision, terminal) = feed.snapshot();
            if terminal {
                terminate(&mut guard).await;
                return;
            }
            current = next;
            seen_revision = revision;
            continue;
        };

        if !owner.is_current() {
            terminate(&mut guard).await;
            return;
        }

        let source = Arc::clone(&generation.source);
        let round_started = Instant::now();

        // Run the round, racing a feed change and an owner poll so a rotation or an
        // owner retirement preempts it.
        let event = {
            let round = run_health_round(&config, &source, &generation, &mut guard.set);
            tokio::pin!(round);
            loop {
                tokio::select! {
                    biased;
                    () = feed.wait_change(seen_revision) => break RoundEvent::Rotated,
                    verdict = &mut round => break RoundEvent::Completed(verdict),
                    () = tokio::time::sleep(OWNER_POLL_INTERVAL) => {
                        if !owner.is_current() {
                            break RoundEvent::OwnerRetired;
                        }
                    }
                }
            }
        };

        match event {
            RoundEvent::OwnerRetired => {
                terminate(&mut guard).await;
                return;
            }
            RoundEvent::Rotated => {
                if handle_rotation(&mut guard, &feed, &mut current, &mut seen_revision).await
                    == LoopControl::Stop
                {
                    return;
                }
            }
            RoundEvent::Completed(verdict) => {
                if let Some(map) = verdict {
                    // Atomic publish critical section: `publish_current` holds the
                    // feed lock across the exact-generation + terminal check, the
                    // owner + routing.still_current check, and the overlay swap, so a
                    // same-source generation replacement, a withdraw, or a close
                    // landing between round-complete and publish cannot publish a
                    // stale map — it either loses the lock race (publish rejected) or
                    // wins it after the publish (and synchronously revokes the feed
                    // gate, so the just-published overlay is immediately non-current).
                    feed.publish_current(&generation, |feed_gate| {
                        if round_authoritative(&routing, &source, &owner) {
                            guard
                                .publisher
                                .publish_round(&source, map, feed_gate, &owner);
                        }
                    });
                }
                // Cadence: next round anchored `interval` after this round started;
                // an over-run makes the sleep already-elapsed so it fires at once.
                // The wait also polls the owner, so a retirement during a long
                // cadence sleep terminates the loop within OWNER_POLL_INTERVAL rather
                // than only when the sleep expires.
                let deadline = round_started + policy.interval();
                let sleep = tokio::time::sleep_until(deadline);
                tokio::pin!(sleep);
                let cadence = loop {
                    tokio::select! {
                        biased;
                        () = feed.wait_change(seen_revision) => break CadenceOutcome::Changed,
                        () = &mut sleep => break CadenceOutcome::Elapsed,
                        () = tokio::time::sleep(OWNER_POLL_INTERVAL) => {
                            if !owner.is_current() {
                                break CadenceOutcome::OwnerRetired;
                            }
                        }
                    }
                };
                match cadence {
                    CadenceOutcome::Changed => {
                        if handle_rotation(&mut guard, &feed, &mut current, &mut seen_revision)
                            .await
                            == LoopControl::Stop
                        {
                            return;
                        }
                    }
                    CadenceOutcome::Elapsed => {
                        // Same generation, next round; re-anchor at the loop top.
                    }
                    CadenceOutcome::OwnerRetired => {
                        terminate(&mut guard).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Whether the loop should keep running or stop after handling a rotation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LoopControl {
    Continue,
    Stop,
}

/// Handles a feed change: a terminal feed (closed/overflowed) terminally
/// withdraws the overlay and stops the loop; otherwise fail-closed FIRST (transient
/// clear), then abort + drain the in-flight round, then adopt the new generation.
async fn handle_rotation(
    guard: &mut HealthLoopGuard,
    feed: &HealthGenerationFeed,
    current: &mut Option<Arc<HealthGeneration>>,
    seen_revision: &mut u64,
) -> LoopControl {
    let (next, revision, terminal) = feed.snapshot();
    if terminal {
        // The feed closed (last feeder dropped) or overflowed: terminally
        // withdraw, drain, stop.
        guard.publisher.revoke_and_clear();
        abort_and_drain(&mut guard.set).await;
        return LoopControl::Stop;
    }
    // Fail-closed FIRST: the retained overlay loses authority immediately, BEFORE
    // any in-flight probe is joined. (The feed transition already revoked the old
    // slot gate synchronously; this also clears the overlay slot.)
    guard.publisher.transient_clear();
    abort_and_drain(&mut guard.set).await;
    *current = next;
    *seen_revision = revision;
    LoopControl::Continue
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use control_plane::{OwnerLease, OwnerScope, OwnerToken, OwnershipRegistry};
    use tokio::sync::{Semaphore, watch};
    use tokio::task::JoinSet;
    use tokio::time::Instant;

    use super::{
        HealthGeneration, HealthOverlayPublisher, HealthPolicy, HealthRoundConfig,
        OWNER_POLL_INTERVAL, probe_backend_in_generation, round_authoritative, run_health_loop,
        run_health_round,
    };
    use crate::backend_health::BackendHealth;
    use crate::discovery_publish::EpochResult;
    use crate::health_feed::HealthGenerationFeeder;
    use crate::merge::{MergedBackend, MergedTopology};
    use crate::model::BackendInfo;
    use crate::routing_snapshot::{
        RoutingSnapshot, RoutingSnapshotHandle, RoutingSnapshotPublisher,
    };

    const CLUSTER: &str = "cluster-a";

    fn owner_lease() -> (OwnershipRegistry, OwnerLease) {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "health-loop-test")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        (registry, lease)
    }

    fn merged_backend(index: usize) -> MergedBackend {
        let addr = format!("10.0.0.{index}:4000");
        MergedBackend {
            backend_id: Arc::from(format!("{CLUSTER}/{addr}").as_str()),
            cluster_name: Arc::from(CLUSTER),
            backend: BackendInfo {
                addr: addr.clone(),
                keyspace: String::new(),
                ip: format!("10.0.0.{index}"),
                status_port: 4000,
                version: String::new(),
                git_hash: String::new(),
                deploy_path: String::new(),
                start_timestamp: 0,
                labels: BTreeMap::new(),
            },
        }
    }

    /// A STATIC backend (empty `ip`, like a placeholder with no status port to
    /// dial): #213-1 treats it as healthy with no network I/O.
    fn static_backend(status_port: u64) -> MergedBackend {
        MergedBackend {
            backend_id: Arc::from(format!("{CLUSTER}/static:{status_port}").as_str()),
            cluster_name: Arc::from(CLUSTER),
            backend: BackendInfo {
                addr: String::new(),
                keyspace: String::new(),
                ip: String::new(),
                status_port,
                version: String::new(),
                git_hash: String::new(),
                deploy_path: String::new(),
                start_timestamp: 0,
                labels: BTreeMap::new(),
            },
        }
    }

    /// Publishes a routing generation with the given exact backends and returns the
    /// publisher (held so its `Drop` keeps the gate live), the handle, and source.
    fn published_backends(
        backends: Vec<MergedBackend>,
    ) -> (
        RoutingSnapshotPublisher,
        RoutingSnapshotHandle,
        Arc<RoutingSnapshot>,
    ) {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publisher
            .publish(EpochResult {
                client_epoch: 1,
                value: MergedTopology { backends },
            })
            .unwrap_or_else(|_| unreachable!("first publish"));
        let source = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        (publisher, handle, source)
    }

    /// Publishes one `client_epoch` generation with `count` backends and returns
    /// the publisher (held so its `Drop` does not revoke the gate), its handle, and
    /// the live source.
    fn published_source(
        client_epoch: u64,
        count: usize,
    ) -> (
        RoutingSnapshotPublisher,
        RoutingSnapshotHandle,
        Arc<RoutingSnapshot>,
    ) {
        let (publisher, handle) = RoutingSnapshotPublisher::new();
        publisher
            .publish(EpochResult {
                client_epoch,
                value: MergedTopology {
                    backends: (0..count).map(merged_backend).collect(),
                },
            })
            .unwrap_or_else(|_| unreachable!("first publish"));
        let source = handle
            .current()
            .unwrap_or_else(|| unreachable!("a snapshot is published"));
        (publisher, handle, source)
    }

    /// A generation for `source`; `networks` is `Some(empty)` when `enabled` (the
    /// enabled branch spawns probes but the injected test probe ignores the map)
    /// and `None` when disabled.
    fn generation(source: &Arc<RoutingSnapshot>, enabled: bool) -> Arc<HealthGeneration> {
        Arc::new(HealthGeneration {
            source: Arc::clone(source),
            networks: enabled.then(|| Arc::new(HashMap::new())),
        })
    }

    // ================================================================
    // B1: the number of constructed in-flight probes stays <= concurrency.
    // ================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn constructed_probes_stay_within_the_concurrency_bound() {
        const N: usize = 3;
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 2 * N);
        let health_gen = generation(&source, true);

        // The probe increments `created` at CONSTRUCTION (synchronously, before the
        // async body), records that it started, then blocks on a semaphore the test
        // opens. With the len<concurrency refill, only `concurrency` futures are
        // ever constructed before one completes; a spawn-all mutant constructs all
        // `2 * N` up front.
        let created = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let inflight = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let probe = {
            let created = Arc::clone(&created);
            let started = Arc::clone(&started);
            let peak = Arc::clone(&peak);
            let inflight = Arc::clone(&inflight);
            let release = Arc::clone(&release);
            move |_gen: Arc<HealthGeneration>,
                  _source: Arc<RoutingSnapshot>,
                  _routing: RoutingSnapshotHandle,
                  _backend: MergedBackend,
                  _policy: HealthPolicy| {
                created.fetch_add(1, Ordering::SeqCst);
                let started = Arc::clone(&started);
                let peak = Arc::clone(&peak);
                let inflight = Arc::clone(&inflight);
                let release = Arc::clone(&release);
                async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    let _permit = release.acquire().await;
                    inflight.fetch_sub(1, Ordering::SeqCst);
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    }
                }
            }
        };

        let config = HealthRoundConfig {
            routing: &routing,
            owner: &owner,
            policy: HealthPolicy::go_defaults(),
            concurrency: N,
            probe: &probe,
        };
        let mut set: JoinSet<(Arc<str>, BackendHealth)> = JoinSet::new();

        // A releaser observes the round blocking at exactly `N` started probes,
        // snapshots the created/peak counts at that point, then unblocks them.
        let releaser = {
            let created = Arc::clone(&created);
            let started = Arc::clone(&started);
            let peak = Arc::clone(&peak);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                while started.load(Ordering::SeqCst) < N {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                let created_at_block = created.load(Ordering::SeqCst);
                let peak_at_block = peak.load(Ordering::SeqCst);
                release.add_permits(4 * N);
                (created_at_block, peak_at_block)
            })
        };

        let map = tokio::time::timeout(
            Duration::from_secs(5),
            run_health_round(&config, &source, &health_gen, &mut set),
        )
        .await
        .unwrap_or_else(|_| unreachable!("the round completes once probes are released"))
        .unwrap_or_else(|| unreachable!("a healthy round yields a whole map"));
        let (created_at_block, peak_at_block) = releaser
            .await
            .unwrap_or_else(|error| unreachable!("releaser task: {error}"));

        assert!(
            created_at_block <= N,
            "constructed probes {created_at_block} exceeded the bound {N} (spawn-all burst)"
        );
        assert!(
            peak_at_block <= N,
            "peak in-flight {peak_at_block} exceeded the bound {N}"
        );
        assert_eq!(map.len(), 2 * N, "the whole map is keyed by every backend");
        assert_eq!(
            created.load(Ordering::SeqCst),
            2 * N,
            "every backend was eventually probed exactly once"
        );
    }

    // ================================================================
    // D1: a disabled generation reports all-healthy with zero probe/spawn.
    // ================================================================

    #[tokio::test]
    async fn a_disabled_generation_is_all_healthy_with_zero_probe() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 4);
        let health_gen = generation(&source, false); // networks = None => disabled

        let called = Arc::new(AtomicUsize::new(0));
        let probe = {
            let called = Arc::clone(&called);
            move |_gen: Arc<HealthGeneration>,
                  _source: Arc<RoutingSnapshot>,
                  _routing: RoutingSnapshotHandle,
                  _backend: MergedBackend,
                  _policy: HealthPolicy| {
                called.fetch_add(1, Ordering::SeqCst);
                async {
                    unreachable!("a disabled generation never calls the probe");
                    #[allow(unreachable_code)]
                    BackendHealth {
                        healthy: false,
                        server_version: None,
                    }
                }
            }
        };
        let config = HealthRoundConfig {
            routing: &routing,
            owner: &owner,
            policy: HealthPolicy::go_defaults(),
            concurrency: super::HEALTH_CONCURRENCY,
            probe: &probe,
        };
        let mut set: JoinSet<(Arc<str>, BackendHealth)> = JoinSet::new();

        let map = run_health_round(&config, &source, &health_gen, &mut set)
            .await
            .unwrap_or_else(|| unreachable!("a disabled round yields a whole map"));

        assert_eq!(called.load(Ordering::SeqCst), 0, "no probe was constructed");
        assert!(set.is_empty(), "no task was spawned");
        let expected: Vec<Arc<str>> = source
            .backends
            .backends
            .iter()
            .map(|backend| Arc::clone(&backend.backend_id))
            .collect();
        assert_eq!(map.len(), expected.len(), "the map keys every backend");
        for backend_id in &expected {
            let verdict = map
                .get(backend_id)
                .unwrap_or_else(|| unreachable!("every backend is keyed"));
            assert!(verdict.healthy, "a disabled backend is healthy");
            assert!(verdict.server_version.is_none(), "with no version");
        }
    }

    // ================================================================
    // D2: a missing network is unhealthy (map complete); a panic discards.
    // ================================================================

    #[tokio::test]
    async fn a_missing_network_is_unhealthy_but_the_map_is_complete() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 4);
        // Enabled, but the networks map has NO entry for the backends' cluster, so
        // the production probe reports every backend unhealthy while keeping the
        // map complete.
        let health_gen = Arc::new(HealthGeneration {
            source: Arc::clone(&source),
            networks: Some(Arc::new(HashMap::new())),
        });
        let probe = probe_backend_in_generation;
        let config = HealthRoundConfig {
            routing: &routing,
            owner: &owner,
            policy: HealthPolicy::go_defaults(),
            concurrency: super::HEALTH_CONCURRENCY,
            probe: &probe,
        };
        let mut set: JoinSet<(Arc<str>, BackendHealth)> = JoinSet::new();

        let map = run_health_round(&config, &source, &health_gen, &mut set)
            .await
            .unwrap_or_else(|| unreachable!("a missing-network round still yields a whole map"));
        assert_eq!(map.len(), 4, "the map is complete");
        for verdict in map.values() {
            assert!(
                !verdict.healthy,
                "a backend whose cluster has no network is unhealthy"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_network_for_a_static_backend_is_healthy_with_zero_probe() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        // A counting listener: a socket would be opened only if a network probe were
        // attempted. A static backend must be healthy with NO probe, so nothing ever
        // connects here.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| unreachable!("bind: {error}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|error| unreachable!("addr: {error}"))
            .port();

        // One STATIC backend (empty ip) and one DYNAMIC backend, both in a cluster
        // with NO network in this generation.
        let (_publisher, routing, source) =
            published_backends(vec![static_backend(u64::from(port)), merged_backend(1)]);
        let health_gen = Arc::new(HealthGeneration {
            source: Arc::clone(&source),
            networks: Some(Arc::new(HashMap::new())),
        });
        let probe = probe_backend_in_generation;
        let config = HealthRoundConfig {
            routing: &routing,
            owner: &owner,
            policy: HealthPolicy::go_defaults(),
            concurrency: super::HEALTH_CONCURRENCY,
            probe: &probe,
        };
        let mut set: JoinSet<(Arc<str>, BackendHealth)> = JoinSet::new();

        let map = run_health_round(&config, &source, &health_gen, &mut set)
            .await
            .unwrap_or_else(|| unreachable!("a static+dynamic round yields a whole map"));
        assert_eq!(map.len(), 2, "the map is complete (static + dynamic)");

        let static_verdict = map
            .get(format!("cluster-a/static:{port}").as_str())
            .unwrap_or_else(|| unreachable!("the static backend is keyed"));
        assert_eq!(
            *static_verdict,
            BackendHealth {
                healthy: true,
                server_version: None,
            },
            "a static backend with a missing network is healthy with no version"
        );
        let dynamic_verdict = map
            .get("cluster-a/10.0.0.1:4000")
            .unwrap_or_else(|| unreachable!("the dynamic backend is keyed"));
        assert!(
            !dynamic_verdict.healthy,
            "a dynamic backend with a missing network stays unhealthy"
        );

        // Zero socket: nothing ever connected to the counting listener.
        let accepted = tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "no probe socket was opened for the static backend"
        );
    }

    #[tokio::test]
    async fn a_probe_panic_discards_the_whole_round() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 4);
        let health_gen = generation(&source, true);
        let probe = move |_gen: Arc<HealthGeneration>,
                          _source: Arc<RoutingSnapshot>,
                          _routing: RoutingSnapshotHandle,
                          _backend: MergedBackend,
                          _policy: HealthPolicy| async {
            // Deliberately panic this probe to force a JoinError.
            unreachable!("injected probe panic");
            #[allow(unreachable_code)]
            BackendHealth {
                healthy: false,
                server_version: None,
            }
        };
        let config = HealthRoundConfig {
            routing: &routing,
            owner: &owner,
            policy: HealthPolicy::go_defaults(),
            concurrency: super::HEALTH_CONCURRENCY,
            probe: &probe,
        };
        let mut set: JoinSet<(Arc<str>, BackendHealth)> = JoinSet::new();

        let outcome = run_health_round(&config, &source, &health_gen, &mut set).await;
        assert!(
            outcome.is_none(),
            "a probe panic discards the whole round (never a partial map)"
        );
        assert!(set.is_empty(), "the set was aborted and drained");
    }

    /// A whole all-healthy map keyed by every backend of `source`.
    fn healthy_map(source: &Arc<RoutingSnapshot>) -> HashMap<Arc<str>, BackendHealth> {
        source
            .backends
            .backends
            .iter()
            .map(|backend| {
                (
                    Arc::clone(&backend.backend_id),
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    },
                )
            })
            .collect()
    }

    // ================================================================
    // A3: the owner+routing authority gates a stale round out of publication.
    // ================================================================

    #[test]
    fn a_rotated_routing_source_is_not_publishable() {
        let (routing_publisher, routing, source) = published_source(1, 2);
        let (_registry, lease) = owner_lease();
        let owner = lease.token();

        assert!(
            round_authoritative(&routing, &source, &owner),
            "a live owner and current source is authoritative"
        );

        // Rotate the routing source: the captured source is now superseded, so the
        // completed round for it is no longer authoritative and is not published.
        routing_publisher
            .publish(EpochResult {
                client_epoch: 2,
                value: MergedTopology {
                    backends: (0..3).map(merged_backend).collect(),
                },
            })
            .unwrap_or_else(|_| unreachable!("second publish"));
        assert!(
            !round_authoritative(&routing, &source, &owner),
            "a source rotated after round-complete is not authoritative"
        );
    }

    // ================================================================
    // Feed: snapshot / revision / publish_current linearization / terminals.
    // ================================================================

    #[test]
    fn a_feed_snapshot_reflects_set_and_advances_revision() {
        let (_publisher, _routing, source) = published_source(1, 1);
        let health_gen = generation(&source, true);
        let (feeder, feed) = HealthGenerationFeeder::new();

        let (initial, rev0, terminal) = feed.snapshot();
        assert!(initial.is_none() && rev0 == 0 && !terminal, "an empty feed");

        feeder.set(Arc::clone(&health_gen));
        let (current, rev1, terminal) = feed.snapshot();
        assert!(
            current.is_some_and(|g| Arc::ptr_eq(&g, &health_gen)),
            "snapshot reflects the set generation"
        );
        assert_eq!(rev1, 1, "a set advances the revision");
        assert!(!terminal);
    }

    #[test]
    fn a_publish_current_rejects_a_superseded_generation() {
        // While a round for G1 (same routing Arc R) is at the publish boundary, the
        // feeder set a new generation G2 over the SAME R and won the lock race. The
        // publish for the OLD G1 must be rejected WITHOUT running the publish
        // closure; only the exact CURRENT generation publishes.
        let (_publisher, _routing, source) = published_source(1, 1);
        let g1 = generation(&source, true);
        let g2 = generation(&source, true);
        assert!(
            !Arc::ptr_eq(&g1, &g2),
            "distinct generation Arcs over one source"
        );
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(Arc::clone(&g1));
        feeder.set(Arc::clone(&g2));

        let mut old_published = false;
        let published = feed.publish_current(&g1, |_feed_gate| old_published = true);
        assert!(
            !published && !old_published,
            "a superseded generation is not published and never runs the publish closure"
        );

        let mut new_published = false;
        let published = feed.publish_current(&g2, |feed_gate| {
            new_published = true;
            assert!(feed_gate.is_live(), "the current slot gate is live");
        });
        assert!(
            published && new_published,
            "the exact current generation publishes under a live slot gate"
        );
    }

    #[test]
    fn a_withdrawn_feed_rejects_publish_current() {
        let (_publisher, _routing, source) = published_source(1, 1);
        let g1 = generation(&source, true);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(Arc::clone(&g1));
        feeder.withdraw();
        let mut called = false;
        assert!(
            !feed.publish_current(&g1, |_feed_gate| called = true) && !called,
            "a withdrawn feed publishes nothing"
        );
    }

    #[test]
    fn a_dropped_feeder_closes_the_feed() {
        let (_publisher, _routing, source) = published_source(1, 1);
        let g1 = generation(&source, true);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(Arc::clone(&g1));
        let (_current, _rev, terminal_before) = feed.snapshot();
        assert!(!terminal_before, "the feed is live while the feeder exists");

        drop(feeder);
        let (current, _rev, terminal_after) = feed.snapshot();
        assert!(
            terminal_after && current.is_none(),
            "a dropped feeder closes the feed"
        );
        let mut called = false;
        assert!(
            !feed.publish_current(&g1, |_feed_gate| called = true) && !called,
            "a closed feed publishes nothing"
        );
    }

    #[test]
    fn a_revision_overflow_is_terminal_fail_closed() {
        let (_publisher, _routing, source) = published_source(1, 1);
        let g1 = generation(&source, true);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.force_revision(u64::MAX);
        feeder.set(Arc::clone(&g1));
        let (_current, _rev, terminal) = feed.snapshot();
        assert!(terminal, "an overflowed revision is terminal fail-closed");
        let mut called = false;
        assert!(
            !feed.publish_current(&g1, |_feed_gate| called = true) && !called,
            "an overflowed feed publishes nothing"
        );
    }

    // ================================================================
    // Amendment 1: a feed transition revokes consumer authority SYNCHRONOUSLY,
    // without the loop polling (the slot gate is embedded in the overlay).
    // ================================================================

    #[test]
    fn a_withdraw_synchronously_revokes_consumer_authority() {
        let (_publisher, routing, source) = published_source(1, 1);
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let g1 = generation(&source, true);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(Arc::clone(&g1));
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();

        // Publish under the feed's slot gate, exactly as the loop does.
        let published = feed.publish_current(&g1, |feed_gate| {
            overlay.publish_round(&source, healthy_map(&source), feed_gate, &owner);
        });
        assert!(published, "the exact current generation publishes");
        let h = overlay_handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the overlay is published"));
        assert!(overlay_handle.still_current_for(&h, &source, &routing));

        // A withdraw revokes the slot gate SYNCHRONOUSLY: a consumer's authority is
        // false the instant `withdraw()` returns, with no loop poll in between.
        feeder.withdraw();
        assert!(
            overlay_handle.current_for(&source).is_none(),
            "current_for is false immediately after withdraw"
        );
        assert!(
            !overlay_handle.still_current_for(&h, &source, &routing),
            "still_current_for is false immediately after withdraw"
        );
    }

    #[test]
    fn a_dropped_feeder_synchronously_revokes_consumer_authority() {
        let (_publisher, routing, source) = published_source(1, 1);
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let g1 = generation(&source, true);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(Arc::clone(&g1));
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();
        let published = feed.publish_current(&g1, |feed_gate| {
            overlay.publish_round(&source, healthy_map(&source), feed_gate, &owner);
        });
        assert!(published);
        let h = overlay_handle
            .current_for(&source)
            .unwrap_or_else(|| unreachable!("the overlay is published"));
        assert!(overlay_handle.still_current_for(&h, &source, &routing));

        // Dropping the last feeder closes the feed and revokes the slot gate
        // synchronously.
        drop(feeder);
        assert!(
            overlay_handle.current_for(&source).is_none(),
            "current_for is false immediately after the feeder drops"
        );
        assert!(
            !overlay_handle.still_current_for(&h, &source, &routing),
            "still_current_for is false immediately after the feeder drops"
        );
    }

    // ================================================================
    // C1: start-to-start cadence under a paused clock.
    // ================================================================

    /// A single-backend generation whose probe records the virtual offset at which
    /// each round started (into `starts`), bumps a round counter, then sleeps
    /// `round_len` to model the round's duration.
    #[allow(clippy::type_complexity)]
    fn recording_probe(
        origin: Instant,
        starts: Arc<Mutex<Vec<Duration>>>,
        counter: watch::Sender<usize>,
        round_len: Duration,
    ) -> impl Fn(
        Arc<HealthGeneration>,
        Arc<RoutingSnapshot>,
        RoutingSnapshotHandle,
        MergedBackend,
        HealthPolicy,
    ) -> std::pin::Pin<Box<dyn Future<Output = BackendHealth> + Send>>
    + Send
    + Sync {
        move |_generation, source, _routing, _backend, _policy| {
            let offset = origin.elapsed();
            starts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(offset);
            counter.send_modify(|count| *count += 1);
            let epoch = source.client_epoch;
            Box::pin(async move {
                tokio::time::sleep(round_len).await;
                BackendHealth {
                    healthy: true,
                    server_version: Some(format!("epoch-{epoch}")),
                }
            })
        }
    }

    /// Runs the loop until `target` rounds have started, then aborts it and returns
    /// the recorded per-round virtual start offsets (in whole seconds).
    async fn collect_round_starts(
        source: &Arc<RoutingSnapshot>,
        routing: &RoutingSnapshotHandle,
        owner: &OwnerToken,
        interval: Duration,
        round_len: Duration,
        target: usize,
    ) -> Vec<u64> {
        let origin = Instant::now();
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (count_tx, mut count_rx) = watch::channel(0usize);
        let probe = recording_probe(origin, Arc::clone(&starts), count_tx, round_len);
        let (overlay, _overlay_handle) = HealthOverlayPublisher::new();
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(generation(source, true));
        let policy = HealthPolicy::new(interval, 0, Duration::from_secs(1))
            .unwrap_or_else(|_| unreachable!("a valid policy"));

        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            policy,
            owner.clone(),
            4,
            probe,
        ));
        // Park on a real (virtual) wait so the paused clock auto-advances the loop.
        let _ = tokio::time::timeout(
            Duration::from_secs(600),
            count_rx.wait_for(|count| *count >= target),
        )
        .await
        .unwrap_or_else(|_| unreachable!("the loop starts {target} rounds"));
        task.abort();
        let recorded = starts.lock().unwrap_or_else(PoisonError::into_inner);
        recorded
            .iter()
            .take(target)
            .map(Duration::as_secs)
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_shorter_than_the_interval_keeps_a_fixed_cadence() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 1);
        // A 2s round on a 3s interval: start-to-start stays 3s (t0, t3, t6).
        let offsets = collect_round_starts(
            &source,
            &routing,
            &owner,
            Duration::from_secs(3),
            Duration::from_secs(2),
            3,
        )
        .await;
        assert_eq!(
            offsets,
            vec![0, 3, 6],
            "a sub-interval round holds a 3s cadence"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_overrunning_round_reanchors_without_a_skip_or_burst() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 1);
        // A 4s round on a 3s interval: the cadence sleep is already elapsed when the
        // round ends, so the next round fires immediately and re-anchors (t0, t4,
        // t8) — never a global interval(Skip) that would land the next at t6.
        let offsets = collect_round_starts(
            &source,
            &routing,
            &owner,
            Duration::from_secs(3),
            Duration::from_secs(4),
            3,
        )
        .await;
        assert_eq!(
            offsets,
            vec![0, 4, 8],
            "an over-running round re-anchors start-to-start, never Skip/burst"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_round_never_bursts_a_catch_up() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 1);
        // A 5s round on a 1s interval crosses several missed intervals; a burst
        // catch-up would fire many rounds at t5. The correct loop runs exactly one
        // round per completion (t0, t5, t10).
        let offsets = collect_round_starts(
            &source,
            &routing,
            &owner,
            Duration::from_secs(1),
            Duration::from_secs(5),
            3,
        )
        .await;
        assert_eq!(
            offsets,
            vec![0, 5, 10],
            "several missed intervals never burst a catch-up"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_source_rotation_preempts_the_in_flight_round_immediately() {
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        // One routing publisher: epoch 1 is r1 (the initial generation's source),
        // and a later epoch 2 rotation makes r2 the live source that the new
        // generation is publishable under.
        let (routing_publisher, routing, r1) = published_source(1, 1);

        let origin = Instant::now();
        // Records (virtual-start-seconds, source epoch) per round.
        let starts = Arc::new(Mutex::new(Vec::<(u64, u64)>::new()));
        let (count_tx, mut count_rx) = watch::channel(0usize);
        let probe = {
            let starts = Arc::clone(&starts);
            move |_generation: Arc<HealthGeneration>,
                  source: Arc<RoutingSnapshot>,
                  _routing: RoutingSnapshotHandle,
                  _backend: MergedBackend,
                  _policy: HealthPolicy| {
                let epoch = source.client_epoch;
                starts
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((origin.elapsed().as_secs(), epoch));
                count_tx.send_modify(|count| *count += 1);
                // Epoch 1 (r1) runs a long round so it is still in flight at t1;
                // epoch 2 (r2) runs a 2s round so its cadence lands the next at t4.
                let round_len = if epoch == 1 {
                    Duration::from_secs(10)
                } else {
                    Duration::from_secs(2)
                };
                Box::pin(async move {
                    tokio::time::sleep(round_len).await;
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    }
                }) as std::pin::Pin<Box<dyn Future<Output = BackendHealth> + Send>>
            }
        };

        let gen1 = generation(&r1, true);
        let (overlay, _overlay_handle) = HealthOverlayPublisher::new();
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(gen1);
        let policy = HealthPolicy::new(Duration::from_secs(3), 0, Duration::from_secs(1))
            .unwrap_or_else(|_| unreachable!("a valid policy"));
        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            policy,
            owner.clone(),
            4,
            probe,
        ));

        // Advance to t1, rotate the routing source to r2, and hand the loop the new
        // generation. The long r1 round is preempted and r2 runs immediately.
        tokio::time::sleep(Duration::from_secs(1)).await;
        routing_publisher
            .publish(EpochResult {
                client_epoch: 2,
                value: MergedTopology {
                    backends: (0..1).map(merged_backend).collect(),
                },
            })
            .unwrap_or_else(|_| unreachable!("the epoch-2 rotation publishes"));
        let r2 = routing
            .current()
            .unwrap_or_else(|| unreachable!("r2 is the live source"));
        feeder.set(generation(&r2, true));

        let _ = tokio::time::timeout(
            Duration::from_secs(600),
            count_rx.wait_for(|count| *count >= 3),
        )
        .await
        .unwrap_or_else(|_| unreachable!("the loop starts three rounds"));
        task.abort();

        let recorded = starts.lock().unwrap_or_else(PoisonError::into_inner);
        let observed: Vec<(u64, u64)> = recorded.iter().take(3).copied().collect();
        assert_eq!(
            observed,
            vec![(0, 1), (1, 2), (4, 2)],
            "the r1 round is preempted at t1; r2 runs immediately then re-anchors at t4"
        );
    }

    // ================================================================
    // B2: rotation fails closed FIRST, then aborts + drains, then starts.
    // ================================================================

    async fn wait_until(predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if predicate() {
                return;
            }
            if Instant::now() > deadline {
                unreachable!("a B2 condition was not reached in time");
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// A guard held by an in-flight probe: on drop it records whether the overlay
    /// had already lost authority (was cleared) and counts itself dropped.
    struct DropGuard {
        overlay: crate::health_overlay::HealthOverlayHandle,
        source: Arc<RoutingSnapshot>,
        drop_count: Arc<AtomicUsize>,
        cleared_at_drop: Arc<Mutex<Vec<bool>>>,
    }

    impl Drop for DropGuard {
        fn drop(&mut self) {
            let cleared = self.overlay.current_for(&self.source).is_none();
            self.cleared_at_drop
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(cleared);
            self.drop_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The shared observation state threaded through the B2 probe and its
    /// assertions.
    #[derive(Clone)]
    struct B2Shared {
        calls: Arc<AtomicUsize>,
        round1_started: Arc<AtomicUsize>,
        drop_count: Arc<AtomicUsize>,
        cleared_at_drop: Arc<Mutex<Vec<bool>>>,
        gen2_dropcount_at_start: Arc<Mutex<Vec<usize>>>,
        overlay_handle: crate::health_overlay::HealthOverlayHandle,
        source: Arc<RoutingSnapshot>,
    }

    type BoxedProbe = std::pin::Pin<Box<dyn Future<Output = BackendHealth> + Send>>;

    /// The B2 probe: generation-1 round 0 completes quickly (so H1 publishes),
    /// round 1 holds a drop guard and blocks in flight, and generation-2 records
    /// how many old guards had already dropped when its probe was constructed.
    fn b2_probe(
        shared: B2Shared,
        n: usize,
    ) -> impl Fn(
        Arc<HealthGeneration>,
        Arc<RoutingSnapshot>,
        RoutingSnapshotHandle,
        MergedBackend,
        HealthPolicy,
    ) -> BoxedProbe
    + Send
    + Sync {
        move |_generation, _source, _routing, _backend, _policy| {
            let index = shared.calls.fetch_add(1, Ordering::SeqCst);
            let healthy = BackendHealth {
                healthy: true,
                server_version: None,
            };
            if index < n {
                Box::pin(async move { healthy }) as BoxedProbe
            } else if index < 2 * n {
                let guard = DropGuard {
                    overlay: shared.overlay_handle.clone(),
                    source: Arc::clone(&shared.source),
                    drop_count: Arc::clone(&shared.drop_count),
                    cleared_at_drop: Arc::clone(&shared.cleared_at_drop),
                };
                let round1_started = Arc::clone(&shared.round1_started);
                Box::pin(async move {
                    let _guard = guard;
                    round1_started.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                    healthy
                }) as BoxedProbe
            } else {
                shared
                    .gen2_dropcount_at_start
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(shared.drop_count.load(Ordering::SeqCst));
                Box::pin(async move { healthy }) as BoxedProbe
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rotation_fails_closed_before_it_aborts_and_drains() {
        const N: usize = 3;
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        // A single routing source r1 is kept live throughout: the second generation
        // reuses r1, so the "overlay cleared" observation isolates the transient
        // clear from any routing revoke.
        let (_routing_publisher, routing, r1) = published_source(1, N);
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();

        let round1_started = Arc::new(AtomicUsize::new(0));
        let drop_count = Arc::new(AtomicUsize::new(0));
        let cleared_at_drop = Arc::new(Mutex::new(Vec::<bool>::new()));
        let gen2_dropcount_at_start = Arc::new(Mutex::new(Vec::<usize>::new()));
        let shared = B2Shared {
            calls: Arc::new(AtomicUsize::new(0)),
            round1_started: Arc::clone(&round1_started),
            drop_count: Arc::clone(&drop_count),
            cleared_at_drop: Arc::clone(&cleared_at_drop),
            gen2_dropcount_at_start: Arc::clone(&gen2_dropcount_at_start),
            overlay_handle: overlay_handle.clone(),
            source: Arc::clone(&r1),
        };
        let probe = b2_probe(shared, N);

        let gen1 = generation(&r1, true);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(gen1);
        let policy = HealthPolicy::new(Duration::from_millis(20), 0, Duration::from_secs(1))
            .unwrap_or_else(|_| unreachable!("a valid policy"));
        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            policy,
            owner.clone(),
            N,
            probe,
        ));

        // Round 0 publishes H1 for r1.
        {
            let overlay_handle = overlay_handle.clone();
            let r1 = Arc::clone(&r1);
            wait_until(move || overlay_handle.current_for(&r1).is_some()).await;
        }
        // Round 1 is fully in flight: all N probes blocked, each holding a guard.
        {
            let round1_started = Arc::clone(&round1_started);
            wait_until(move || round1_started.load(Ordering::SeqCst) == N).await;
        }

        // Rotate to a new generation reusing the still-live r1. `set` synchronously
        // revokes the old slot gate (so H1 loses authority at once) and advances the
        // revision (so the loop preempts round 1).
        feeder.set(generation(&r1, true));

        // The new generation publishes H2 for r1 once the old round is collected.
        {
            let gen2 = Arc::clone(&gen2_dropcount_at_start);
            wait_until(move || gen2.lock().unwrap_or_else(PoisonError::into_inner).len() == N)
                .await;
        }
        // And a fresh overlay is republished.
        {
            let overlay_handle = overlay_handle.clone();
            let r1 = Arc::clone(&r1);
            wait_until(move || overlay_handle.current_for(&r1).is_some()).await;
        }
        task.abort();

        assert_eq!(
            drop_count.load(Ordering::SeqCst),
            N,
            "every in-flight guard dropped exactly once (abort + drain)"
        );
        let cleared = cleared_at_drop
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(cleared.len(), N, "one observation per dropped guard");
        assert!(
            cleared.iter().all(|&was_cleared| was_cleared),
            "the overlay lost authority (feed-gate revoke on `set`) BEFORE the probes were aborted"
        );
        let gen2 = gen2_dropcount_at_start
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(gen2.len(), N, "the new generation probed every backend");
        assert!(
            gen2.iter().all(|&dropped| dropped == N),
            "the new generation started no probe until every old probe was collected"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_hard_task_abort_drops_every_in_flight_probe() {
        const N: usize = 3;
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (_routing_publisher, routing, r1) = published_source(1, N);
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();
        let started = Arc::new(AtomicUsize::new(0));
        let drop_count = Arc::new(AtomicUsize::new(0));
        let cleared_at_drop = Arc::new(Mutex::new(Vec::<bool>::new()));

        let probe = {
            let started = Arc::clone(&started);
            let drop_count = Arc::clone(&drop_count);
            let cleared_at_drop = Arc::clone(&cleared_at_drop);
            let overlay_handle = overlay_handle.clone();
            let r1 = Arc::clone(&r1);
            move |_generation: Arc<HealthGeneration>,
                  _source: Arc<RoutingSnapshot>,
                  _routing: RoutingSnapshotHandle,
                  _backend: MergedBackend,
                  _policy: HealthPolicy| {
                let guard = DropGuard {
                    overlay: overlay_handle.clone(),
                    source: Arc::clone(&r1),
                    drop_count: Arc::clone(&drop_count),
                    cleared_at_drop: Arc::clone(&cleared_at_drop),
                };
                let started = Arc::clone(&started);
                Box::pin(async move {
                    let _guard = guard;
                    started.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    }
                }) as BoxedProbe
            }
        };

        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(generation(&r1, true));
        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            HealthPolicy::go_defaults(),
            owner.clone(),
            N,
            probe,
        ));

        // Every probe of the first round is in flight, holding a guard.
        {
            let started = Arc::clone(&started);
            wait_until(move || started.load(Ordering::SeqCst) == N).await;
        }
        // A hard outer abort: the RAII guard must terminal-clear the overlay and
        // abort every in-flight child — no detached task can leak.
        task.abort();
        {
            let drop_count = Arc::clone(&drop_count);
            wait_until(move || drop_count.load(Ordering::SeqCst) == N).await;
        }
        {
            let overlay_handle = overlay_handle.clone();
            let r1 = Arc::clone(&r1);
            wait_until(move || overlay_handle.current_for(&r1).is_none()).await;
        }
        assert_eq!(
            drop_count.load(Ordering::SeqCst),
            N,
            "the RAII backstop dropped every in-flight probe exactly once"
        );
    }

    #[test]
    fn a_stale_owner_is_not_publishable() {
        let registry = OwnershipRegistry::new();
        let lease = registry
            .claim(OwnerScope::Process, "health-loop-owner")
            .unwrap_or_else(|error| unreachable!("claim: {error}"));
        let owner = lease.token();
        let (_publisher, routing, source) = published_source(1, 2);
        assert!(round_authoritative(&routing, &source, &owner));
        drop(lease);
        assert!(
            !round_authoritative(&routing, &source, &owner),
            "a retired owner is not publishable"
        );
    }

    // ================================================================
    // Fix 2: the loop observes an owner retirement within OWNER_POLL_INTERVAL in
    // each of its three waits (paused clock; one row per wait).
    // ================================================================

    /// A generous virtual watchdog: a correct loop terminates within one owner
    /// poll (~1s), so 300s never elapses for it; a hang (missing owner-poll arm)
    /// trips it and the row goes RED.
    const OWNER_WATCHDOG: Duration = Duration::from_secs(300);

    /// A guard that counts its own drop, proving an in-flight probe was aborted and
    /// dropped on termination.
    struct CountingGuard {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for CountingGuard {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_owner_retirement_terminates_the_none_park() {
        // The feed has NO generation (feeder held so the feed stays open), so the
        // loop parks in `wait_change_or_owner`.
        let (_publisher, routing, source) = published_source(1, 1);
        let (_feeder, feed) = HealthGenerationFeeder::new();
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();

        let probe = move |_g: Arc<HealthGeneration>,
                          _s: Arc<RoutingSnapshot>,
                          _r: RoutingSnapshotHandle,
                          _b: MergedBackend,
                          _p: HealthPolicy| {
            Box::pin(async {
                BackendHealth {
                    healthy: true,
                    server_version: None,
                }
            }) as BoxedProbe
        };
        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            HealthPolicy::go_defaults(),
            owner.clone(),
            4,
            probe,
        ));

        // Let the loop reach the park, then confirm one owner poll with a LIVE owner
        // does NOT terminate it.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(OWNER_POLL_INTERVAL).await;
        assert!(
            !task.is_finished(),
            "the loop stays parked while the owner is live"
        );

        // Release the owner: the next poll terminates the loop within one interval,
        // with no feed change.
        drop(lease);
        tokio::time::advance(OWNER_POLL_INTERVAL).await;
        let joined = tokio::time::timeout(OWNER_WATCHDOG, task).await;
        assert!(
            joined.is_ok(),
            "the none-park loop terminates within one owner poll after release"
        );
        assert!(
            overlay_handle.current_for(&source).is_none(),
            "the overlay is withdrawn"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_owner_retirement_terminates_an_in_flight_round() {
        let (_publisher, routing, source) = published_source(1, 1);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(generation(&source, true));
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();

        let started = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let probe = {
            let started = Arc::clone(&started);
            let drops = Arc::clone(&drops);
            move |_g: Arc<HealthGeneration>,
                  _s: Arc<RoutingSnapshot>,
                  _r: RoutingSnapshotHandle,
                  _b: MergedBackend,
                  _p: HealthPolicy| {
                let started = Arc::clone(&started);
                let guard = CountingGuard {
                    drops: Arc::clone(&drops),
                };
                Box::pin(async move {
                    let _guard = guard;
                    started.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    }
                }) as BoxedProbe
            }
        };
        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            HealthPolicy::go_defaults(),
            owner.clone(),
            4,
            probe,
        ));

        // Wait until the probe is in flight (blocked), so the round never completes.
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(OWNER_POLL_INTERVAL).await;
        assert!(
            !task.is_finished(),
            "the loop stays in the in-flight round while the owner is live"
        );

        drop(lease);
        tokio::time::advance(OWNER_POLL_INTERVAL).await;
        let joined = tokio::time::timeout(OWNER_WATCHDOG, task).await;
        assert!(
            joined.is_ok(),
            "the in-flight round terminates within one owner poll after release"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the in-flight probe was aborted and dropped"
        );
        assert!(
            overlay_handle.current_for(&source).is_none(),
            "the overlay is withdrawn"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_owner_retirement_terminates_a_long_cadence_sleep() {
        let (_publisher, routing, source) = published_source(1, 1);
        let (feeder, feed) = HealthGenerationFeeder::new();
        feeder.set(generation(&source, true));
        let (_registry, lease) = owner_lease();
        let owner = lease.token();
        let (overlay, overlay_handle) = HealthOverlayPublisher::new();

        // A one-hour cadence: the loop must terminate on the owner poll (~1s), NOT
        // when the 3600s cadence deadline is reached.
        let policy = HealthPolicy::new(Duration::from_secs(3600), 0, Duration::from_secs(1))
            .unwrap_or_else(|_| unreachable!("a valid policy"));
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = {
            let calls = Arc::clone(&calls);
            move |_g: Arc<HealthGeneration>,
                  _s: Arc<RoutingSnapshot>,
                  _r: RoutingSnapshotHandle,
                  _b: MergedBackend,
                  _p: HealthPolicy| {
                calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    BackendHealth {
                        healthy: true,
                        server_version: None,
                    }
                }) as BoxedProbe
            }
        };
        let task = tokio::spawn(run_health_loop(
            feed,
            routing.clone(),
            overlay,
            policy,
            owner.clone(),
            4,
            probe,
        ));

        // The first round publishes, then the loop enters the 1h cadence sleep.
        {
            let overlay_handle = overlay_handle.clone();
            let source = Arc::clone(&source);
            while overlay_handle.current_for(&source).is_none() {
                tokio::task::yield_now().await;
            }
        }
        tokio::time::advance(OWNER_POLL_INTERVAL).await;
        assert!(
            !task.is_finished(),
            "the loop stays in the cadence sleep while the owner is live"
        );

        drop(lease);
        tokio::time::advance(OWNER_POLL_INTERVAL).await;
        let joined = tokio::time::timeout(OWNER_WATCHDOG, task).await;
        assert!(
            joined.is_ok(),
            "the cadence sleep terminates within one owner poll, not at the 3600s deadline"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only the first round ran; the cadence deadline was never reached"
        );
        assert!(
            overlay_handle.current_for(&source).is_none(),
            "the overlay is withdrawn"
        );
    }
}
