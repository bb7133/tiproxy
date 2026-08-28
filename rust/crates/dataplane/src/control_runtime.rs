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

//! The **single production composition entry** for the Rust control
//! plane (CTL-06): [`spawn_control_runtime`] constructs the
//! [`ControlClient`] and supervises every task the control plane needs
//! — the transport owner running `ControlClient::run` with the
//! dispatch [`InboundForwarder`](crate::control_dispatch::InboundForwarder)
//! (including its retained-frame `resume_session` pump), the dispatch
//! loop itself, and the CTL-05 snapshot owner. Metering has its full
//! production lifecycle through the dispatch handle: producers call
//! [`ControlDispatchHandle::record_metering`] and receive the ledger's
//! own fail-closed verdict, the tick seals batches onto the wire, and
//! reconnects replay everything unacknowledged.
//!
//! **Supervision**: a dedicated supervisor watches all three tasks. As
//! soon as any of them terminates — cleanly, fatally, or by panic —
//! it requests transport shutdown (cancelling the siblings), joins
//! every task, and only then arbitrates the result: a real error
//! (dispatch fatal, transport failure, panic) always wins over the
//! clean cascade exits it triggers, regardless of which exit the
//! supervisor happened to observe first; clean exits under a requested
//! shutdown are `Ok`, while a clean transport exit **without** a
//! requested shutdown is reported as an unexpected termination.
//!
//! **Snapshot transaction**: the snapshot owner applies each
//! `StateSnapshot` in two phases — [`SnapshotStore::stage`] (validate
//! only; the staged token holds the store's writer reservation) →
//! serving-side [`SnapshotConsumer::apply`] → commit. A consumer
//! rejection leaves the store untouched, so replaying the same
//! generation re-runs the consumer instead of being falsely
//! acknowledged off an already-advanced store; success is answered
//! with the initiating request id and feeds the applied generation
//! into drain provenance.
//!
//! DPL-03's `tiproxy-rs` main starts this runtime and feeds its
//! snapshot owner into the live listener generation manager. Terminal
//! session effects, metering producers, and topology projection remain
//! DPL-04/06/07 work, so issue #16's end-to-end lost-event/restart
//! acceptance stays open until those integrations land.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use control_proto::control_transport::{
    ClientConfig, ConnectionState, ControlClient, SessionMeta, TransportError,
};
use control_proto::snapshot::{
    SnapshotError, SnapshotLineage, SnapshotStore, UnixTime, ValidatedSnapshot,
};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{ControlEnvelope, Priority};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinError, JoinHandle};

use crate::control_dispatch::{
    ControlDispatchHandle, DispatchFatal, DispatchStats, TaggedEnvelope, spawn_control_dispatch,
    system_unix_millis,
};

/// Applies each newly validated snapshot to the serving side (for
/// example [`crate::server::DataplaneHandle::update_snapshot`], which
/// enforces listener-set immutability). A rejection is answered to the
/// peer as a failed `SnapshotResult` and the store is **not**
/// advanced: the previously applied snapshot stays in force and a
/// replay re-runs this consumer.
pub trait SnapshotConsumer: Send + 'static {
    /// Applies one validated snapshot.
    ///
    /// `still_current` is a cheap synchronous check of whether the
    /// control session that produced this snapshot is still the live
    /// one. A consumer that performs an externally visible serving
    /// swap **must** call it immediately before that swap, inside
    /// whatever lock guards the swap and with no `.await` between the
    /// check and the swap, and reject (return an error, applying
    /// nothing) when it returns `false`. The snapshot owner can span a
    /// Go restart at any `.await` inside `apply`; without this check a
    /// dead lineage's config could become the served generation after
    /// its process is gone. Consumers with no serving side effect may
    /// ignore it.
    ///
    /// # Errors
    ///
    /// Returns the rejection reported to the peer.
    fn apply(
        &mut self,
        snapshot: &Arc<ValidatedSnapshot>,
        still_current: &(dyn Fn() -> bool + Send + Sync),
    ) -> impl Future<Output = Result<(), SnapshotError>> + Send;
}

impl<F, Fut> SnapshotConsumer for F
where
    F: FnMut(&Arc<ValidatedSnapshot>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), SnapshotError>> + Send,
{
    fn apply(
        &mut self,
        snapshot: &Arc<ValidatedSnapshot>,
        _still_current: &(dyn Fn() -> bool + Send + Sync),
    ) -> impl Future<Output = Result<(), SnapshotError>> + Send {
        self(snapshot)
    }
}

/// Configuration for [`spawn_control_runtime`].
pub struct ControlRuntimeConfig {
    /// The validated control transport configuration (socket path,
    /// negotiation, queue bounds, timing).
    pub client: ClientConfig,
    /// The dispatch tick driving drain force deadlines and metering
    /// seals.
    pub tick_interval: Duration,
    /// Bounded queue between the dispatch loop and the snapshot owner.
    pub snapshot_queue: usize,
}

/// The running control plane: one supervisor owning every task,
/// joinable and stoppable.
pub struct ControlRuntime {
    client: Arc<ControlClient>,
    handle: ControlDispatchHandle,
    supervisor: JoinHandle<Result<(), TransportError>>,
}

impl ControlRuntime {
    /// The session-facing dispatch surface (register/backend/expect/
    /// metering/closed/finished, all through typed methods with their
    /// causal-ack contracts).
    #[must_use]
    pub fn handle(&self) -> ControlDispatchHandle {
        self.handle.clone()
    }

    /// The dispatcher's observable counters.
    #[must_use]
    pub fn stats(&self) -> Arc<DispatchStats> {
        self.handle.stats()
    }

    /// The shared transport owner (diagnostics: epoch, reconnects,
    /// drop counters).
    #[must_use]
    pub fn client(&self) -> Arc<ControlClient> {
        Arc::clone(&self.client)
    }

    /// Requests shutdown: the transport stops, and the supervisor
    /// cancels and joins the whole task chain.
    pub fn shutdown(&self) {
        self.client.shutdown();
    }

    /// Awaits the supervisor: it has already joined every task and
    /// arbitrated the first real error (never masked by the clean
    /// cascade exits an error triggers).
    ///
    /// # Errors
    ///
    /// The first real task error, or a description of a panicked task.
    pub async fn join(self) -> Result<(), TransportError> {
        match self.supervisor.await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Configuration(
                "control runtime supervisor panicked".to_owned(),
            )),
        }
    }

    /// Assembles a runtime from externally spawned tasks. This is the
    /// supervision seam [`spawn_control_runtime`] uses; it is public
    /// so alternate compositions and supervision regressions can drive
    /// exactly the production arbitration logic.
    #[must_use]
    pub fn supervise(
        client: Arc<ControlClient>,
        handle: ControlDispatchHandle,
        transport: JoinHandle<Result<(), TransportError>>,
        dispatch: JoinHandle<Result<(), DispatchFatal>>,
        snapshots: JoinHandle<Result<(), TransportError>>,
    ) -> Self {
        let supervisor = tokio::spawn(supervise_tasks(
            Arc::clone(&client),
            transport,
            dispatch,
            snapshots,
        ));
        Self {
            client,
            handle,
            supervisor,
        }
    }
}

/// Which task the supervisor observed terminating first.
enum FirstExit {
    Transport(Result<Result<(), TransportError>, JoinError>),
    Dispatch(Result<Result<(), DispatchFatal>, JoinError>),
    Snapshots(Result<Result<(), TransportError>, JoinError>),
}

/// Waits for the first task to terminate, shuts the transport down
/// (cancelling the siblings), joins **all** tasks, and only then
/// arbitrates: real errors always win over the clean cascade exits
/// they trigger, whichever exit was observed first.
async fn supervise_tasks(
    client: Arc<ControlClient>,
    mut transport: JoinHandle<Result<(), TransportError>>,
    mut dispatch: JoinHandle<Result<(), DispatchFatal>>,
    mut snapshots: JoinHandle<Result<(), TransportError>>,
) -> Result<(), TransportError> {
    let first = tokio::select! {
        result = &mut transport => FirstExit::Transport(result),
        result = &mut dispatch => FirstExit::Dispatch(result),
        result = &mut snapshots => FirstExit::Snapshots(result),
    };
    // Sampled BEFORE the supervisor's own cascade shutdown, so the
    // cascade cannot retroactively legitimize an unexpected exit.
    let shutdown_requested = client.is_shutdown();
    client.shutdown();

    let first_task = match &first {
        FirstExit::Transport(_) => "control transport",
        FirstExit::Dispatch(_) => "control dispatch",
        FirstExit::Snapshots(_) => "control snapshot owner",
    };
    let (transport_result, dispatch_result, snapshot_result) = match first {
        FirstExit::Transport(result) => (result, dispatch.await, snapshots.await),
        FirstExit::Dispatch(result) => (transport.await, result, snapshots.await),
        FirstExit::Snapshots(result) => (transport.await, dispatch.await, result),
    };

    let transport_error = match transport_result {
        Err(_) => Some(TransportError::Configuration(
            "control transport task panicked".to_owned(),
        )),
        Ok(Err(error)) => Some(error),
        Ok(Ok(())) => None,
    };
    let dispatch_error = match dispatch_result {
        Err(_) => Some(TransportError::Configuration(
            "control dispatch task panicked".to_owned(),
        )),
        Ok(Err(fatal)) => Some(TransportError::Configuration(format!(
            "control dispatch terminated: {fatal}"
        ))),
        Ok(Ok(())) => None,
    };
    let snapshot_error = match snapshot_result {
        Err(_) => Some(TransportError::Configuration(
            "control snapshot owner panicked".to_owned(),
        )),
        Ok(Err(error)) => Some(error),
        Ok(Ok(())) => None,
    };

    // Arbitration: real errors first — dispatch fatals describe the
    // root cause most precisely, then transport failures, then the
    // snapshot owner's. Clean exits contribute nothing, so a fatal can
    // never be masked by the cascade it triggered. When there is no
    // real error anywhere and no shutdown was requested, the FIRST
    // exit — whichever task it was, however the select observed it —
    // was an unexpected clean termination and is reported as such.
    if let Some(error) = [dispatch_error, transport_error, snapshot_error]
        .into_iter()
        .flatten()
        .next()
    {
        return Err(error);
    }
    if !shutdown_requested {
        return Err(TransportError::Configuration(format!(
            "{first_task} exited without a requested shutdown"
        )));
    }
    Ok(())
}

/// Constructs the control client and spawns the transport, dispatch,
/// and snapshot-owner tasks under one supervisor. This is the one
/// production call site that puts [`ControlClient::run`] and the
/// dispatch gate on a live socket.
///
/// # Errors
///
/// Returns the client's configuration validation error.
pub fn spawn_control_runtime<C: SnapshotConsumer>(
    config: ControlRuntimeConfig,
    store: SnapshotStore,
    consumer: C,
) -> Result<ControlRuntime, TransportError> {
    let client = Arc::new(ControlClient::new(config.client)?);
    Ok(spawn_control_runtime_with_client(
        client,
        config.tick_interval,
        config.snapshot_queue,
        store,
        consumer,
    ))
}

/// [`spawn_control_runtime`] over a pre-built client — the seam for
/// compositions whose session owner needs the shared client before the
/// runtime exists (the dispatch handle already has the same one-shot
/// installer shape).
#[must_use]
pub fn spawn_control_runtime_with_client<C: SnapshotConsumer>(
    client: Arc<ControlClient>,
    tick_interval: Duration,
    snapshot_queue: usize,
    store: SnapshotStore,
    consumer: C,
) -> ControlRuntime {
    let (snapshot_tx, snapshot_rx) = mpsc::channel(snapshot_queue.max(1));
    let (handle, forwarder, dispatch) =
        spawn_control_dispatch(Arc::clone(&client), snapshot_tx, tick_interval);
    let transport = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.run(&forwarder).await })
    };
    let snapshots = tokio::spawn(run_snapshot_owner(
        Arc::clone(&client),
        handle.clone(),
        store,
        consumer,
        snapshot_rx,
    ));
    ControlRuntime::supervise(client, handle, transport, dispatch, snapshots)
}

/// Applies one `StateSnapshot` envelope through the two-phase
/// transaction — [`SnapshotStore::stage`] (validate only, writer
/// reservation held) → serving-side consumer → commit — and builds the
/// peer's answer with the **initiating request id**. Returns the
/// answer plus the applied generation when (and only when) the commit
/// succeeded. Public so the transaction semantics are directly
/// testable.
pub async fn process_state_snapshot<C: SnapshotConsumer>(
    store: &SnapshotStore,
    consumer: &mut C,
    state: &watch::Receiver<ConnectionState>,
    tagged: &TaggedEnvelope,
    now: UnixTime,
) -> (ControlEnvelope, Option<u64>) {
    let envelope = &tagged.envelope;
    let lineage = SnapshotLineage {
        peer_process_id: Arc::clone(&tagged.origin.peer_process_id),
        peer_started_unix_millis: tagged.origin.peer_started_unix_millis,
    };
    let generation = envelope.generation;
    let (result, applied) = match &envelope.body {
        Some(Body::StateSnapshot(snapshot)) => {
            match store.stage(generation, snapshot.clone(), now, lineage) {
                Ok(staged) => {
                    let consumer_verdict = if staged.is_changed() {
                        // The consumer calls this immediately before any
                        // serving swap so a lineage superseded mid-apply
                        // never becomes the served generation.
                        let still_current = || origin_matches_live_session(state, &tagged.origin);
                        consumer.apply(staged.snapshot(), &still_current).await
                    } else {
                        // Already committed — which implies the whole
                        // two-phase apply (consumer included) succeeded
                        // when it was committed.
                        Ok(())
                    };
                    match consumer_verdict {
                        // Re-check lineage AFTER the consumer's apply
                        // (its await points can span a Go restart): if
                        // the live session is no longer this snapshot's
                        // lineage, the staged token is dropped
                        // uncommitted — the store, last-good, and the
                        // applied-generation barrier never advance under
                        // a dead lineage. (The serving consumer may have
                        // already swapped its generation; the live Go's
                        // own desired snapshot re-applies its config, and
                        // the dispatch loop's applied-generation barrier
                        // never binds commands to this uncommitted view.)
                        Ok(()) if !origin_matches_live_session(state, &tagged.origin) => (
                            SnapshotError::unsupported(
                                "control session changed lineage during snapshot apply",
                            )
                            .to_result(store_generation(store)),
                            None,
                        ),
                        Ok(()) => match store.commit(staged) {
                            Ok(outcome) => {
                                let applied = outcome.snapshot.generation();
                                (outcome.to_result(), Some(applied))
                            }
                            Err(error) => (error.to_result(store_generation(store)), None),
                        },
                        // The consumer rejected: the staged token is
                        // dropped uncommitted, the store still holds
                        // the previous generation, and a replay of
                        // this generation will re-run the consumer.
                        Err(error) => (error.to_result(store_generation(store)), None),
                    }
                }
                Err(error) => (error.to_result(store_generation(store)), None),
            }
        }
        _ => (
            SnapshotError::invalid("snapshot owner received a non-snapshot body")
                .to_result(store_generation(store)),
            None,
        ),
    };
    let answer = ControlEnvelope {
        request_id: envelope.request_id,
        generation,
        priority: Priority::Critical.into(),
        body: Some(Body::SnapshotResult(result)),
        ..ControlEnvelope::default()
    };
    (answer, applied)
}

/// The CTL-05 snapshot owner task: drives [`process_state_snapshot`]
/// for every inbound snapshot, passes the **applied-generation
/// barrier** (the dispatcher must have recorded the generation before
/// the OK goes to Go — commands minted against the new generation can
/// then never race an older applied view), and answers the peer.
/// Failure semantics are explicit: a barrier or send failure during a
/// requested shutdown is the normal cascade (clean exit), while the
/// same failure without one — the dispatcher or transport died
/// unexpectedly under this in-flight snapshot — propagates as the
/// owner's error for the supervisor to surface.
async fn run_snapshot_owner<C: SnapshotConsumer>(
    client: Arc<ControlClient>,
    handle: ControlDispatchHandle,
    store: SnapshotStore,
    mut consumer: C,
    mut snapshots: mpsc::Receiver<TaggedEnvelope>,
) -> Result<(), TransportError> {
    let state = client.subscribe_state();
    while let Some(tagged) = snapshots.recv().await {
        match snapshot_owner_step(&client, &handle, &store, &mut consumer, &state, &tagged).await? {
            SnapshotStep::Continue => {}
            SnapshotStep::CleanExit => return Ok(()),
        }
    }
    Ok(())
}

/// Whether the current live control session belongs to the SAME Go
/// lineage that produced `origin`. A snapshot can sit in the owner
/// queue across a session switch: wire epoch VALUES repeat across Go
/// restarts, so a snapshot from a dead lineage must be recognized by
/// its peer identity — never staged, applied, committed, or allowed to
/// move last-good / applied-generation against the current session's
/// desired state.
fn origin_matches_live_session(
    state: &watch::Receiver<ConnectionState>,
    origin: &SessionMeta,
) -> bool {
    match &*state.borrow() {
        ConnectionState::Connected {
            peer_process_id,
            peer_started_unix_millis,
            ..
        } => {
            peer_process_id.as_ref() == origin.peer_process_id.as_ref()
                && *peer_started_unix_millis == origin.peer_started_unix_millis
        }
        _ => false,
    }
}

/// Outcome of one snapshot-owner step.
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotStep {
    /// The envelope was processed and answered; keep serving.
    Continue,
    /// A requested shutdown interrupted the barrier or the answer:
    /// the normal cascade, exit cleanly.
    CleanExit,
}

/// One snapshot-owner iteration: transaction, applied-generation
/// barrier, answer. Public so the shutdown-boundary semantics are
/// directly testable: barrier/send failures under a requested
/// shutdown normalize to [`SnapshotStep::CleanExit`], while the same
/// failures without one propagate as the owner's error.
///
/// # Errors
///
/// The dispatch task disappearing before the barrier, or a
/// non-cascade transport send failure.
pub async fn snapshot_owner_step<C: SnapshotConsumer>(
    client: &Arc<ControlClient>,
    handle: &ControlDispatchHandle,
    store: &SnapshotStore,
    consumer: &mut C,
    state: &watch::Receiver<ConnectionState>,
    tagged: &TaggedEnvelope,
) -> Result<SnapshotStep, TransportError> {
    // Lineage gate BEFORE the transaction: a snapshot whose origin Go
    // lineage is not the live session's — because Go restarted while
    // this snapshot waited in the owner queue, or because there is no
    // live session at all — must not be staged, applied, committed, or
    // allowed to advance last-good / the applied-generation barrier.
    // Its desired state belongs to a process that no longer owns the
    // control plane; the current Go re-sends on its own session.
    if !origin_matches_live_session(state, &tagged.origin) {
        client.count_foreign_snapshot_dropped();
        return Ok(SnapshotStep::Continue);
    }
    let now = UnixTime::since_unix_epoch(Duration::from_millis(system_unix_millis()));
    let (answer, applied) = process_state_snapshot(store, consumer, state, tagged, now).await;
    if let Some(generation) = applied {
        client.mark_last_good_snapshot(generation);
        if !handle.applied_generation(generation).await {
            if client.is_shutdown() {
                return Ok(SnapshotStep::CleanExit);
            }
            return Err(TransportError::Configuration(
                "dispatch task gone before the applied-generation barrier".to_owned(),
            ));
        }
    }
    match client
        .send_session_scoped(answer, tagged.origin.serial)
        .await
    {
        // Any answer-send failure under a requested shutdown is the
        // normal cascade.
        Err(TransportError::StaleSessionEpoch | TransportError::Closed) if client.is_shutdown() => {
            Ok(SnapshotStep::CleanExit)
        }
        // Stale without shutdown: the session that carried this
        // snapshot is gone, and the answer would false-ack (or
        // false-nack) a DIFFERENT session's exchange — it is dropped.
        // Go re-sends the snapshot on the new session.
        Ok(()) | Err(TransportError::StaleSessionEpoch) => Ok(SnapshotStep::Continue),
        Err(error) => Err(error),
    }
}

fn store_generation(store: &SnapshotStore) -> u64 {
    store
        .current()
        .ok()
        .flatten()
        .map_or(0, |snapshot| snapshot.generation())
}
