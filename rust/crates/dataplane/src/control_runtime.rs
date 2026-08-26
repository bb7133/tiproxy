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
//! Application `main` wiring (live listener sessions feeding this
//! runtime) lands with the DPL-03/05 integrations; issue #16's
//! end-to-end lost-event/restart acceptance stays open until then.

use std::sync::Arc;
use std::time::Duration;

use control_proto::control_transport::{ClientConfig, ControlClient, TransportError};
use control_proto::snapshot::{SnapshotError, SnapshotStore, UnixTime, ValidatedSnapshot};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{ControlEnvelope, Priority};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};

use crate::control_dispatch::{
    ControlDispatchHandle, DispatchFatal, DispatchStats, spawn_control_dispatch, system_unix_millis,
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
    /// # Errors
    ///
    /// Returns the rejection reported to the peer.
    fn apply(&mut self, snapshot: &Arc<ValidatedSnapshot>) -> Result<(), SnapshotError>;
}

impl<F> SnapshotConsumer for F
where
    F: FnMut(&Arc<ValidatedSnapshot>) -> Result<(), SnapshotError> + Send + 'static,
{
    fn apply(&mut self, snapshot: &Arc<ValidatedSnapshot>) -> Result<(), SnapshotError> {
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
        snapshots: JoinHandle<()>,
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
    Snapshots(Result<(), JoinError>),
}

/// Waits for the first task to terminate, shuts the transport down
/// (cancelling the siblings), joins **all** tasks, and only then
/// arbitrates: real errors always win over the clean cascade exits
/// they trigger, whichever exit was observed first.
async fn supervise_tasks(
    client: Arc<ControlClient>,
    mut transport: JoinHandle<Result<(), TransportError>>,
    mut dispatch: JoinHandle<Result<(), DispatchFatal>>,
    mut snapshots: JoinHandle<()>,
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

    let transport_first = matches!(first, FirstExit::Transport(_));
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
        // A clean transport exit is unexpected only when the transport
        // itself terminated first without a requested shutdown; after
        // the supervisor's own cascade it is the expected outcome.
        Ok(Ok(())) if transport_first && !shutdown_requested => {
            Some(TransportError::Configuration(
                "control transport exited without a requested shutdown".to_owned(),
            ))
        }
        Ok(Ok(())) => None,
    };
    let dispatch_error = match dispatch_result {
        Err(_) => Some(TransportError::Configuration(
            "control dispatch task panicked".to_owned(),
        )),
        Ok(Err(fatal)) => Some(TransportError::Configuration(format!(
            "control dispatch terminated: {fatal}"
        ))),
        // A clean dispatch exit is the shutdown cascade (its channels
        // closed); never an error by itself.
        Ok(Ok(())) => None,
    };
    let snapshot_error = snapshot_result
        .err()
        .map(|_| TransportError::Configuration("control snapshot owner panicked".to_owned()));

    // Arbitration: dispatch fatals describe the root cause most
    // precisely, then transport failures, then panics of the snapshot
    // owner. Clean exits contribute nothing, so a fatal can never be
    // masked by the cascade it triggered.
    match [dispatch_error, transport_error, snapshot_error]
        .into_iter()
        .flatten()
        .next()
    {
        Some(error) => Err(error),
        None => Ok(()),
    }
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
    let (snapshot_tx, snapshot_rx) = mpsc::channel(config.snapshot_queue.max(1));
    let (handle, forwarder, dispatch) =
        spawn_control_dispatch(Arc::clone(&client), snapshot_tx, config.tick_interval);
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
    Ok(ControlRuntime::supervise(
        client, handle, transport, dispatch, snapshots,
    ))
}

/// Applies one `StateSnapshot` envelope through the two-phase
/// transaction — [`SnapshotStore::stage`] (validate only, writer
/// reservation held) → serving-side consumer → commit — and builds the
/// peer's answer with the **initiating request id**. Returns the
/// answer plus the applied generation when (and only when) the commit
/// succeeded. Public so the transaction semantics are directly
/// testable.
pub fn process_state_snapshot<C: SnapshotConsumer>(
    store: &SnapshotStore,
    consumer: &mut C,
    envelope: &ControlEnvelope,
    now: UnixTime,
) -> (ControlEnvelope, Option<u64>) {
    let generation = envelope.generation;
    let (result, applied) = match &envelope.body {
        Some(Body::StateSnapshot(snapshot)) => {
            match store.stage(generation, snapshot.clone(), now) {
                Ok(staged) => {
                    let consumer_verdict = if staged.is_changed() {
                        consumer.apply(staged.snapshot())
                    } else {
                        // Already committed — which implies the whole
                        // two-phase apply (consumer included) succeeded
                        // when it was committed.
                        Ok(())
                    };
                    match consumer_verdict {
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
/// for every inbound snapshot, answers the peer, and feeds successful
/// applications into drain provenance.
async fn run_snapshot_owner<C: SnapshotConsumer>(
    client: Arc<ControlClient>,
    handle: ControlDispatchHandle,
    store: SnapshotStore,
    mut consumer: C,
    mut snapshots: mpsc::Receiver<ControlEnvelope>,
) {
    while let Some(envelope) = snapshots.recv().await {
        let now = UnixTime::since_unix_epoch(Duration::from_millis(system_unix_millis()));
        let (answer, applied) = process_state_snapshot(&store, &mut consumer, &envelope, now);
        if let Some(generation) = applied {
            let _ = handle.applied_generation(generation).await;
        }
        let _ = client.send(answer).await;
    }
}

fn store_generation(store: &SnapshotStore) -> u64 {
    store
        .current()
        .ok()
        .flatten()
        .map_or(0, |snapshot| snapshot.generation())
}
