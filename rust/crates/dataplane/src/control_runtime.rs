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
//! [`ControlClient`] and owns every task the control plane needs —
//! the transport owner running `ControlClient::run` with the
//! dispatch [`InboundForwarder`] (including its retained-frame
//! `resume_session` pump), the dispatch loop itself, and the CTL-05
//! snapshot owner (validate → apply → answer `SnapshotResult` with the
//! initiating request id → feed the applied generation back into drain
//! provenance). Metering has its full production lifecycle through the
//! dispatch loop: sessions record deltas via
//! [`DispatchNotice::Metering`], the tick seals batches onto the wire,
//! and reconnects replay everything unacknowledged.
//!
//! Shutdown and error propagation are owned here too:
//! [`ControlRuntime::shutdown`] stops the transport, which cascades —
//! the transport task returns, dropping the forwarder, which closes
//! the dispatch inbound, which drops the snapshot channel — and
//! [`ControlRuntime::join`] joins every task and reports the first
//! transport error.
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
use tokio::task::JoinHandle;

use crate::control_dispatch::{
    ControlDispatchHandle, DispatchNotice, spawn_control_dispatch, system_unix_millis,
};

/// Applies each newly validated snapshot to the serving side (for
/// example [`crate::server::DataplaneHandle::update_snapshot`], which
/// enforces listener-set immutability). A rejection is answered to the
/// peer as a failed `SnapshotResult`; the previously applied snapshot
/// stays in force.
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

/// The running control plane: every task it owns, joinable and
/// stoppable.
pub struct ControlRuntime {
    client: Arc<ControlClient>,
    handle: ControlDispatchHandle,
    transport: JoinHandle<Result<(), TransportError>>,
    dispatch: JoinHandle<()>,
    snapshots: JoinHandle<()>,
}

impl ControlRuntime {
    /// The session-facing dispatch surface (register/backend/expect/
    /// metering/closed/finished notices).
    #[must_use]
    pub fn handle(&self) -> ControlDispatchHandle {
        self.handle.clone()
    }

    /// The shared transport owner (diagnostics: epoch, reconnects,
    /// drop counters).
    #[must_use]
    pub fn client(&self) -> Arc<ControlClient> {
        Arc::clone(&self.client)
    }

    /// Requests shutdown: the transport stops, and the task chain
    /// drains (transport → forwarder drop → dispatch inbound close →
    /// snapshot channel close).
    pub fn shutdown(&self) {
        self.client.shutdown();
    }

    /// Joins every owned task and returns the transport's terminal
    /// result. Task panics surface as configuration errors rather
    /// than being swallowed.
    ///
    /// # Errors
    ///
    /// Returns the first transport error, or a description of a
    /// panicked task.
    pub async fn join(self) -> Result<(), TransportError> {
        let transport = match self.transport.await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Configuration(
                "control transport task panicked".to_owned(),
            )),
        };
        let dispatch = self.dispatch.await;
        let snapshots = self.snapshots.await;
        if dispatch.is_err() || snapshots.is_err() {
            return Err(TransportError::Configuration(
                "control dispatch or snapshot task panicked".to_owned(),
            ));
        }
        transport
    }
}

/// Constructs the control client and spawns the transport, dispatch,
/// and snapshot-owner tasks. This is the one production call site that
/// puts [`ControlClient::run`] and the dispatch gate on a live socket.
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
    Ok(ControlRuntime {
        client,
        handle,
        transport,
        dispatch,
        snapshots,
    })
}

/// The CTL-05 snapshot owner: validates and applies each inbound
/// `StateSnapshot` through the monotonic [`SnapshotStore`], hands the
/// changed snapshot to the serving-side consumer, answers the peer
/// with a `SnapshotResult` carrying the **initiating request id**, and
/// feeds the applied generation into the dispatch gate (drain
/// provenance). Rejections answer the peer and leave the previous
/// snapshot in force — never a silent drop.
async fn run_snapshot_owner<C: SnapshotConsumer>(
    client: Arc<ControlClient>,
    handle: ControlDispatchHandle,
    store: SnapshotStore,
    mut consumer: C,
    mut snapshots: mpsc::Receiver<ControlEnvelope>,
) {
    while let Some(envelope) = snapshots.recv().await {
        let Some(Body::StateSnapshot(snapshot)) = envelope.body else {
            continue;
        };
        let generation = envelope.generation;
        let now = UnixTime::since_unix_epoch(Duration::from_millis(system_unix_millis()));
        let result = match store.apply(generation, snapshot, now) {
            Ok(outcome) => {
                let applied = outcome.snapshot.generation();
                let apply_result = if outcome.changed {
                    consumer.apply(&outcome.snapshot)
                } else {
                    Ok(())
                };
                match apply_result {
                    Ok(()) => {
                        let _ = handle
                            .notify(DispatchNotice::AppliedGeneration(applied))
                            .await;
                        outcome.to_result()
                    }
                    Err(error) => error.to_result(store_generation(&store)),
                }
            }
            Err(error) => error.to_result(store_generation(&store)),
        };
        let answer = ControlEnvelope {
            request_id: envelope.request_id,
            generation,
            priority: Priority::Critical.into(),
            body: Some(Body::SnapshotResult(result)),
            ..ControlEnvelope::default()
        };
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
