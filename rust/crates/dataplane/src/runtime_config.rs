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

//! Atomic serving-side snapshot generations (DPL-03).
//!
//! The first accepted generation binds every SQL listener before the CTL-05
//! transaction commits. Later generations go through
//! [`DataplaneHandle::update_snapshot`], so all new admissions observe one
//! complete `Arc<ValidatedSnapshot>` while existing sessions retain the one
//! they captured. A rejected bind/update never changes either the serving
//! handle or the snapshot store's last-good generation.

use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use std::time::{Duration, Instant};

use control_proto::snapshot::{
    CompositionGenerations, SnapshotError, SnapshotStore, UnixTime, ValidatedSnapshot,
};
use control_proto::v1::StateSnapshot;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::admission::MemoryProbe;
use crate::control_runtime::{SnapshotComposition, SnapshotConsumer};
use crate::server::{
    AcceptedConnection, ConnectionFuture, ConnectionHandler, DataplaneHandle, DataplaneServer,
    ServerError,
};

/// Coherent serving-generation counters and last-good age.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GenerationStatusSnapshot {
    /// Latest generation successfully applied to the SQL serving side.
    pub applied_generation: u64,
    /// Latest generation rejected by bind or reload.
    pub rejected_generation: u64,
    /// Successful serving-side applies, including the initial bind.
    pub applied_total: u64,
    /// Serving-side rejections.
    pub rejected_total: u64,
    /// Current age of the last successful apply.
    pub last_good_age: Option<Duration>,
    /// Latest Rust-owned config/namespace generation composed into serving.
    pub composition_generation: u64,
    /// Latest rejected Rust-owned composition generation.
    pub rejected_composition_generation: u64,
    /// Successful independent config/namespace recompositions.
    pub composition_applied_total: u64,
    /// Rejected independent config/namespace recompositions.
    pub composition_rejected_total: u64,
}

#[derive(Debug, Default)]
struct GenerationStatusInner {
    applied_generation: u64,
    rejected_generation: u64,
    applied_total: u64,
    rejected_total: u64,
    last_good_at: Option<Instant>,
    composition_generation: u64,
    rejected_composition_generation: u64,
    composition_applied_total: u64,
    composition_rejected_total: u64,
}

/// Cloneable status reader shared with diagnostics/metrics exporters.
#[derive(Debug, Clone)]
pub struct GenerationStatus {
    inner: Arc<StdMutex<GenerationStatusInner>>,
    /// Latest Rust-owned config source generation actually installed by a
    /// successful serving apply (bridge bind/apply or recomposition). The
    /// value travels inside the validated view, so it is published only in
    /// the apply path that installed that exact view; CP-ADMIN's
    /// namespace-commit barrier waits on it directly.
    applied_config: tokio::sync::watch::Sender<u64>,
}

impl Default for GenerationStatus {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            applied_config: tokio::sync::watch::channel(0).0,
        }
    }
}

impl GenerationStatus {
    /// Observes every Rust-owned config generation a successful apply
    /// installed.
    #[must_use]
    pub fn applied_config_generation(&self) -> tokio::sync::watch::Receiver<u64> {
        self.applied_config.subscribe()
    }

    fn record_applied_config(&self, generation: u64) {
        self.applied_config.send_if_modified(|current| {
            if generation > *current {
                *current = generation;
                true
            } else {
                false
            }
        });
    }

    /// Returns one coherent observation.
    #[must_use]
    pub fn snapshot(&self) -> GenerationStatusSnapshot {
        let inner = lock_std(&self.inner);
        GenerationStatusSnapshot {
            applied_generation: inner.applied_generation,
            rejected_generation: inner.rejected_generation,
            applied_total: inner.applied_total,
            rejected_total: inner.rejected_total,
            last_good_age: inner.last_good_at.map(|instant| instant.elapsed()),
            composition_generation: inner.composition_generation,
            rejected_composition_generation: inner.rejected_composition_generation,
            composition_applied_total: inner.composition_applied_total,
            composition_rejected_total: inner.composition_rejected_total,
        }
    }

    fn applied(&self, generation: u64, composition_generation: u64, config_generation: u64) {
        let mut inner = lock_std(&self.inner);
        inner.applied_generation = generation;
        inner.applied_total = inner.applied_total.saturating_add(1);
        inner.last_good_at = Some(Instant::now());
        if composition_generation != 0 {
            inner.composition_generation = composition_generation;
        }
        drop(inner);
        self.record_applied_config(config_generation);
    }

    fn rejected(&self, generation: u64) {
        let mut inner = lock_std(&self.inner);
        inner.rejected_generation = generation;
        inner.rejected_total = inner.rejected_total.saturating_add(1);
    }

    fn composition_applied(&self, generation: u64, config_generation: u64) {
        let mut inner = lock_std(&self.inner);
        inner.composition_generation = generation;
        inner.composition_applied_total = inner.composition_applied_total.saturating_add(1);
        inner.last_good_at = Some(Instant::now());
        drop(inner);
        self.record_applied_config(config_generation);
    }

    fn composition_rejected(&self, generation: u64) {
        let mut inner = lock_std(&self.inner);
        inner.rejected_composition_generation = generation;
        inner.composition_rejected_total = inner.composition_rejected_total.saturating_add(1);
    }
}

struct ServingState {
    handle: Option<DataplaneHandle>,
    owner: Option<JoinHandle<Result<(), ServerError>>>,
    shutting_down: bool,
    last_bridge_source: Option<StateSnapshot>,
}

impl ServingState {
    const fn new() -> Self {
        Self {
            handle: None,
            owner: None,
            shutting_down: false,
            last_bridge_source: None,
        }
    }
}

/// In-process field-level composer used while topology remains on the legacy
/// bridge and config/namespace are Rust-owned.
pub trait ServingSnapshotComposer: Send + Sync + 'static {
    /// Replaces owned fields and returns a complete effective snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded validation error without changing serving state.
    fn compose(&self, source: &StateSnapshot) -> Result<SnapshotComposition, SnapshotError>;
}

#[derive(Clone)]
struct SharedConnectionHandler(Arc<dyn ConnectionHandler>);

impl ConnectionHandler for SharedConnectionHandler {
    fn handle(&self, connection: AcceptedConnection) -> ConnectionFuture {
        self.0.handle(connection)
    }
}

/// CTL-05 consumer that owns the SQL server's first bind and subsequent
/// atomic reloads.
pub struct DataplaneSnapshotConsumer {
    state: Arc<Mutex<ServingState>>,
    memory: Arc<dyn MemoryProbe>,
    handler: Arc<dyn ConnectionHandler>,
    status: GenerationStatus,
    force_join_grace: Duration,
    composer: Option<Arc<dyn ServingSnapshotComposer>>,
}

/// Cloneable shutdown/join/status surface retained by the executable while
/// the consumer itself lives in the control runtime's snapshot-owner task.
#[derive(Clone)]
pub struct DataplaneServingHandle {
    state: Arc<Mutex<ServingState>>,
    status: GenerationStatus,
    composer: Option<Arc<dyn ServingSnapshotComposer>>,
}

impl DataplaneSnapshotConsumer {
    /// Builds an initially unbound serving generation owner.
    #[must_use]
    pub fn new(
        memory: Arc<dyn MemoryProbe>,
        handler: Arc<dyn ConnectionHandler>,
    ) -> (Self, DataplaneServingHandle) {
        let state = Arc::new(Mutex::new(ServingState::new()));
        let status = GenerationStatus::default();
        (
            Self {
                state: Arc::clone(&state),
                memory,
                handler,
                status: status.clone(),
                force_join_grace: Duration::ZERO,
                composer: None,
            },
            DataplaneServingHandle {
                state,
                status,
                composer: None,
            },
        )
    }

    /// Builds a consumer that replaces Rust-owned fields before bridge
    /// validation and serving application.
    #[must_use]
    pub fn new_with_composer(
        memory: Arc<dyn MemoryProbe>,
        handler: Arc<dyn ConnectionHandler>,
        composer: Arc<dyn ServingSnapshotComposer>,
    ) -> (Self, DataplaneServingHandle) {
        let (mut consumer, mut serving) = Self::new(memory, handler);
        consumer.composer = Some(Arc::clone(&composer));
        serving.composer = Some(composer);
        (consumer, serving)
    }

    /// Forwards the forced-shutdown join grace to every server this
    /// consumer binds (see [`DataplaneServer::with_force_join_grace`]).
    #[must_use]
    pub fn with_force_join_grace(mut self, grace: Duration) -> Self {
        self.force_join_grace = grace;
        self
    }
}

impl SnapshotConsumer for DataplaneSnapshotConsumer {
    fn compose(&self, source: &StateSnapshot) -> Result<SnapshotComposition, SnapshotError> {
        match &self.composer {
            Some(composer) => composer.compose(source),
            None => Ok(SnapshotComposition {
                snapshot: source.clone(),
                generation: 0,
                config_generation: 0,
            }),
        }
    }

    fn apply(
        &mut self,
        snapshot: &Arc<ValidatedSnapshot>,
        still_current: &(dyn Fn() -> bool + Send + Sync),
    ) -> impl Future<Output = Result<(), SnapshotError>> + Send {
        let snapshot = Arc::clone(snapshot);
        let state = Arc::clone(&self.state);
        let memory = Arc::clone(&self.memory);
        let handler = Arc::clone(&self.handler);
        let status = self.status.clone();
        let force_join_grace = self.force_join_grace;
        async move {
            let generation = snapshot.generation();
            let mut serving = state.lock().await;
            if serving.shutting_down {
                status.rejected(generation);
                return Err(SnapshotError::unsupported("dataplane is shutting down"));
            }
            if serving.owner.as_ref().is_some_and(JoinHandle::is_finished) {
                status.rejected(generation);
                return Err(SnapshotError::invalid(
                    "SQL listener owner stopped before snapshot apply",
                ));
            }

            let bridge_source = snapshot.source_raw().clone();
            let composition_generation = snapshot.composition_generation();
            let config_generation = snapshot.config_generation();
            let result = if let Some(handle) = &serving.handle {
                // Lineage check immediately before the serving swap,
                // inside the serving lock with no await between: a
                // snapshot whose control session was superseded during
                // this apply must not become the served generation.
                if !still_current() {
                    status.rejected(generation);
                    return Err(SnapshotError::unsupported(
                        "control session superseded before snapshot swap",
                    ));
                }
                handle
                    .update_snapshot(snapshot)
                    .map_err(|error| snapshot_apply_error(&error))
            } else {
                match DataplaneServer::bind(snapshot, memory).await {
                    Ok(server) => {
                        // The bind awaited above; re-check lineage before
                        // committing the listener owner (no await between
                        // this check and the swap), and drop the freshly
                        // bound server if the session was superseded.
                        if !still_current() {
                            status.rejected(generation);
                            return Err(SnapshotError::unsupported(
                                "control session superseded before listener bind commit",
                            ));
                        }
                        let server = server.with_force_join_grace(force_join_grace);
                        let handle = server.handle();
                        let owner = tokio::spawn(server.run(SharedConnectionHandler(handler)));
                        serving.handle = Some(handle);
                        serving.owner = Some(owner);
                        Ok(())
                    }
                    Err(error) => Err(snapshot_apply_error(&error)),
                }
            };
            match result {
                Ok(()) => {
                    serving.last_bridge_source = Some(bridge_source);
                    status.applied(generation, composition_generation, config_generation);
                    Ok(())
                }
                Err(error) => {
                    status.rejected(generation);
                    Err(error)
                }
            }
        }
    }
}

impl DataplaneServingHandle {
    /// Observes every Rust-owned config generation a successful serving
    /// apply installed (initial bind, bridge apply, and recomposition alike).
    /// The generation is read from the validated view that was installed, so
    /// a rejected apply, a skipped recomposition, or a composition prepared
    /// but never applied can never confirm a config generation.
    #[must_use]
    pub fn applied_config_generation(&self) -> tokio::sync::watch::Receiver<u64> {
        self.status.applied_config_generation()
    }

    /// Returns the current serving-generation status.
    #[must_use]
    pub fn status(&self) -> GenerationStatusSnapshot {
        self.status.snapshot()
    }

    /// Returns the current listener/session metrics snapshot. `None` means
    /// no config generation has bound the SQL server yet.
    pub async fn metrics(&self) -> Option<crate::server::ServerMetricsSnapshot> {
        let serving = self.state.lock().await;
        serving.handle.as_ref().map(DataplaneHandle::metrics)
    }

    /// Re-composes the last bridge topology with the latest Rust-owned
    /// config/namespace generation and atomically swaps the serving view. A
    /// call before the first bridge snapshot is a no-op; that first snapshot
    /// will use the latest composer state.
    ///
    /// # Errors
    ///
    /// Returns complete snapshot validation or serving preflight errors while
    /// retaining the prior last-good view.
    pub async fn reload_composed(
        &self,
        validator: &SnapshotStore,
        now: UnixTime,
    ) -> Result<bool, SnapshotError> {
        let Some(composer) = &self.composer else {
            return Ok(false);
        };
        let serving = self.state.lock().await;
        let Some(source) = &serving.last_bridge_source else {
            return Ok(false);
        };
        let Some(handle) = &serving.handle else {
            return Ok(false);
        };
        let composition = composer.compose(source)?;
        if composition.generation == self.status.snapshot().composition_generation {
            return Ok(false);
        }
        let bridge_generation = self.status.snapshot().applied_generation;
        let generation = composition.generation;
        let config_generation = composition.config_generation;
        let snapshot = match validator.validate_composed(
            bridge_generation,
            CompositionGenerations {
                composition: generation,
                config: config_generation,
            },
            composition.snapshot,
            now,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.status.composition_rejected(generation);
                return Err(error);
            }
        };
        match handle.update_snapshot(snapshot) {
            Ok(()) => {
                self.status
                    .composition_applied(generation, config_generation);
                Ok(true)
            }
            Err(error) => {
                self.status.composition_rejected(generation);
                Err(snapshot_apply_error(&error))
            }
        }
    }

    /// Whether the SQL serving side is live for readiness probes: an
    /// owner task exists and has not finished, the listeners are not in
    /// the stop-accept phase, and shutdown has not begun.
    pub async fn is_serving(&self) -> bool {
        let serving = self.state.lock().await;
        let owner_alive = serving
            .owner
            .as_ref()
            .is_some_and(|owner| !owner.is_finished());
        let accepting = serving
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_draining());
        owner_alive && accepting && !serving.shutting_down
    }

    /// Stops accepting new connections while existing sessions keep
    /// running (the first coordinated-shutdown phase); a no-op before
    /// the first bind.
    pub async fn stop_accepting(&self) {
        let serving = self.state.lock().await;
        if let Some(handle) = &serving.handle {
            handle.stop_accepting();
        }
    }

    /// Requests listener/session shutdown and joins the one SQL server owner.
    /// Repeated calls are harmless.
    ///
    /// # Errors
    ///
    /// Returns a listener-owner error or a stable panic diagnostic.
    pub async fn shutdown(&self) -> Result<(), ServerError> {
        let owner = {
            let mut serving = self.state.lock().await;
            serving.shutting_down = true;
            if let Some(handle) = &serving.handle {
                handle.shutdown();
            }
            serving.owner.take()
        };
        let Some(owner) = owner else {
            return Ok(());
        };
        match owner.await {
            Ok(result) => result,
            Err(_) => Err(ServerError::ListenerTaskPanicked),
        }
    }
}

fn snapshot_apply_error(error: &ServerError) -> SnapshotError {
    match error {
        ServerError::TrafficReplayUnsupported | ServerError::ListenerReloadRequiresRestart => {
            SnapshotError::unsupported(error.to_string())
        }
        _ => SnapshotError::invalid(error.to_string()),
    }
}

fn lock_std<T>(mutex: &StdMutex<T>) -> StdMutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::GenerationStatus;

    /// Every successful apply path (bridge bind/apply with a composition,
    /// and recomposition) publishes the config generation carried by the
    /// installed view monotonically; a bridge apply without a composition
    /// carries none, and rejections never confirm anything.
    #[test]
    fn applied_config_watch_follows_every_successful_apply() {
        let status = GenerationStatus::default();
        let watch = status.applied_config_generation();
        assert_eq!(*watch.borrow(), 0);
        status.applied(1, 0, 0);
        assert_eq!(
            *watch.borrow(),
            0,
            "legacy one-source apply carries no config generation"
        );
        status.applied(2, 1, 1);
        assert_eq!(*watch.borrow(), 1, "initial bind records its config");
        status.composition_applied(2, 3);
        assert_eq!(*watch.borrow(), 3, "recomposition records its config");
        status.composition_applied(3, 2);
        assert_eq!(*watch.borrow(), 3, "never moves backwards");
        status.rejected(5);
        status.composition_rejected(9);
        assert_eq!(*watch.borrow(), 3, "rejections never confirm");
    }
}
