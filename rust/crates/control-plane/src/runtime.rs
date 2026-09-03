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

//! Single-process control runtime, domain module seam, and observability.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::{Id, JoinSet};

use crate::config::{ConfigError, ConfigSource, ConfigStore, ControlConfig};
use crate::ownership::{OwnerError, OwnerLease, OwnerScope, OwnerToken, OwnershipRegistry};

/// Runtime lifecycle phases in their only valid order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// The process owner is claimed and foundations are being installed.
    Starting,
    /// All process-local foundations are installed.
    Ready,
    /// New ownership-affecting work must stop.
    Quiescing,
    /// SQL admission is stopped and established sessions are draining.
    Draining,
    /// Durable final effects are sealing and managed modules are stopping.
    Stopping,
    /// All managed work has joined and ownership has been released.
    Stopped,
    /// A managed module failed; shutdown remains mandatory.
    Failed,
}

impl LifecyclePhase {
    /// Returns the stable observation spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Quiescing => "quiescing",
            Self::Draining => "draining",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    const fn shutdown_started(self) -> bool {
        matches!(
            self,
            Self::Quiescing | Self::Draining | Self::Stopping | Self::Stopped | Self::Failed
        )
    }
}

/// Why the process-local runtime began shutting down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGTERM or SIGINT was received.
    Signal,
    /// A caller explicitly requested shutdown.
    Requested,
    /// A managed module exited before shutdown.
    ModuleExit,
    /// A managed module failed or panicked.
    ModuleFailure,
}

impl ShutdownReason {
    /// Returns the stable observation spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signal => "signal",
            Self::Requested => "requested",
            Self::ModuleExit => "module_exit",
            Self::ModuleFailure => "module_failure",
        }
    }
}

/// Immutable runtime state published to every in-process module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleSnapshot {
    /// Current phase.
    pub phase: LifecyclePhase,
    /// Unique process owner.
    pub owner_id: Arc<str>,
    /// Monotonic process-owner generation.
    pub owner_generation: u64,
    /// Last-good process configuration generation.
    pub config_generation: u64,
    /// First shutdown reason, if shutdown has started.
    pub shutdown_reason: Option<ShutdownReason>,
}

/// Stable event kinds emitted by the process foundation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEventKind {
    /// The process owner was acquired.
    RuntimeStarted,
    /// All foundations were installed.
    RuntimeReady,
    /// A lifecycle phase changed.
    PhaseChanged,
    /// A new last-good configuration committed.
    ConfigApplied,
    /// A candidate configuration was rejected.
    ConfigRejected,
    /// A managed module failed.
    RuntimeFailed,
    /// Shutdown completed and the owner was released.
    RuntimeStopped,
}

impl RuntimeEventKind {
    /// Returns the stable structured-log spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeStarted => "runtime_started",
            Self::RuntimeReady => "runtime_ready",
            Self::PhaseChanged => "phase_changed",
            Self::ConfigApplied => "config_applied",
            Self::ConfigRejected => "config_rejected",
            Self::RuntimeFailed => "runtime_failed",
            Self::RuntimeStopped => "runtime_stopped",
        }
    }
}

/// Payload-free structured lifecycle evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEvent {
    /// Event kind.
    pub kind: RuntimeEventKind,
    /// Lifecycle state after the event.
    pub snapshot: LifecycleSnapshot,
    /// Owned scope.
    pub owner_scope: String,
    /// Optional bounded module name.
    pub module: Option<&'static str>,
    /// Optional public error class; never an error string or payload.
    pub error_class: Option<&'static str>,
}

/// Sink for process-local structured lifecycle events.
pub trait EventSink: Send + Sync + 'static {
    /// Records one event. Implementations must not block indefinitely.
    fn record(&self, event: &RuntimeEvent);
}

/// JSON-lines stderr sink used by the production binary.
#[derive(Debug, Default)]
pub struct JsonStderrSink;

impl EventSink for JsonStderrSink {
    fn record(&self, event: &RuntimeEvent) {
        eprintln!(
            "{}",
            json!({
                "component": "control-plane",
                "event": event.kind.as_str(),
                "phase": event.snapshot.phase.as_str(),
                "owner_id": event.snapshot.owner_id.as_ref(),
                "owner_generation": event.snapshot.owner_generation,
                "config_generation": event.snapshot.config_generation,
                "owner_scope": event.owner_scope,
                "shutdown_reason": event.snapshot.shutdown_reason.map(ShutdownReason::as_str),
                "module": event.module,
                "error_class": event.error_class,
            })
        );
    }
}

/// Bounded counters for the runtime foundation.
#[derive(Debug, Default)]
pub struct RuntimeMetrics {
    starts: AtomicU64,
    ready: AtomicU64,
    shutdowns: AtomicU64,
    failures: AtomicU64,
    config_applied: AtomicU64,
    config_rejected: AtomicU64,
}

impl RuntimeMetrics {
    /// Takes a consistent-enough monotonic snapshot for metrics export.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeMetricsSnapshot {
        RuntimeMetricsSnapshot {
            starts: self.starts.load(Ordering::Relaxed),
            ready: self.ready.load(Ordering::Relaxed),
            shutdowns: self.shutdowns.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            config_applied: self.config_applied.load(Ordering::Relaxed),
            config_rejected: self.config_rejected.load(Ordering::Relaxed),
        }
    }
}

/// Public metric values with no dynamic labels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeMetricsSnapshot {
    /// Acquired process-owner count.
    pub starts: u64,
    /// Ready transition count.
    pub ready: u64,
    /// Shutdown request count.
    pub shutdowns: u64,
    /// Fatal module count.
    pub failures: u64,
    /// Accepted configuration count.
    pub config_applied: u64,
    /// Rejected configuration count.
    pub config_rejected: u64,
}

/// Runtime construction and transition failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeError {
    /// Process ownership could not be acquired.
    #[error(transparent)]
    Owner(#[from] OwnerError),
    /// A configuration replacement failed.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The requested lifecycle transition would violate shutdown ordering.
    #[error("invalid control runtime transition {from:?} -> {to:?}")]
    InvalidTransition {
        /// Current phase.
        from: LifecyclePhase,
        /// Requested phase.
        to: LifecyclePhase,
    },
}

/// Public failure returned by a future control module.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("control module {module} failed with {error_class}")]
pub struct ModuleError {
    /// Stable module name.
    pub module: &'static str,
    /// Public bounded error class, never a concrete error string.
    pub error_class: &'static str,
}

/// Boxed future returned by a dynamically composed control module.
pub type ModuleFuture = Pin<Box<dyn Future<Output = Result<(), ModuleError>> + Send + 'static>>;

/// Domain seam for later in-process control modules.
pub trait ControlModule: Send + 'static {
    /// Stable module name used in metrics and structured logs.
    fn name(&self) -> &'static str;

    /// Runs until shutdown or a fatal module error.
    fn run(self: Box<Self>, context: ModuleContext) -> ModuleFuture;
}

/// Registration failure for a process-local control module.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ModuleSetError {
    /// A stable module name may be registered only once per process runtime.
    #[error("control module {0} is already registered")]
    DuplicateModule(&'static str),
}

/// Terminal result for one registered control module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleExit {
    /// Stable module name.
    pub module: &'static str,
    /// Successful shutdown or a bounded public failure.
    pub result: Result<(), ModuleError>,
}

/// Explicit executor for feature modules owned by the binary composition root.
///
/// The set does not own lifecycle transitions. Its caller reacts to the first
/// unexpected exit by moving the shared [`ControlRuntime`] into shutdown, then
/// joins every remaining module before releasing process ownership.
pub struct ControlModuleSet {
    context: ModuleContext,
    registered: BTreeSet<&'static str>,
    task_names: HashMap<Id, &'static str>,
    tasks: JoinSet<Result<(), ModuleError>>,
}

impl ControlModuleSet {
    /// Creates an empty module set for one process runtime.
    #[must_use]
    pub fn new(handle: &RuntimeHandle) -> Self {
        Self {
            context: handle.module_context(),
            registered: BTreeSet::new(),
            task_names: HashMap::new(),
            tasks: JoinSet::new(),
        }
    }

    /// Registers and starts one module.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleSetError::DuplicateModule`] when the stable name was
    /// already registered, even if its original task has exited.
    pub fn spawn<M>(&mut self, module: M) -> Result<(), ModuleSetError>
    where
        M: ControlModule,
    {
        self.spawn_boxed(Box::new(module))
    }

    /// Registers and starts a dynamically composed module.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleSetError::DuplicateModule`] when the stable name was
    /// already registered, even if its original task has exited.
    pub fn spawn_boxed(&mut self, module: Box<dyn ControlModule>) -> Result<(), ModuleSetError> {
        let name = module.name();
        if !self.registered.insert(name) {
            return Err(ModuleSetError::DuplicateModule(name));
        }
        let context = self.context.clone();
        let task = self.tasks.spawn(async move { module.run(context).await });
        self.task_names.insert(task.id(), name);
        Ok(())
    }

    /// Returns whether no registered module task remains to be joined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Waits for the next module terminal result.
    ///
    /// Task panics and cancellations are converted to bounded public classes;
    /// concrete panic payloads and join errors never cross this boundary.
    pub async fn join_next(&mut self) -> Option<ModuleExit> {
        let joined = self.tasks.join_next_with_id().await?;
        match joined {
            Ok((id, result)) => {
                let module = self.task_names.remove(&id).unwrap_or("module_executor");
                Some(ModuleExit { module, result })
            }
            Err(error) => {
                let module = self
                    .task_names
                    .remove(&error.id())
                    .unwrap_or("module_executor");
                let error_class = if error.is_panic() {
                    "module_panicked"
                } else if error.is_cancelled() {
                    "module_cancelled"
                } else {
                    "module_join_failed"
                };
                Some(ModuleExit {
                    module,
                    result: Err(ModuleError {
                        module,
                        error_class,
                    }),
                })
            }
        }
    }

    /// Aborts all still-running tasks as a bounded final shutdown backstop.
    /// Callers must continue calling [`Self::join_next`] until the set is empty.
    pub fn abort_all(&mut self) {
        self.tasks.abort_all();
    }
}

/// Context shared with a process-local control module.
#[derive(Clone)]
pub struct ModuleContext {
    owner: OwnerToken,
    config: ConfigStore,
    lifecycle: watch::Receiver<LifecycleSnapshot>,
    metrics: Arc<RuntimeMetrics>,
}

impl ModuleContext {
    /// Returns the generation fence for externally visible writes.
    #[must_use]
    pub const fn owner(&self) -> &OwnerToken {
        &self.owner
    }

    /// Returns the versioned process configuration source.
    #[must_use]
    pub const fn config(&self) -> &ConfigStore {
        &self.config
    }

    /// Subscribes to lifecycle and shutdown phases.
    #[must_use]
    pub fn lifecycle(&self) -> watch::Receiver<LifecycleSnapshot> {
        self.lifecycle.clone()
    }

    /// Returns the shared bounded metrics owner.
    #[must_use]
    pub fn metrics(&self) -> Arc<RuntimeMetrics> {
        Arc::clone(&self.metrics)
    }
}

/// Handle exposed to the binary composition and future modules.
#[derive(Clone)]
pub struct RuntimeHandle {
    owner: OwnerToken,
    config: ConfigStore,
    lifecycle: watch::Receiver<LifecycleSnapshot>,
    metrics: Arc<RuntimeMetrics>,
}

impl RuntimeHandle {
    /// Returns a module context without exposing the owner lease.
    #[must_use]
    pub fn module_context(&self) -> ModuleContext {
        ModuleContext {
            owner: self.owner.clone(),
            config: self.config.clone(),
            lifecycle: self.lifecycle.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// Returns the versioned configuration source.
    #[must_use]
    pub const fn config(&self) -> &ConfigStore {
        &self.config
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub fn lifecycle(&self) -> LifecycleSnapshot {
        self.lifecycle.borrow().clone()
    }

    /// Returns a lifecycle subscriber.
    #[must_use]
    pub fn subscribe_lifecycle(&self) -> watch::Receiver<LifecycleSnapshot> {
        self.lifecycle.clone()
    }

    /// Returns the runtime counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<RuntimeMetrics> {
        Arc::clone(&self.metrics)
    }
}

/// Unique process-local control runtime owner.
pub struct ControlRuntime {
    lease: Mutex<Option<OwnerLease>>,
    owner_token: OwnerToken,
    owner_scope: OwnerScope,
    config: ConfigStore,
    lifecycle: watch::Sender<LifecycleSnapshot>,
    state: Mutex<LifecycleSnapshot>,
    events: Arc<dyn EventSink>,
    metrics: Arc<RuntimeMetrics>,
}

impl ControlRuntime {
    /// Claims the unique process owner and installs the initial foundations.
    ///
    /// # Errors
    ///
    /// Returns an error when another runtime already owns the process scope.
    pub fn claim_process(
        registry: &OwnershipRegistry,
        owner_id: impl Into<String>,
        initial: ControlConfig,
        events: Arc<dyn EventSink>,
    ) -> Result<Self, RuntimeError> {
        let lease = registry.claim(OwnerScope::Process, owner_id)?;
        let owner_token = lease.token();
        let config = ConfigStore::new(initial);
        let snapshot = LifecycleSnapshot {
            phase: LifecyclePhase::Starting,
            owner_id: Arc::from(lease.owner_id()),
            owner_generation: lease.generation(),
            config_generation: config.current().generation(),
            shutdown_reason: None,
        };
        let (lifecycle, _) = watch::channel(snapshot.clone());
        let metrics = Arc::new(RuntimeMetrics::default());
        metrics.starts.fetch_add(1, Ordering::Relaxed);
        let runtime = Self {
            lease: Mutex::new(Some(lease)),
            owner_token,
            owner_scope: OwnerScope::Process,
            config,
            lifecycle,
            state: Mutex::new(snapshot),
            events,
            metrics,
        };
        runtime.emit(RuntimeEventKind::RuntimeStarted, None, None);
        Ok(runtime)
    }

    /// Returns the in-process handle.
    #[must_use]
    pub fn handle(&self) -> RuntimeHandle {
        RuntimeHandle {
            owner: self.owner_token.clone(),
            config: self.config.clone(),
            lifecycle: self.lifecycle.subscribe(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// Marks all process foundations installed.
    ///
    /// # Errors
    ///
    /// Returns an error unless the runtime is starting.
    pub fn mark_ready(&self) -> Result<(), RuntimeError> {
        self.transition(LifecyclePhase::Ready, None)?;
        self.metrics.ready.fetch_add(1, Ordering::Relaxed);
        self.emit(RuntimeEventKind::RuntimeReady, None, None);
        Ok(())
    }

    /// Begins the fail-closed shutdown sequence. Repeated calls are idempotent
    /// and preserve the first reason.
    ///
    /// # Errors
    ///
    /// Returns an error only for a phase that cannot enter shutdown.
    pub fn begin_shutdown(&self, reason: ShutdownReason) -> Result<(), RuntimeError> {
        let current = self.current_state();
        if current.phase.shutdown_started() {
            return Ok(());
        }
        self.transition(LifecyclePhase::Quiescing, Some(reason))?;
        self.metrics.shutdowns.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Advances the ordered shutdown sequence to `Draining` or `Stopping`.
    ///
    /// # Errors
    ///
    /// Returns an error for skipped or reversed phases.
    pub fn advance_shutdown(&self, phase: LifecyclePhase) -> Result<(), RuntimeError> {
        self.transition(phase, None)
    }

    /// Records a public module failure and makes shutdown mandatory.
    ///
    /// The exact owner lease remains current while final effects are sealed
    /// and tasks join; [`Self::finish`] releases it only after those joins.
    pub fn fail(&self, module: &'static str, error_class: &'static str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase == LifecyclePhase::Stopped {
            return;
        }
        let was_shutdown = state.phase.shutdown_started();
        if !matches!(
            state.phase,
            LifecyclePhase::Draining | LifecyclePhase::Stopping
        ) {
            state.phase = LifecyclePhase::Failed;
        }
        state
            .shutdown_reason
            .get_or_insert(ShutdownReason::ModuleFailure);
        self.lifecycle.send_replace(state.clone());
        drop(state);
        if !was_shutdown {
            self.metrics.shutdowns.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics.failures.fetch_add(1, Ordering::Relaxed);
        self.emit(
            RuntimeEventKind::RuntimeFailed,
            Some(module),
            Some(error_class),
        );
    }

    /// Atomically applies a validated immediate-successor configuration.
    ///
    /// # Errors
    ///
    /// Returns the lineage error and keeps the prior last-good view.
    pub fn apply_config(
        &self,
        candidate: ControlConfig,
    ) -> Result<Arc<ControlConfig>, RuntimeError> {
        match self.config.apply(candidate) {
            Ok(applied) => {
                self.update_config_generation(applied.generation());
                self.metrics.config_applied.fetch_add(1, Ordering::Relaxed);
                self.emit(RuntimeEventKind::ConfigApplied, None, None);
                Ok(applied)
            }
            Err(error) => {
                self.metrics.config_rejected.fetch_add(1, Ordering::Relaxed);
                self.emit(
                    RuntimeEventKind::ConfigRejected,
                    None,
                    Some("invalid_config"),
                );
                Err(error.into())
            }
        }
    }

    /// Finishes shutdown and releases the unique process owner.
    ///
    /// # Errors
    ///
    /// Returns an error unless the runtime reached `Stopping`, including after
    /// a module failure. Failure never permits skipping drain and final seal.
    pub fn finish(&self) -> Result<(), RuntimeError> {
        self.transition(LifecyclePhase::Stopped, None)?;
        let lease = self
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(lease) = lease {
            lease.release();
        }
        self.emit(RuntimeEventKind::RuntimeStopped, None, None);
        Ok(())
    }

    fn transition(
        &self,
        next: LifecyclePhase,
        reason: Option<ShutdownReason>,
    ) -> Result<(), RuntimeError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = matches!(
            (state.phase, next),
            (LifecyclePhase::Starting, LifecyclePhase::Ready)
                | (
                    LifecyclePhase::Starting | LifecyclePhase::Ready,
                    LifecyclePhase::Quiescing
                )
                | (
                    LifecyclePhase::Quiescing | LifecyclePhase::Failed,
                    LifecyclePhase::Draining
                )
                | (LifecyclePhase::Draining, LifecyclePhase::Stopping)
                | (LifecyclePhase::Stopping, LifecyclePhase::Stopped)
        );
        if !valid {
            return Err(RuntimeError::InvalidTransition {
                from: state.phase,
                to: next,
            });
        }
        state.phase = next;
        if state.shutdown_reason.is_none() {
            state.shutdown_reason = reason;
        }
        self.lifecycle.send_replace(state.clone());
        drop(state);
        self.emit(RuntimeEventKind::PhaseChanged, None, None);
        Ok(())
    }

    fn update_config_generation(&self, generation: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.config_generation = generation;
        self.lifecycle.send_replace(state.clone());
    }

    fn current_state(&self) -> LifecycleSnapshot {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn emit(
        &self,
        kind: RuntimeEventKind,
        module: Option<&'static str>,
        error_class: Option<&'static str>,
    ) {
        self.events.record(&RuntimeEvent {
            kind,
            snapshot: self.current_state(),
            owner_scope: self.owner_scope.label(),
            module,
            error_class,
        });
    }
}
