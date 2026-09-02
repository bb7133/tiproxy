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

//! CP-001 ownership, config/TLS, lifecycle, and fault/restart contracts.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use control_plane::{
    ConfigSource, ControlConfig, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
    MetricsPolicy, OwnerError, OwnerScope, OwnershipRegistry, RuntimeEvent, RuntimeEventKind,
    ShutdownReason, TlsPolicy, TlsSource,
};

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<RuntimeEvent>>,
}

impl RecordingSink {
    fn events(&self) -> Vec<RuntimeEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl EventSink for RecordingSink {
    fn record(&self, event: &RuntimeEvent) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
    }
}

fn config(generation: u64, roots: Vec<PathBuf>) -> ControlConfig {
    ControlConfig::new(
        generation,
        Duration::from_secs(30),
        8080,
        TlsPolicy::new(roots).unwrap_or_else(|error| unreachable!("valid TLS policy: {error}")),
        LogLevel::Info,
        MetricsPolicy::default(),
    )
    .unwrap_or_else(|error| unreachable!("valid config: {error}"))
}

#[test]
fn one_owner_per_scope_and_restart_fences_stale_tokens() {
    let registry = OwnershipRegistry::new();
    let first = registry
        .claim(OwnerScope::Process, "tiproxy-rs-100")
        .unwrap_or_else(|error| unreachable!("first owner: {error}"));
    let first_token = first.token();
    let duplicate = registry.claim(OwnerScope::Process, "tiproxy-rs-101");
    assert!(matches!(duplicate, Err(OwnerError::AlreadyOwned { .. })));
    let first_generation = first.generation();
    first.release();
    assert!(!first_token.is_current(), "released generations are fenced");

    let successor = registry
        .claim(OwnerScope::Process, "tiproxy-rs-101")
        .unwrap_or_else(|error| unreachable!("successor owner: {error}"));
    assert!(successor.generation() > first_generation);
    assert!(successor.token().is_current());
}

#[test]
fn config_is_atomic_last_good_and_tls_views_are_generation_stable() {
    let initial_root = PathBuf::from("/etc/tiproxy/tls-a");
    let next_root = PathBuf::from("/etc/tiproxy/tls-b");
    let store = control_plane::ConfigStore::new(config(1, vec![initial_root.clone()]));
    let established_tls = store.current_tls();
    let updates = store.subscribe();

    assert!(store.apply(config(3, vec![next_root.clone()])).is_err());
    assert_eq!(store.current().generation(), 1, "skips retain last-good");
    assert!(!updates.has_changed().unwrap_or(false));

    let applied = store
        .apply(config(2, vec![next_root.clone()]))
        .unwrap_or_else(|error| unreachable!("successor config: {error}"));
    assert_eq!(applied.generation(), 2);
    assert!(updates.has_changed().unwrap_or(false));
    assert_eq!(
        established_tls.roots(),
        &[initial_root],
        "an established user retains its immutable TLS generation"
    );
    assert_eq!(
        store.current_tls().roots(),
        &[next_root],
        "new users see the committed TLS generation"
    );
}

#[test]
fn config_generation_never_wraps_or_reuses_a_stale_value() {
    let store = control_plane::ConfigStore::new(config(u64::MAX, Vec::new()));
    let Err(error) = store.apply(config(1, Vec::new())) else {
        unreachable!("a terminal generation cannot wrap to one");
    };
    assert!(matches!(
        error,
        control_plane::ConfigError::GenerationExhausted { current: u64::MAX }
    ));
    assert_eq!(store.current().generation(), u64::MAX);
}

#[test]
fn lifecycle_is_ordered_observable_and_releases_owner() {
    let registry = OwnershipRegistry::new();
    let sink = Arc::new(RecordingSink::default());
    let runtime = ControlRuntime::claim_process(
        &registry,
        "tiproxy-rs-200",
        config(1, Vec::new()),
        sink.clone(),
    )
    .unwrap_or_else(|error| unreachable!("runtime claim: {error}"));
    let handle = runtime.handle();

    runtime
        .mark_ready()
        .unwrap_or_else(|error| unreachable!("ready: {error}"));
    runtime
        .apply_config(config(2, vec![PathBuf::from("/etc/tiproxy/tls")]))
        .unwrap_or_else(|error| unreachable!("config apply: {error}"));
    assert!(runtime.apply_config(config(4, Vec::new())).is_err());
    runtime
        .begin_shutdown(ShutdownReason::Signal)
        .unwrap_or_else(|error| unreachable!("quiesce: {error}"));
    runtime
        .advance_shutdown(LifecyclePhase::Draining)
        .unwrap_or_else(|error| unreachable!("drain: {error}"));
    runtime
        .advance_shutdown(LifecyclePhase::Stopping)
        .unwrap_or_else(|error| unreachable!("stop: {error}"));
    runtime
        .finish()
        .unwrap_or_else(|error| unreachable!("finish: {error}"));

    assert_eq!(handle.lifecycle().phase, LifecyclePhase::Stopped);
    assert!(!handle.module_context().owner().is_current());
    let metrics = handle.metrics().snapshot();
    assert_eq!(metrics.starts, 1);
    assert_eq!(metrics.ready, 1);
    assert_eq!(metrics.shutdowns, 1);
    assert_eq!(metrics.config_applied, 1);
    assert_eq!(metrics.config_rejected, 1);
    assert_eq!(metrics.failures, 0);

    let kinds: Vec<_> = sink.events().into_iter().map(|event| event.kind).collect();
    assert_eq!(
        kinds,
        [
            RuntimeEventKind::RuntimeStarted,
            RuntimeEventKind::PhaseChanged,
            RuntimeEventKind::RuntimeReady,
            RuntimeEventKind::ConfigApplied,
            RuntimeEventKind::ConfigRejected,
            RuntimeEventKind::PhaseChanged,
            RuntimeEventKind::PhaseChanged,
            RuntimeEventKind::PhaseChanged,
            RuntimeEventKind::PhaseChanged,
            RuntimeEventKind::RuntimeStopped,
        ]
    );

    let successor = registry.claim(OwnerScope::Process, "tiproxy-rs-201");
    assert!(
        successor.is_ok(),
        "finish releases the exact owner generation"
    );
}

#[test]
fn module_failure_preserves_owner_and_cannot_skip_ordered_shutdown() {
    let registry = OwnershipRegistry::new();
    let sink = Arc::new(RecordingSink::default());
    let runtime = ControlRuntime::claim_process(
        &registry,
        "tiproxy-rs-300",
        config(1, Vec::new()),
        sink.clone(),
    )
    .unwrap_or_else(|error| unreachable!("runtime claim: {error}"));
    let token = runtime.handle().module_context().owner().clone();
    runtime
        .mark_ready()
        .unwrap_or_else(|error| unreachable!("ready: {error}"));
    runtime.fail("legacy_bridge", "unexpected_exit");
    assert_eq!(runtime.handle().lifecycle().phase, LifecyclePhase::Failed);
    assert!(
        token.is_current(),
        "the lease stays live while tasks are joining"
    );
    assert!(
        runtime.advance_shutdown(LifecyclePhase::Stopping).is_err(),
        "failed runtimes cannot skip directly into a normal phase"
    );
    assert!(
        runtime.finish().is_err(),
        "failed runtimes cannot release ownership before drain and final seal"
    );
    runtime
        .advance_shutdown(LifecyclePhase::Draining)
        .unwrap_or_else(|error| unreachable!("failed runtime enters drain: {error}"));
    runtime
        .advance_shutdown(LifecyclePhase::Stopping)
        .unwrap_or_else(|error| unreachable!("failed runtime enters final seal: {error}"));
    runtime
        .finish()
        .unwrap_or_else(|error| unreachable!("failed runtime joins then finishes: {error}"));
    assert!(!token.is_current());
    assert_eq!(runtime.handle().metrics().snapshot().failures, 1);
    let events = sink.events();
    assert!(events.iter().any(|event| {
        event.kind == RuntimeEventKind::RuntimeFailed
            && event.module == Some("legacy_bridge")
            && event.error_class == Some("unexpected_exit")
    }));
}

#[test]
fn late_module_failure_does_not_regress_drain_or_final_seal() {
    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "tiproxy-rs-400",
        config(1, Vec::new()),
        Arc::new(RecordingSink::default()),
    )
    .unwrap_or_else(|error| unreachable!("runtime claim: {error}"));
    runtime
        .mark_ready()
        .unwrap_or_else(|error| unreachable!("ready: {error}"));
    runtime
        .begin_shutdown(ShutdownReason::Signal)
        .unwrap_or_else(|error| unreachable!("quiesce: {error}"));
    runtime
        .advance_shutdown(LifecyclePhase::Draining)
        .unwrap_or_else(|error| unreachable!("drain: {error}"));
    runtime.fail("metering_sampler", "late_failure");
    assert_eq!(runtime.handle().lifecycle().phase, LifecyclePhase::Draining);
    runtime
        .advance_shutdown(LifecyclePhase::Stopping)
        .unwrap_or_else(|error| unreachable!("final seal: {error}"));
    runtime.fail("legacy_bridge", "late_failure");
    assert_eq!(runtime.handle().lifecycle().phase, LifecyclePhase::Stopping);
    runtime
        .finish()
        .unwrap_or_else(|error| unreachable!("finish after late failure: {error}"));
}

#[test]
fn internal_domain_has_no_control_proto_dependency() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .unwrap_or_else(|error| unreachable!("read control-plane manifest: {error}"));
    assert!(
        !manifest.contains("control-proto"),
        "the legacy protobuf boundary must not become the internal domain model"
    );
}
