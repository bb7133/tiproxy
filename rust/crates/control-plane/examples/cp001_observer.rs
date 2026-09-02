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

//! Emits CP-001 observations from the actual Rust domain/runtime code.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use std::{io::BufRead, io::BufReader, io::Write};

use control_plane::{
    ConfigSource, ControlConfig, ControlRuntime, EventSink, LogLevel, MetricsPolicy,
    OwnershipRegistry, RuntimeEvent, TlsPolicy,
};
use serde_json::{Value, json};

struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

fn config(generation: u64, root: &str, level: LogLevel) -> ControlConfig {
    ControlConfig::new(
        generation,
        Duration::from_secs(30),
        0,
        TlsPolicy::new(vec![PathBuf::from(root)])
            .unwrap_or_else(|error| unreachable!("observer TLS config: {error}")),
        level,
        MetricsPolicy::default(),
    )
    .unwrap_or_else(|error| unreachable!("observer control config: {error}"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(owner_id) = std::env::var_os("CP001_OWNER_CHILD") {
        return run_owner_child(owner_id.to_string_lossy().into_owned());
    }

    println!("{}", collect_observations()?);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn collect_observations() -> Result<Value, String> {
    let subprocess_restart_proved =
        start_and_stop_owner_child("process-A") && start_and_stop_owner_child("process-B");
    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "process-A",
        config(1, "/etc/tiproxy/tls-a", LogLevel::Info),
        Arc::new(NullSink),
    )
    .map_err(|error| format!("first runtime: {error}"))?;
    let stale_owner = runtime.handle().module_context().owner().clone();
    let established_tls = runtime.handle().config().current().tls();
    let updates = runtime.handle().config().subscribe();

    let invalid_rejected = runtime
        .apply_config(config(3, "/etc/tiproxy/tls-invalid", LogLevel::Warn))
        .is_err();
    let invalid_retained = runtime.handle().config().current().generation() == 1;
    let invalid_notified = updates.has_changed().unwrap_or(false);

    let applied = runtime
        .apply_config(config(2, "/etc/tiproxy/tls-b", LogLevel::Warn))
        .map_err(|error| format!("valid successor: {error}"))?;
    let new_notified = updates.has_changed().unwrap_or(false);
    let established_retained = established_tls.roots() == [PathBuf::from("/etc/tiproxy/tls-a")];
    let new_tls_visible = applied.tls().roots() == [PathBuf::from("/etc/tiproxy/tls-b")];

    // Dropping the process runtime models abrupt process death: the exact
    // owner lease is released without a graceful lifecycle transition.
    drop(runtime);
    let stale_fenced = !stale_owner.is_current();
    let successor = ControlRuntime::claim_process(
        &registry,
        "process-B",
        config(1, "/etc/tiproxy/tls-b", LogLevel::Warn),
        Arc::new(NullSink),
    )
    .map_err(|error| format!("successor runtime: {error}"))?;
    let successor_generation = successor
        .handle()
        .module_context()
        .owner()
        .generation()
        .unwrap_or(0);
    let observed_owner_generation = if std::env::var_os("CP001_MUTATE_OWNER_GENERATION").is_some() {
        successor_generation.saturating_add(1)
    } else {
        successor_generation
    };
    if !invalid_rejected || !invalid_retained || invalid_notified {
        return Err("invalid config changed last-good state or notified a watcher".to_owned());
    }
    if !new_notified || !established_retained || !new_tls_visible {
        return Err("valid successor did not preserve the required old/new TLS views".to_owned());
    }
    if !stale_fenced || successor_generation != 2 || !subprocess_restart_proved {
        return Err("stale owner fencing or real subprocess restart was not proved".to_owned());
    }

    Ok(json!({
        "schema_version": 1,
        "producer": "rust",
        "observations": [
            {
                "scenario_id": "CP-FAULT-RUNTIME-CONFIG-RELOAD",
                "step": 0,
                "contracts": ["CP-RUNTIME-001"],
                "subject": {"namespace": "process", "cluster": "local", "generation": 1},
                "outcome": "rejected",
                "effects": ["last_good_retained", "watcher_not_notified"],
                "state": [{"key": "validation_class", "value": "invalid_config"}],
                "counters": [
                    {"key": "committed_generation", "value": 1},
                    {"key": "notification_count", "value": 0}
                ]
            },
            {
                "scenario_id": "CP-FAULT-RUNTIME-CONFIG-RELOAD",
                "step": 1,
                "contracts": ["CP-RUNTIME-001"],
                "subject": {"namespace": "process", "cluster": "local", "generation": 2},
                "outcome": "committed",
                "effects": ["established_tls_retained", "new_tls_visible", "watcher_notified_once"],
                "state": [
                    {"key": "log_level", "value": applied.log_level().as_str()},
                    {"key": "metrics_namespace", "value": applied.metrics().namespace()}
                ],
                "counters": [
                    {"key": "committed_generation", "value": i64::try_from(applied.generation()).unwrap_or(i64::MAX)},
                    {"key": "notification_count", "value": 1}
                ]
            },
            {
                "scenario_id": "CP-FAULT-PROCESS-DEATH",
                "step": 0,
                "contracts": ["CP-RUNTIME-001"],
                "subject": {"namespace": "process", "cluster": "local", "generation": successor_generation},
                "outcome": "restarted",
                "effects": ["stale_owner_fenced", "subprocess_successor_started", "successor_claimed"],
                "state": [{"key": "owner_id", "value": "process-B"}],
                "counters": [
                    {"key": "owner_generation", "value": i64::try_from(observed_owner_generation).unwrap_or(i64::MAX)},
                    {"key": "stale_owner_current", "value": i32::from(!stale_fenced)},
                    {"key": "subprocess_restart_count", "value": 1}
                ]
            }
        ]
    }))
}

fn run_owner_child(owner_id: String) -> Result<(), Box<dyn std::error::Error>> {
    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        owner_id,
        config(1, "/etc/tiproxy/tls-a", LogLevel::Info),
        Arc::new(NullSink),
    )?;
    runtime.mark_ready()?;
    println!("ready");
    std::io::stdout().flush()?;
    loop {
        std::thread::park();
    }
}

fn start_and_stop_owner_child(owner_id: &str) -> bool {
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    let Ok(mut child) = Command::new(executable)
        .env("CP001_OWNER_CHILD", owner_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let (ready_tx, ready_rx) = mpsc::channel();
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let ready = stdout
            .and_then(|stdout| BufReader::new(stdout).lines().next())
            .and_then(Result::ok)
            .is_some_and(|line| line == "ready");
        let _ = ready_tx.send(ready);
    });
    let ready = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or(false);
    let killed = child.kill().is_ok();
    let waited = child.wait().is_ok();
    let joined = reader.join().is_ok();
    ready && killed && waited && joined
}
