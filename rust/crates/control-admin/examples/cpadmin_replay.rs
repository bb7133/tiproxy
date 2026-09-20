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

//! Replays `tests/controlplane/cpadmin/script.json` through the Rust admin
//! router with the same state actions the Go capture test applies, and
//! computes the config checksum scenarios with `control-config`. Output is
//! compared exactly against the Go capture by `tests/controlplane/cpadmin`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use control_admin::router::oneshot;
use control_admin::{
    AdminApp, AdminHooks, DataplaneStatus, DrainProgress, DrainStartError, HealthInputs,
    HealthState, MemoryConfigAdmin, ScriptedDrainAdmin, full_router,
};
use control_config::EffectiveConfig;
use serde_json::{Value, json};

/// The Go capture builds its server with this overlay because the Rust
/// dataplane composition rejects traffic replay.
const SERVER_OVERLAY: &[u8] = b"enable-traffic-replay = false\n";
const PARTIAL_UPDATE: &[u8] = b"[proxy]\nmax-connections = 123\n[log]\nlevel = \"warn\"\n";
const NO_CHANGE_UPDATE: &[u8] = b"[proxy]\nmax-connections = 123\n";

struct Shared {
    closing: AtomicBool,
    namespaces_ready: AtomicBool,
    dataplane: Mutex<Option<DataplaneStatus>>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let script = std::env::var("CPADMIN_SCRIPT").expect("CPADMIN_SCRIPT");
    let current_dir =
        PathBuf::from(std::env::var("CPADMIN_CURRENT_DIR").expect("CPADMIN_CURRENT_DIR"));
    let steps: Vec<Value> =
        serde_json::from_slice(&std::fs::read(script).expect("read script")).expect("script json");

    let default_config = EffectiveConfig::default()
        .validated(&current_dir)
        .expect("default config");
    let server_config = default_config
        .patched_with_toml(SERVER_OVERLAY, &current_dir)
        .expect("server overlay");
    let partial = default_config
        .patched_with_toml(PARTIAL_UPDATE, &current_dir)
        .expect("partial update");
    let no_change = partial
        .patched_with_toml(NO_CHANGE_UPDATE, &current_dir)
        .expect("no-change update");
    // Namespaces carry their own checksum; the config checksum is unaffected.
    let namespace_only = no_change.go_checksum();

    let shared = Arc::new(Shared {
        closing: AtomicBool::new(false),
        namespaces_ready: AtomicBool::new(true),
        dataplane: Mutex::new(None),
    });
    // Go's per-process namespace store and SetTOMLConfig semantics, so the
    // HTTP layer is compared on identical storage behaviour; the health
    // checksum follows the store so a configuration PUT changes it like Go.
    let config_admin = Arc::new(MemoryConfigAdmin::new(
        server_config.clone(),
        current_dir.clone(),
    ));
    // The drain seam is scripted by the same actions the Go capture applies
    // to its stub drainer, so the HTTP mapping is compared one to one.
    let drainer = Arc::new(ScriptedDrainAdmin::default());
    let drain_enabled = Arc::new(AtomicBool::new(false));
    let backend_metrics = Arc::new(Mutex::new(Vec::<u8>::new()));
    let backend_metrics_source = Arc::clone(&backend_metrics);
    let hooks = {
        let health = Arc::clone(&shared);
        let status = Arc::clone(&shared);
        let checksum_source = Arc::clone(&config_admin);
        AdminHooks {
            health_inputs: Arc::new(move || HealthInputs {
                closing: health.closing.load(Ordering::SeqCst),
                namespaces_ready: health.namespaces_ready.load(Ordering::SeqCst),
                applied_generation: health
                    .dataplane
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map_or(1, |status| status.applied_generation),
                config_checksum: checksum_source.go_checksum(),
            }),
            metrics_text: Arc::new(|| "# HELP tiproxy_server_connections x\n".to_owned()),
            dataplane_status: Arc::new(move || {
                status.dataplane.lock().unwrap().clone().unwrap_or_default()
            }),
            config: config_admin,
            drain: None,
            log_file: None,
            backend_metrics: Arc::new(move |_| backend_metrics_source.lock().unwrap().clone()),
        }
    };
    let hooks_with_drain = AdminHooks {
        drain: Some(Arc::clone(&drainer) as control_admin::SharedDrainAdmin),
        ..hooks.clone()
    };
    let health_state = HealthState::new();
    let app = Arc::new(AdminApp::new(hooks, health_state.clone()));
    let app_with_drain = Arc::new(AdminApp::new(hooks_with_drain, health_state));
    let router_without_drain = full_router(Arc::clone(&app));
    let router_with_drain = full_router(Arc::clone(&app_with_drain));

    let mut observations = Vec::with_capacity(steps.len());
    for step in &steps {
        if let Some(action) = step.get("action") {
            if action.get("ready").and_then(Value::as_bool) == Some(true) {
                app.mark_ready();
                app_with_drain.mark_ready();
            }
            if let Some(data) = action.get("backend_metrics").and_then(Value::as_str) {
                *backend_metrics.lock().unwrap() = data.as_bytes().to_vec();
            }
            if let Some(drain) = action.get("drainer") {
                drain_enabled.store(true, Ordering::SeqCst);
                if let Some(start) = drain.get("start").and_then(Value::as_str) {
                    drainer.push_start(match start {
                        "ok" => Ok(()),
                        "invalid_budget" => Err(DrainStartError::InvalidBudget),
                        "no_session" => Err(DrainStartError::NoSession),
                        "snapshot_not_ready" => Err(DrainStartError::SnapshotNotReady),
                        "in_progress" => Err(DrainStartError::InProgress),
                        "foreign_active" => Err(DrainStartError::ForeignActive),
                        other => Err(DrainStartError::Other(other.to_owned())),
                    });
                }
                if let Some(status) = drain.get("status").and_then(Value::as_object) {
                    let number = |key: &str| status.get(key).and_then(Value::as_u64).unwrap_or(0);
                    drainer.set_status(
                        status
                            .get("drain_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                        DrainProgress {
                            active_connections: number("active_connections"),
                            gracefully_closed: number("gracefully_closed"),
                            force_closed: number("force_closed"),
                            complete: status
                                .get("complete")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            code: status
                                .get("code")
                                .and_then(Value::as_str)
                                .unwrap_or("ERROR_CODE_OK")
                                .to_owned(),
                            detail: status
                                .get("detail")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                        },
                    );
                }
            }
            if let Some(ready) = action.get("namespaces_ready").and_then(Value::as_bool) {
                shared.namespaces_ready.store(ready, Ordering::SeqCst);
            }
            if action.get("preclose").and_then(Value::as_bool) == Some(true) {
                shared.closing.store(true, Ordering::SeqCst);
            }
            if let Some(dataplane) = action.get("dataplane") {
                let field = |key: &str| dataplane[key].as_u64().unwrap_or_default();
                *shared.dataplane.lock().unwrap() = Some(DataplaneStatus {
                    enabled: true,
                    desired_generation: field("desired_generation"),
                    sent_generation: field("sent_generation"),
                    applied_generation: field("applied_generation"),
                    rejected_generation: field("rejected_generation"),
                    last_result_code: dataplane["last_result_code"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    detail: dataplane["detail"].as_str().unwrap_or_default().to_owned(),
                    last_good_age_ms: dataplane["last_good_age_ms"].as_i64().unwrap_or_default(),
                });
            }
        }
        let mut builder = Request::builder()
            .method(step["method"].as_str().unwrap_or("GET"))
            .uri(step["path"].as_str().unwrap_or("/"));
        if let Some(headers) = step.get("headers").and_then(Value::as_object) {
            for (name, value) in headers {
                builder = builder.header(name.as_str(), value.as_str().unwrap_or_default());
            }
        }
        let request = builder
            .body(Body::from(
                step["body"].as_str().unwrap_or_default().to_owned(),
            ))
            .expect("request");
        let router = if drain_enabled.load(Ordering::SeqCst) {
            router_with_drain.clone()
        } else {
            router_without_drain.clone()
        };
        let (status, content_type, body) = oneshot(router, request).await;
        observations.push(json!({
            "name": step["name"],
            "status": status.as_u16(),
            "content_type": content_type,
            "body": body,
        }));
    }
    let output = json!({
        "observations": observations,
        "checksums": {
            "default": default_config.go_checksum(),
            "partial_update": partial.go_checksum(),
            "no_change_update": no_change.go_checksum(),
            "namespace_only_update": namespace_only,
            "workdir": current_dir.join("work").to_string_lossy(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&output).expect("json"));
}
