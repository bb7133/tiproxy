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
    AdminApp, AdminHooks, DataplaneStatus, HealthInputs, HealthState, full_router,
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
    let checksum = server_config.go_checksum();
    let hooks = {
        let health = Arc::clone(&shared);
        let status = Arc::clone(&shared);
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
                config_checksum: checksum,
            }),
            metrics_text: Arc::new(|| "# HELP tiproxy_server_connections x\n".to_owned()),
            dataplane_status: Arc::new(move || {
                status.dataplane.lock().unwrap().clone().unwrap_or_default()
            }),
        }
    };
    let app = Arc::new(AdminApp::new(hooks, HealthState::new()));
    let router = full_router(Arc::clone(&app));

    let mut observations = Vec::with_capacity(steps.len());
    for step in &steps {
        if let Some(action) = step.get("action") {
            if action.get("ready").and_then(Value::as_bool) == Some(true) {
                app.mark_ready();
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
        let request = Request::builder()
            .method(step["method"].as_str().unwrap_or("GET"))
            .uri(step["path"].as_str().unwrap_or("/"))
            .body(Body::from(
                step["body"].as_str().unwrap_or_default().to_owned(),
            ))
            .expect("request");
        let (status, content_type, body) = oneshot(router.clone(), request).await;
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
