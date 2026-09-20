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

//! CP-ADMIN slice 4d replay: the real `tiproxyctl` binary runs
//! `tests/controlplane/cpctl/script.json` against the Rust admin listener
//! (plaintext, and TLS with `--insecure`), producing the same document as the
//! Go `TestCPCtlCapture` oracle. Environment: `CPCTL_SCRIPT`,
//! `CPCTL_TIPROXYCTL`, `CPADMIN_CURRENT_DIR` (the Go test package directory,
//! which fixes the default workdir inside the configuration).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use control_admin::config::MemoryConfigAdmin;
use control_admin::health::{HealthInputs, HealthState};
use control_admin::router::{AdminApp, AdminHooks, DataplaneStatus, full_router, plaintext_router};
use control_admin::serve::{ServeOptions, TlsConfigSource, serve};
use control_config::EffectiveConfig;
use rustls_pki_types::PrivateKeyDer;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::watch;

const SERVER_OVERLAY: &[u8] = b"enable-traffic-replay = false\n";
/// The Go oracle enables auto certificates on its TLS run; the overlay keeps
/// the configuration (and therefore `config get` and the health checksum) equal.
const TLS_OVERLAY: &[u8] =
    b"enable-traffic-replay = false\nsecurity.server-http-tls.auto-certs = true\n";

fn certificate() -> Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    )
}

async fn start(
    current_dir: &Path,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let default_config = EffectiveConfig::default()
        .validated(current_dir)
        .expect("default config");
    let server_config = default_config
        .patched_with_toml(
            if tls.is_some() {
                TLS_OVERLAY
            } else {
                SERVER_OVERLAY
            },
            current_dir,
        )
        .expect("server overlay");
    let config_admin = Arc::new(MemoryConfigAdmin::new(
        server_config,
        current_dir.to_path_buf(),
    ));
    let checksum_source = Arc::clone(&config_admin);
    let hooks = AdminHooks {
        health_inputs: Arc::new(move || HealthInputs {
            closing: false,
            namespaces_ready: true,
            applied_generation: 1,
            config_checksum: checksum_source.go_checksum(),
        }),
        metrics_text: Arc::new(|| "# HELP tiproxy_server_connections x\n".to_owned()),
        dataplane_status: Arc::new(DataplaneStatus::default),
        config: config_admin,
        drain: None,
        log_file: None,
        backend_metrics: Arc::new(|_| Vec::new()),
        redirect: Arc::new(|| Ok(())),
    };
    let app = Arc::new(AdminApp::new(hooks, HealthState::new()));
    app.mark_ready();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let tls: TlsConfigSource = Arc::new(move || tls.clone());
    let task = tokio::spawn(async move {
        serve(
            listener,
            full_router(Arc::clone(&app)),
            plaintext_router(app),
            tls,
            shutdown_rx,
            ServeOptions {
                connection_timeout: Duration::from_secs(30),
                shutdown_grace: Duration::from_millis(200),
                ..ServeOptions::default()
            },
        )
        .await;
    });
    (address, shutdown_tx, task)
}

fn write_files(dir: &Path, files: &Value) {
    for (name, content) in files.as_object().unwrap() {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content.as_str().unwrap()).unwrap();
    }
}

fn run_commands(
    binary: &str,
    dir: &Path,
    address: SocketAddr,
    insecure: bool,
    script: &Value,
) -> Vec<Value> {
    let mut observations = Vec::new();
    for command in script["commands"].as_array().unwrap() {
        let mut args: Vec<String> = vec![
            "--host".to_owned(),
            address.ip().to_string(),
            "--port".to_owned(),
            address.port().to_string(),
        ];
        if insecure {
            args.push("--insecure".to_owned());
        }
        for arg in command["args"].as_array().unwrap() {
            let arg = arg.as_str().unwrap();
            args.push(match arg.strip_prefix('@') {
                Some(name) => dir.join(name).to_string_lossy().into_owned(),
                None => arg.to_owned(),
            });
        }
        let output = Command::new(binary)
            .args(&args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout)
            .trim_end_matches('\n')
            .to_owned();
        observations.push(json!({
            "name": command["name"],
            "stdout": stdout,
            "exit_code": output.status.code().unwrap_or(-1),
        }));
    }
    observations
}

#[tokio::main]
async fn main() {
    let script: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("CPCTL_SCRIPT").expect("CPCTL_SCRIPT")).unwrap(),
    )
    .unwrap();
    let binary = std::env::var("CPCTL_TIPROXYCTL").expect("CPCTL_TIPROXYCTL");
    let current_dir =
        PathBuf::from(std::env::var("CPADMIN_CURRENT_DIR").expect("CPADMIN_CURRENT_DIR"));
    let mut capture = serde_json::Map::new();
    for (side, tls) in [("plain", None), ("tls", Some(certificate()))] {
        let dir = std::env::temp_dir().join(format!(
            "tiproxy-cpctl-replay-{}-{side}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_files(&dir, &script["files"]);
        let (address, shutdown, task) = start(&current_dir, tls.clone()).await;
        let observations = tokio::task::spawn_blocking({
            let binary = binary.clone();
            let dir = dir.clone();
            let script = script.clone();
            move || run_commands(&binary, &dir, address, tls.is_some(), &script)
        })
        .await
        .unwrap();
        let _ = shutdown.send(true);
        let _ = task.await;
        let _ = std::fs::remove_dir_all(&dir);
        capture.insert(side.to_owned(), Value::Array(observations));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(capture)).unwrap()
    );
}
