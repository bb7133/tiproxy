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

//! CP-ADMIN slice 4b replay: the Rust admin listener (plaintext h2c and
//! TLS) answers `tests/controlplane/cpdiag/script.json` over a real gRPC
//! wire, producing the same document as the Go `TestCPDiagCapture` oracle.
//! Environment: `CPDIAG_SCRIPT` (script path); the JSON goes to stdout.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use control_admin::health::{HealthInputs, HealthState};
use control_admin::router::{AdminApp, AdminHooks, DataplaneStatus, full_router, plaintext_router};
use control_admin::serve::{ServeOptions, TlsConfigSource, serve};
use control_external::diagnostics::{
    LogLevel, SearchLogRequest, SearchLogResponse, ServerInfoRequest, ServerInfoResponse,
};
use http::uri::PathAndQuery;
use hyper_util::rt::TokioIo;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tonic_prost::ProstCodec;

fn write_fixture(dir: &Path, files: &[Value]) {
    for file in files {
        let name = file["name"].as_str().unwrap();
        let lines: Vec<String> = if let Some(generate) = file.get("generate") {
            let count = generate["count"].as_u64().unwrap();
            let prefix = generate["stamp_prefix"].as_str().unwrap();
            let level = generate["level"].as_str().unwrap();
            (0..count)
                .map(|i| {
                    format!(
                        "[{prefix}{:02}.{:03} -04:00] [{level}] [bulk.go:1] [\"line {i}\"]",
                        i / 1000,
                        i % 1000
                    )
                })
                .collect()
        } else {
            file["lines"]
                .as_array()
                .unwrap()
                .iter()
                .map(|line| line.as_str().unwrap().to_owned())
                .collect()
        };
        let content = lines.join("\n") + "\n";
        let path = dir.join(name);
        if file["gz"].as_bool().unwrap_or(false) {
            let handle = std::fs::File::create(&path).unwrap();
            let mut encoder = flate2::write::GzEncoder::new(handle, flate2::Compression::default());
            encoder.write_all(content.as_bytes()).unwrap();
            encoder.finish().unwrap();
        } else {
            std::fs::write(&path, content).unwrap();
        }
    }
}

fn certificate() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(["localhost".to_owned()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key)
    .unwrap();
    (Arc::new(config), cert)
}

async fn start(
    log_file: PathBuf,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let mut hooks = AdminHooks::fixed(
        HealthInputs {
            closing: false,
            namespaces_ready: true,
            applied_generation: 1,
            config_checksum: 7,
        },
        "# metrics\n".to_owned(),
        DataplaneStatus::default(),
        Arc::new(control_admin::config::MemoryConfigAdmin::default()),
    );
    hooks.log_file = Some(log_file);
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

fn client_config(cert: CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

async fn channel(
    address: SocketAddr,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> tonic::transport::Channel {
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{address}")).unwrap();
    match tls {
        None => endpoint.connect().await.unwrap(),
        Some(config) => {
            let connector = tokio_rustls::TlsConnector::from(config);
            let service = tower::service_fn(move |_uri: http::Uri| {
                let connector = connector.clone();
                async move {
                    let stream = TcpStream::connect(address).await?;
                    let stream = connector
                        .connect(ServerName::try_from("localhost").unwrap(), stream)
                        .await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            });
            endpoint.connect_with_connector(service).await.unwrap()
        }
    }
}

fn level_number(name: &str) -> i32 {
    LogLevel::from_str_name(name).map_or(0, |level| level as i32)
}

fn code_name(status: &tonic::Status) -> String {
    match status.code() {
        tonic::Code::Ok => "OK".to_owned(),
        tonic::Code::Cancelled => "Canceled".to_owned(),
        tonic::Code::Unknown => "Unknown".to_owned(),
        tonic::Code::InvalidArgument => "InvalidArgument".to_owned(),
        tonic::Code::Unimplemented => "Unimplemented".to_owned(),
        tonic::Code::Internal => "Internal".to_owned(),
        tonic::Code::Unavailable => "Unavailable".to_owned(),
        other => format!("{other:?}"),
    }
}

async fn run_side(
    address: SocketAddr,
    tls: Option<Arc<rustls::ClientConfig>>,
    script: &Value,
    tls_side: bool,
) -> Value {
    let mut searches = Vec::new();
    for search in script["searches"].as_array().unwrap() {
        let request = SearchLogRequest {
            start_time: search["start_time"].as_i64().unwrap_or(0),
            end_time: search["end_time"].as_i64().unwrap_or(0),
            levels: search["levels"]
                .as_array()
                .map(|levels| {
                    levels
                        .iter()
                        .map(|level| level_number(level.as_str().unwrap()))
                        .collect()
                })
                .unwrap_or_default(),
            patterns: search["patterns"]
                .as_array()
                .map(|patterns| {
                    patterns
                        .iter()
                        .map(|pattern| pattern.as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default(),
            target: 0,
        };
        let cancel_after = search["cancel_after_packets"].as_u64().unwrap_or(0) as usize;
        let mut client = tonic::client::Grpc::new(channel(address, tls.clone()).await);
        client.ready().await.unwrap();
        let mut packets: Vec<Value> = Vec::new();
        let code = match client
            .server_streaming(
                tonic::Request::new(request),
                PathAndQuery::from_static("/diagnosticspb.Diagnostics/search_log"),
                ProstCodec::<SearchLogRequest, SearchLogResponse>::default(),
            )
            .await
        {
            Err(status) => code_name(&status),
            Ok(response) => {
                let mut stream = response.into_inner();
                loop {
                    match stream.message().await {
                        Ok(Some(response)) => {
                            packets.push(json!(
                                response
                                    .messages
                                    .iter()
                                    .map(|message| json!({
                                        "time": message.time,
                                        "level": message.level,
                                        "message": message.message,
                                    }))
                                    .collect::<Vec<_>>()
                            ));
                            if cancel_after > 0 && packets.len() >= cancel_after {
                                // Dropping the stream cancels the call; the
                                // client observes its own cancellation.
                                drop(stream);
                                break "Canceled".to_owned();
                            }
                        }
                        Ok(None) => break "OK".to_owned(),
                        Err(status) => break code_name(&status),
                    }
                }
            }
        };
        searches.push(json!({"name": search["name"], "packets": packets, "code": code}));
    }
    // The full inventory on the plaintext side; the TLS side re-checks the
    // types the script lists.
    let mut names: Vec<String> = script["server_info_types"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    names.sort();
    if tls_side {
        names = script["server_info_tls_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect();
    }
    let mut server_info = serde_json::Map::new();
    for name in names {
        let tp = script["server_info_types"][&name].as_i64().unwrap() as i32;
        let mut client = tonic::client::Grpc::new(channel(address, tls.clone()).await);
        client.ready().await.unwrap();
        let (code, items) = match client
            .unary(
                tonic::Request::new(ServerInfoRequest { tp }),
                PathAndQuery::from_static("/diagnosticspb.Diagnostics/server_info"),
                ProstCodec::<ServerInfoRequest, ServerInfoResponse>::default(),
            )
            .await
        {
            Ok(response) => (
                "OK".to_owned(),
                response
                    .into_inner()
                    .items
                    .iter()
                    .map(|item| {
                        json!({
                            "tp": item.tp,
                            "name": item.name,
                            "pairs": item.pairs.iter().map(|pair| json!({"key": pair.key, "value": pair.value})).collect::<Vec<_>>(),
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            Err(status) => (code_name(&status), Vec::new()),
        };
        server_info.insert(name, json!({"code": code, "items": items}));
    }
    let path = script["http1_probe_path"].as_str().unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut response = Vec::new();
    match &tls {
        None => {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let _ = stream.read_to_end(&mut response).await;
        }
        Some(config) => {
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(config));
            let stream = TcpStream::connect(address).await.unwrap();
            let mut stream = connector
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let _ = stream.read_to_end(&mut response).await;
        }
    }
    let status_line = String::from_utf8_lossy(&response);
    let http1_status: u64 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    json!({
        "searches": searches,
        "server_info": Value::Object(server_info),
        "http1_grpc_status": http1_status,
    })
}

/// Go `runtime.GOOS` for this build.
fn go_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

#[tokio::main]
async fn main() {
    let script: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("CPDIAG_SCRIPT").expect("CPDIAG_SCRIPT")).unwrap(),
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("tiproxy-cpdiag-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_fixture(&dir, script["files"].as_array().unwrap());
    let log_file = dir.join("tiproxy.log");

    let (plain_address, plain_shutdown, plain_task) = start(log_file.clone(), None).await;
    let plain = run_side(plain_address, None, &script, false).await;
    let _ = plain_shutdown.send(true);
    let _ = plain_task.await;

    let (server_tls, cert) = certificate();
    let (tls_address, tls_shutdown, tls_task) = start(log_file, Some(server_tls)).await;
    let tls = run_side(tls_address, Some(client_config(cert)), &script, true).await;
    let _ = tls_shutdown.send(true);
    let _ = tls_task.await;
    let _ = std::fs::remove_dir_all(&dir);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"goos": go_os(), "plain": plain, "tls": tls}))
            .unwrap()
    );
}
