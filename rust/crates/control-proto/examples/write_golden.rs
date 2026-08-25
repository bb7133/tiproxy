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

//! Writes the canonical Rust-to-Go protobuf compatibility fixture.

use std::fs;
use std::path::PathBuf;

use control_proto::v1::control_envelope::Body;
use control_proto::v1::{
    BackendSnapshot, ConfigSnapshot, ControlCapability, ControlEnvelope, KeepalivePolicy, Listener,
    NamespaceSnapshot, Priority, ProxyProtocolMode, ReconcileConnection, ReconcileRequest,
    StateSnapshot,
};
use control_proto::{DEFAULT_MAX_FRAME_BYTES, encode_frame};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let envelope = ControlEnvelope {
        protocol_version: 1,
        control_epoch: 52,
        generation: 11,
        request_id: 101,
        priority: Priority::Control.into(),
        sent_unix_millis: 1_800_000_001_000,
        required_capabilities: vec![2, 8, 64],
        body: Some(Body::StateSnapshot(StateSnapshot {
            config: Some(ConfigSnapshot {
                max_connections: 10_000,
                high_memory_reject_threshold: 0.9,
                connection_buffer_bytes: 32_768,
                frontend_keepalive: Some(KeepalivePolicy {
                    enabled: true,
                    idle_millis: 60_000,
                    probe_count: 5,
                    interval_millis: 3_000,
                    user_timeout_millis: 15_000,
                }),
                healthy_backend_keepalive: None,
                unhealthy_backend_keepalive: None,
                proxy_protocol: ProxyProtocolMode::V2.into(),
                require_backend_tls: true,
                graceful_wait_millis: 5_000,
                graceful_close_millis: 15_000,
                listeners: vec![Listener {
                    address: "127.0.0.1".into(),
                    port: 6000,
                    name: "sql-primary".into(),
                }],
                public_cidrs: vec!["203.0.113.0/24".into()],
                advertised_capability: u32::MAX,
                server_version: "8.5.1-TiProxy".into(),
                frontend_tls: None,
                backend_tls: None,
                traffic_replay_enabled: false,
            }),
            backends: vec![BackendSnapshot {
                backend_id: "backend-1".into(),
                address: "127.0.0.1:4000".into(),
                cluster_name: "default".into(),
                keyspace: "ks-1".into(),
                healthy: true,
                local: true,
                draining: false,
                cidrs: vec!["127.0.0.0/8".into()],
                labels: [("zone".into(), "local".into())].into(),
            }],
            namespaces: vec![NamespaceSnapshot {
                name: "default".into(),
                users: vec!["root".into()],
                backend_cluster: "default".into(),
            }],
        })),
    };
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    write_frame(&repository, "rust-snapshot.frame", &envelope)?;
    write_frame(
        &repository,
        "rust-reconcile.frame",
        &ControlEnvelope {
            protocol_version: 1,
            control_epoch: 53,
            request_id: 102,
            priority: Priority::Critical.into(),
            required_capabilities: vec![ControlCapability::ReconcileConnections as u64],
            body: Some(Body::ReconcileRequest(ReconcileRequest {
                known_generation: 11,
                last_connection_event_sequence: 21,
                last_metrics_sequence: 22,
                last_metering_sequence: 23,
                connections: vec![ReconcileConnection {
                    connection_id: 77,
                    backend_id: "backend-1".into(),
                    namespace: "default".into(),
                    redirect_pending: true,
                }],
            })),
            ..Default::default()
        },
    )?;
    Ok(())
}

fn write_frame(
    repository: &std::path::Path,
    name: &str,
    envelope: &ControlEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame = encode_frame(envelope, DEFAULT_MAX_FRAME_BYTES)?;
    let path = repository.join("proto/dataplane/v1/testdata").join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &frame)?;
    println!("wrote {} ({} bytes)", path.display(), frame.len());
    Ok(())
}
