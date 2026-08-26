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

//! Control-runtime composition tests: the single entry owns the
//! transport, dispatch, and snapshot tasks, and shutdown propagates
//! through the whole chain to a clean join.

use std::time::Duration;

use control_proto::control_transport::ClientConfig;
use control_proto::snapshot::SnapshotStore;
use control_proto::v1::{Hello, Role};
use dataplane::control_runtime::{ControlRuntimeConfig, spawn_control_runtime};

fn runtime_config(socket: std::path::PathBuf) -> ControlRuntimeConfig {
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id: "runtime-test".to_owned(),
        supported_versions: vec![1],
        capabilities: vec![1, 2, 3],
        max_frame_bytes: 1024 * 1024,
        ..Hello::default()
    };
    let mut client = ClientConfig::with_defaults(socket, 0, hello);
    client.reconnect_base = Duration::from_millis(10);
    client.reconnect_cap = Duration::from_millis(20);
    ControlRuntimeConfig {
        client,
        tick_interval: Duration::from_millis(50),
        snapshot_queue: 4,
    }
}

/// The runtime owns its whole task chain: with no Go socket present it
/// keeps reconnecting, and `shutdown` cascades — the transport task
/// returns, the forwarder drops, the dispatch inbound closes, the
/// snapshot channel closes — so `join` completes cleanly.
#[tokio::test]
async fn runtime_shutdown_cascades_to_clean_join() {
    let directory = std::env::temp_dir().join(format!("tiproxy-rt-{}", std::process::id()));
    let socket = directory.join("missing-control.sock");
    let Ok(store) = SnapshotStore::new(Vec::new()) else {
        unreachable!("empty allowlist store constructs")
    };
    let Ok(runtime) = spawn_control_runtime(runtime_config(socket), store, |_snapshot: &_| Ok(()))
    else {
        unreachable!("valid configuration spawns")
    };
    let handle = runtime.handle();
    // The session surface is live even while disconnected.
    assert!(
        handle
            .notify(dataplane::control_dispatch::DispatchNotice::AppliedGeneration(7))
            .await,
        "the dispatch task accepts notices"
    );
    runtime.shutdown();
    let joined = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
    let Ok(Ok(())) = joined else {
        unreachable!("shutdown cascades to a clean join: {joined:?}")
    };
}
