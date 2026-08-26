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

//! Cross-language session test against a fake peer built from the Go codec.

use std::error::Error;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use control_proto::control_transport::{
    ClientConfig, ConnectionState, ControlClient, TransportError,
};
use control_proto::v1::control_envelope::Body;
use control_proto::v1::{ControlEnvelope, Hello, Priority, Role, RouteResult};
use control_proto::{CONTROL_PROTOCOL_V1, DEFAULT_MAX_FRAME_BYTES};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn wait(&mut self) -> Result<std::process::ExitStatus, std::io::Error> {
        let Some(mut child) = self.0.take() else {
            return Err(std::io::Error::other("Go fake peer already consumed"));
        };
        child.wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn unique_directory() -> Result<PathBuf, std::io::Error> {
    let identifier = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "tiproxy-go-peer-{}-{identifier}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn build_go_peer(repository: &Path, binary: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new("go")
        .current_dir(repository)
        .args([
            "build",
            "-o",
            binary.to_str().ok_or("non-UTF8 fake peer binary path")?,
            "./pkg/controlbridge/transport/testfixture/go-fake-server",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "build Go fake peer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_client_exchanges_messages_with_go_codec_peer() -> Result<(), Box<dyn Error>> {
    let directory = unique_directory()?;
    let socket_path = directory.join("control.sock");
    let binary = directory.join("go-fake-server");
    build_go_peer(&repository_root(), &binary)?;
    let child = Command::new(&binary)
        .args([
            "--socket",
            socket_path.to_str().ok_or("non-UTF8 control socket path")?,
        ])
        .spawn()?;
    let mut child = ChildGuard(Some(child));

    let metadata = timeout(Duration::from_secs(2), async {
        loop {
            match fs::symlink_metadata(&socket_path) {
                Ok(metadata)
                    if metadata.file_type().is_socket() && metadata.mode() & 0o777 == 0o600 =>
                {
                    return Ok::<_, std::io::Error>(metadata);
                }
                Ok(_) | Err(_) => sleep(Duration::from_millis(5)).await,
            }
        }
    })
    .await??;
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id: "rust-cross-language-client".to_owned(),
        supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
        capabilities: vec![2, 3, 7],
        max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        ..Default::default()
    };
    let mut config = ClientConfig::with_defaults(socket_path.clone(), metadata.uid(), hello);
    config.required_capabilities = vec![3];
    config.heartbeat_interval = Duration::from_millis(50);
    config.peer_timeout = Duration::from_secs(1);
    let client = Arc::new(ControlClient::new(config)?);
    let mut state = client.subscribe_state();
    let (message_tx, mut message_rx) = mpsc::unbounded_channel();
    let run_client = Arc::clone(&client);
    let client_task = tokio::spawn(async move {
        let handler = move |envelope| {
            message_tx
                .send(envelope)
                .map_err(|_| TransportError::Protocol("cross-language receiver dropped".to_owned()))
        };
        run_client.run(&handler).await
    });

    timeout(Duration::from_secs(2), async {
        loop {
            if matches!(
                *state.borrow(),
                ConnectionState::Connected { epoch: 101, .. }
            ) {
                return Ok::<(), TransportError>(());
            }
            state.changed().await.map_err(|_| TransportError::Closed)?;
        }
    })
    .await??;
    client
        .send(ControlEnvelope {
            priority: Priority::Critical as i32,
            body: Some(Body::RouteResult(RouteResult {
                assignment_id: "assignment-101".to_owned(),
                connected: true,
                ..Default::default()
            })),
            ..Default::default()
        })
        .await?;
    let envelope = timeout(Duration::from_secs(2), message_rx.recv())
        .await?
        .ok_or("Go peer closed before sending heartbeat")?;
    let Some(Body::Heartbeat(heartbeat)) = envelope.body else {
        return Err("expected Go heartbeat".into());
    };
    assert_eq!(heartbeat.monotonic_millis, 4242);

    client.shutdown();
    timeout(Duration::from_secs(1), client_task).await???;
    let status = child.wait()?;
    assert!(status.success());
    let _ = fs::remove_file(binary);
    let _ = fs::remove_file(socket_path);
    fs::remove_dir(directory)?;
    Ok(())
}
