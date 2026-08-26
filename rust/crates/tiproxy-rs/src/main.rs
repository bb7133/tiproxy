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

//! `TiProxy` Rust dataplane executable.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_proto::CONTROL_PROTOCOL_V1;
use control_proto::control_transport::ClientConfig;
use control_proto::snapshot::SnapshotStore;
use control_proto::v1::{ControlCapability, Hello, Role};
use dataplane::control_runtime::{ControlRuntimeConfig, spawn_control_runtime};
use dataplane::{
    BoundSessionHandler, DataplaneSnapshotConsumer, DispatchConnectionHandler, SystemMemoryProbe,
};

const VERSION: &str = env!("TIPROXY_BUILD_VERSION");
const COMMIT: &str = env!("TIPROXY_BUILD_COMMIT");
const BUILD_TIME: &str = env!("TIPROXY_BUILD_TIME");

const CONTROL_SOCKET_ENV: &str = "TIPROXY_CONTROL_SOCKET";
const CONTROL_UID_ENV: &str = "TIPROXY_CONTROL_UID";
const TLS_ROOTS_ENV: &str = "TIPROXY_TLS_ROOTS";

#[derive(Debug, PartialEq, Eq)]
struct Options {
    control_socket: PathBuf,
    control_uid: u32,
    tls_roots: Vec<PathBuf>,
}

enum Command {
    Run(Options),
    Version,
    Help,
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = match parse_options(env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("{error}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Version => {
            println!("{}", version_output());
            ExitCode::SUCCESS
        }
        Command::Help => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Command::Run(options) => match run(options).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("tiproxy-rs stopped: {error}");
                ExitCode::from(1)
            }
        },
    }
}

async fn run(options: Options) -> Result<(), String> {
    let capabilities = vec![
        ControlCapability::PerConnectionClose as u64,
        ControlCapability::ReconcileConnections as u64,
        ControlCapability::ReconcileSessionRehydration as u64,
    ];
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id: format!("tiproxy-rs-{}", std::process::id()),
        process_started_unix_millis: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
        capabilities: capabilities.clone(),
        max_frame_bytes: control_proto::DEFAULT_MAX_FRAME_BYTES,
        build_version: VERSION.to_owned(),
        build_commit: COMMIT.to_owned(),
    };
    let mut client =
        ClientConfig::with_defaults(options.control_socket, options.control_uid, hello);
    client.required_capabilities = capabilities;
    let store = SnapshotStore::new(options.tls_roots)
        .map_err(|error| format!("create snapshot store: {error}"))?;

    // DPL-03 installs the typed live-session control seam. DPL-04 replaces
    // this parked owner with the concrete SessionLoop/effect composition;
    // until then admitted sockets stay owned and cancellable instead of
    // running an incomplete forwarding path.
    let parked: Arc<dyn BoundSessionHandler> = Arc::new(|_connection, _binding| async move {
        std::future::pending::<()>().await;
    });
    let (connection_handler, installer) = DispatchConnectionHandler::new("default", parked);
    let (consumer, serving) = DataplaneSnapshotConsumer::new(
        Arc::new(SystemMemoryProbe::new()),
        Arc::new(connection_handler),
    );
    let runtime = spawn_control_runtime(
        ControlRuntimeConfig {
            client,
            tick_interval: Duration::from_millis(100),
            snapshot_queue: 8,
        },
        store,
        consumer,
    )
    .map_err(|error| error.to_string())?;
    if !installer.install(runtime.handle()) {
        runtime.shutdown();
        return Err("install control dispatch handle exactly once".to_owned());
    }

    let control_result = runtime.join().await;
    let serving_result = serving.shutdown().await;
    match (control_result, serving_result) {
        (Err(error), _) => Err(error.to_string()),
        (Ok(()), Err(error)) => Err(format!("shut down SQL listeners: {error}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn parse_options(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let mut socket = env::var_os(CONTROL_SOCKET_ENV).map(PathBuf::from);
    let mut uid = env::var(CONTROL_UID_ENV)
        .ok()
        .map(|value| parse_uid(&value))
        .transpose()?;
    let mut tls_roots: Vec<PathBuf> = env::var_os(TLS_ROOTS_ENV)
        .map(|value| env::split_paths(&value).collect())
        .unwrap_or_default();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            "--control-socket" => {
                socket =
                    Some(PathBuf::from(arguments.next().ok_or_else(|| {
                        "--control-socket requires a path".to_owned()
                    })?));
            }
            "--control-uid" => {
                uid = Some(parse_uid(
                    &arguments
                        .next()
                        .ok_or_else(|| "--control-uid requires a uid".to_owned())?,
                )?);
            }
            "--tls-root" => tls_roots.push(PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| "--tls-root requires a path".to_owned())?,
            )),
            _ => return Err(format!("unknown argument {argument:?}")),
        }
    }
    let control_socket =
        socket.ok_or_else(|| format!("--control-socket or {CONTROL_SOCKET_ENV} is required"))?;
    if !control_socket.is_absolute() {
        return Err("control socket path must be absolute".to_owned());
    }
    if tls_roots.iter().any(|root| !root.is_absolute()) {
        return Err("TLS allowlist roots must be absolute".to_owned());
    }
    Ok(Command::Run(Options {
        control_socket,
        control_uid: uid
            .ok_or_else(|| format!("--control-uid or {CONTROL_UID_ENV} is required"))?,
        tls_roots,
    }))
}

fn parse_uid(value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("control uid must be a uint32, got {value:?}"))
}

fn usage() -> &'static str {
    "Usage: tiproxy-rs --control-socket <absolute-path> --control-uid <uid> [--tls-root <absolute-path>]...\n\
     Environment: TIPROXY_CONTROL_SOCKET, TIPROXY_CONTROL_UID, TIPROXY_TLS_ROOTS"
}

fn version_output() -> String {
    format!("tiproxy-rs {VERSION} (commit {COMMIT}, built {BUILD_TIME})")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Command, Options, parse_options, version_output};

    #[test]
    fn version_output_labels_all_build_metadata() {
        let output = version_output();
        assert!(output.starts_with("tiproxy-rs "));
        assert!(output.contains(" (commit "));
        assert!(output.contains(", built "));
    }

    #[test]
    fn parses_operational_cli() {
        let command = parse_options([
            "--control-socket".to_owned(),
            "/tmp/control.sock".to_owned(),
            "--control-uid".to_owned(),
            "42".to_owned(),
            "--tls-root".to_owned(),
            "/etc/tiproxy/tls".to_owned(),
        ]);
        let Ok(Command::Run(options)) = command else {
            unreachable!("valid operational arguments")
        };
        assert_eq!(
            options,
            Options {
                control_socket: PathBuf::from("/tmp/control.sock"),
                control_uid: 42,
                tls_roots: vec![PathBuf::from("/etc/tiproxy/tls")],
            }
        );
    }

    #[test]
    fn rejects_relative_or_incomplete_cli() {
        assert!(
            parse_options([
                "--control-socket".to_owned(),
                "control.sock".to_owned(),
                "--control-uid".to_owned(),
                "42".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_options([
                "--control-socket".to_owned(),
                "/tmp/control.sock".to_owned(),
            ])
            .is_err()
        );
    }
}
