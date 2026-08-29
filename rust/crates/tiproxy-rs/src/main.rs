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

mod health;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_proto::CONTROL_PROTOCOL_V1;
use control_proto::control_transport::ClientConfig;
use control_proto::control_transport::ControlClient;
use control_proto::snapshot::SnapshotStore;
use control_proto::v1::{ControlCapability, Hello, Role};
use dataplane::control_runtime::spawn_control_runtime_with_client;
use dataplane::session::SessionLoopConfig;
use dataplane::session_engine::EngineSessionOwner;
use dataplane::{
    BoundSessionHandler, DEFAULT_OBSERVATION_CAPACITY, DataplaneServingHandle,
    DataplaneSnapshotConsumer, DispatchConnectionHandler, MetricsRecorder, SystemMemoryProbe,
    spawn_metrics_exporter,
};
use tokio::sync::watch;

const VERSION: &str = env!("TIPROXY_BUILD_VERSION");
const COMMIT: &str = env!("TIPROXY_BUILD_COMMIT");
const BUILD_TIME: &str = env!("TIPROXY_BUILD_TIME");

const CONTROL_SOCKET_ENV: &str = "TIPROXY_CONTROL_SOCKET";
const CONTROL_UID_ENV: &str = "TIPROXY_CONTROL_UID";
const TLS_ROOTS_ENV: &str = "TIPROXY_TLS_ROOTS";

/// Upper bound for `--drain-grace-seconds` (30 days, the drain
/// subsystem's shared deadline cap): far above any real grace and small
/// enough that deadline arithmetic on `Instant` can never overflow.
const MAX_DRAIN_GRACE_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, PartialEq, Eq)]
struct Options {
    control_socket: PathBuf,
    control_uid: u32,
    tls_roots: Vec<PathBuf>,
    drain_grace: Duration,
    health_port: u16,
}

enum Command {
    Run(Options),
    Version,
    Help,
    IntegrationCapabilities,
}

/// The integration harness's capability contract (DPL-07): only what
/// this binary truthfully provides today. TLS (frontend `SSLRequest` +
/// backend TLS, WIRE-activation A1) and the PROXY v2 backend preamble
/// (WIRE-activation B) are wired, so `tls` and `proxy-v2` are advertised;
/// compression is still not wired, so `zlib`/`zstd` remain absent and the
/// topology preflight admits plain, tls, and proxy.
const INTEGRATION_CAPABILITIES: &str =
    "control-bridge-v1,mysql-listener,health-endpoint,graceful-shutdown,tls,proxy-v2";

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
        Command::IntegrationCapabilities => {
            println!("{INTEGRATION_CAPABILITIES}");
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

    // DPL-04: the real session owner replaces DPL-03's parked handler.
    // Sessions share the control client with the runtime; the drain and
    // session-shutdown watches drive the coordinated local shutdown.
    let shared_client = Arc::new(ControlClient::new(client).map_err(|error| error.to_string())?);
    let (drain_tx, drain_rx) = watch::channel(false);
    let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
    let loop_config = session_loop_config(options.drain_grace);
    let (metrics, observations) = MetricsRecorder::channel(DEFAULT_OBSERVATION_CAPACITY);
    let owner: Arc<dyn BoundSessionHandler> = Arc::new(
        EngineSessionOwner::new(
            Arc::clone(&shared_client),
            "default",
            session_shutdown_rx,
            drain_rx,
            loop_config,
        )
        .with_metrics(metrics.clone()),
    );
    let (connection_handler, installer) = DispatchConnectionHandler::new("default", owner);
    let (consumer, serving) = DataplaneSnapshotConsumer::new(
        Arc::new(SystemMemoryProbe::new()),
        Arc::new(connection_handler),
    );
    // Forced shutdown lets each session owner finish its bounded
    // terminal work (close notice + engine join) before the abort
    // backstop fires.
    let consumer =
        consumer.with_force_join_grace(loop_config.cleanup_deadline + Duration::from_secs(1));
    let runtime = spawn_control_runtime_with_client(
        Arc::clone(&shared_client),
        Duration::from_millis(100),
        8,
        store,
        consumer,
    );
    if !installer.install(runtime.handle()) {
        runtime.shutdown();
        return Err("install control dispatch handle exactly once".to_owned());
    }
    let metrics_exporter = spawn_metrics_exporter(
        Arc::clone(&shared_client),
        serving.clone(),
        runtime.stats(),
        &metrics,
        observations,
        Duration::from_secs(1),
    );

    // Readiness probe for the integration topology: answers 503 until
    // the first applied generation, 200 after. Bound before serving so
    // a bad port fails fast; the task is owned and aborted at exit.
    let health_task = spawn_health(options.health_port, serving.clone()).await?;

    // Coordinated shutdown on SIGTERM/SIGINT:
    // stop-accept → graceful drain (per-session force at the loop's
    // drain deadline) → absolute grace deadline force → join everything.
    {
        let serving = serving.clone();
        let runtime_client = Arc::clone(&shared_client);
        let grace = options.drain_grace;
        tokio::spawn(async move {
            wait_for_termination_signal().await;
            serving.stop_accepting().await;
            drain_tx.send_replace(true);
            tokio::time::sleep(grace).await;
            session_shutdown_tx.send_replace(true);
            let _ = serving.shutdown().await;
            runtime_client.shutdown();
        });
    }

    let control_result = runtime.join().await;
    if let Some(task) = health_task {
        task.abort();
        let _ = task.await;
    }
    let serving_result = serving.shutdown().await;
    metrics_exporter.shutdown();
    metrics_exporter.join().await;
    match (control_result, serving_result) {
        (Err(error), _) => Err(error.to_string()),
        (Ok(()), Err(error)) => Err(format!("shut down SQL listeners: {error}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Binds the optional integration readiness endpoint before its serving task
/// starts, so a port conflict fails the composition synchronously.
async fn spawn_health(
    port: u16,
    serving: DataplaneServingHandle,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    if port == 0 {
        return Ok(None);
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        // The operator diagnostic names the exact port: a bind conflict
        // must be traceable to the address that caused it.
        .map_err(|error| format!("bind health endpoint 127.0.0.1:{port}: {error}"))?;
    Ok(Some(tokio::spawn(health::serve(listener, serving))))
}

/// ONE grace lineage: the CLI's validated drain grace IS the
/// per-session FSM drain deadline, so the coordinator's absolute grace
/// and the loop's own force timer never diverge.
fn session_loop_config(drain_grace: Duration) -> SessionLoopConfig {
    SessionLoopConfig {
        drain_deadline: drain_grace,
        ..SessionLoopConfig::default()
    }
}

/// Resolves on SIGTERM or SIGINT.
async fn wait_for_termination_signal() {
    let Ok(mut sigterm) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return std::future::pending::<()>().await;
    };
    let Ok(mut sigint) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        return std::future::pending::<()>().await;
    };
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
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
    let mut drain_grace = Duration::from_secs(30);
    let mut health_port: u16 = 0;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            "--integration-capabilities" => return Ok(Command::IntegrationCapabilities),
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
            "--health-port" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--health-port requires a port".to_owned())?;
                health_port = value
                    .parse()
                    .map_err(|_| format!("health port must be a u16, got {value:?}"))?;
            }
            "--drain-grace-seconds" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--drain-grace-seconds requires a number".to_owned())?;
                let seconds: u64 = value
                    .parse()
                    .map_err(|_| format!("drain grace must be a u64, got {value:?}"))?;
                if seconds > MAX_DRAIN_GRACE_SECONDS {
                    return Err(format!(
                        "--drain-grace-seconds must be at most {MAX_DRAIN_GRACE_SECONDS} \
                         (30 days), got {seconds}"
                    ));
                }
                drain_grace = Duration::from_secs(seconds);
            }
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
        drain_grace,
        health_port,
    }))
}

fn parse_uid(value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("control uid must be a uint32, got {value:?}"))
}

fn usage() -> &'static str {
    "Usage: tiproxy-rs --control-socket <absolute-path> --control-uid <uid> \
     [--tls-root <absolute-path>]... [--drain-grace-seconds <n>] [--health-port <n>]\n\
     Environment: TIPROXY_CONTROL_SOCKET, TIPROXY_CONTROL_UID, TIPROXY_TLS_ROOTS"
}

fn version_output() -> String {
    format!("tiproxy-rs {VERSION} (commit {COMMIT}, built {BUILD_TIME})")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        Command, INTEGRATION_CAPABILITIES, MAX_DRAIN_GRACE_SECONDS, Options, parse_options,
        session_loop_config, version_output,
    };

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
                drain_grace: std::time::Duration::from_secs(30),
                health_port: 0,
            }
        );
    }

    #[test]
    fn drain_grace_is_the_session_drain_deadline() {
        let command = parse_options([
            "--control-socket".to_owned(),
            "/tmp/control.sock".to_owned(),
            "--control-uid".to_owned(),
            "42".to_owned(),
            "--drain-grace-seconds".to_owned(),
            "45".to_owned(),
        ]);
        let Ok(Command::Run(options)) = command else {
            unreachable!("valid operational arguments")
        };
        assert_eq!(options.drain_grace, std::time::Duration::from_secs(45));
        assert_eq!(
            session_loop_config(options.drain_grace).drain_deadline,
            std::time::Duration::from_secs(45),
            "one lineage: the CLI grace is the per-session FSM deadline"
        );
    }

    #[test]
    fn integration_capabilities_are_the_honest_contract() {
        let Ok(Command::IntegrationCapabilities) =
            parse_options(["--integration-capabilities".to_owned()])
        else {
            unreachable!("the capability probe needs no other arguments")
        };
        assert_eq!(
            INTEGRATION_CAPABILITIES,
            "control-bridge-v1,mysql-listener,health-endpoint,graceful-shutdown,tls,proxy-v2",
            "only what the binary truthfully provides: the plain slice plus wired TLS and PROXY v2"
        );
        for wired in ["tls", "proxy-v2"] {
            assert!(
                INTEGRATION_CAPABILITIES.contains(wired),
                "{wired:?} is wired (WIRE-activation A1/B), so it must be advertised"
            );
        }
        for absent in ["zlib", "zstd"] {
            assert!(
                !INTEGRATION_CAPABILITIES.contains(absent),
                "unimplemented variant capability {absent:?} must not be advertised"
            );
        }
    }

    #[test]
    fn parses_health_port() {
        let command = parse_options([
            "--control-socket".to_owned(),
            "/tmp/control.sock".to_owned(),
            "--control-uid".to_owned(),
            "42".to_owned(),
            "--health-port".to_owned(),
            "8081".to_owned(),
        ]);
        let Ok(Command::Run(options)) = command else {
            unreachable!("valid operational arguments")
        };
        assert_eq!(options.health_port, 8081);
        assert!(
            parse_options([
                "--control-socket".to_owned(),
                "/tmp/control.sock".to_owned(),
                "--health-port".to_owned(),
                "not-a-port".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_over_bound_drain_grace() {
        let Err(error) = parse_options([
            "--control-socket".to_owned(),
            "/tmp/control.sock".to_owned(),
            "--control-uid".to_owned(),
            "42".to_owned(),
            "--drain-grace-seconds".to_owned(),
            (MAX_DRAIN_GRACE_SECONDS + 1).to_string(),
        ]) else {
            unreachable!("an over-bound grace must be rejected")
        };
        assert!(error.contains("at most"), "the bound is named: {error}");
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
