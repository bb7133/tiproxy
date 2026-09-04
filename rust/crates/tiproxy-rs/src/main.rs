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

mod config_composition;
mod health;
mod topology_composition;

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config_composition::{
    ConfigServingAdapter, RustConfigComposer, ServingCandidateValidator, control_config,
};
use control_config::{
    ConfigModule, ConfigModuleHandle, ConfigModuleOptions, ConfigNamespaceSource,
    TopologyRuntimeIdentity,
};
use control_etcd::ElectionConfig;
use control_external::{EtcdClientConfig, EtcdTlsConfig};
use control_plane::{
    ConfigSource, ControlModuleSet, ControlRuntime as InProcessControlRuntime, JsonStderrSink,
    LifecyclePhase, OwnershipRegistry, ShutdownReason,
};
use control_proto::CONTROL_PROTOCOL_V1;
use control_proto::control_transport::ClientConfig;
use control_proto::control_transport::ControlClient;
use control_proto::snapshot::SnapshotStore;
use control_proto::v1::{ControlCapability, Hello, Role};
use control_topology::{InterfaceAdvertiseResolver, TopologyModule};
use dataplane::control_runtime::spawn_control_runtime_with_client_and_handler;
use dataplane::metering::{MeteringSourceRegistry, run_metering_sampler};
use dataplane::session::SessionLoopConfig;
use dataplane::session_engine::EngineSessionOwner;
use dataplane::{
    BoundSessionHandler, ControlCommandHandler, DEFAULT_OBSERVATION_CAPACITY,
    DataplaneServingHandle, DataplaneSnapshotConsumer, DispatchConnectionHandler, MeteringLedger,
    MetricsRecorder, ServerError, SystemMemoryProbe, spawn_metrics_exporter,
};
use tokio::sync::watch;
use topology_composition::{
    ArtifactClusterFactory, CompositeCandidateValidator, TopologyCandidateValidator,
    interface_advertise_candidates,
};

const VERSION: &str = env!("TIPROXY_BUILD_VERSION");
const COMMIT: &str = env!("TIPROXY_BUILD_COMMIT");
const BUILD_TIME: &str = env!("TIPROXY_BUILD_TIME");

const CONTROL_SOCKET_ENV: &str = "TIPROXY_CONTROL_SOCKET";
const CONTROL_UID_ENV: &str = "TIPROXY_CONTROL_UID";
const TLS_ROOTS_ENV: &str = "TIPROXY_TLS_ROOTS";
const CONFIG_FILE_ENV: &str = "TIPROXY_CONFIG";

/// Upper bound for `--drain-grace-seconds` (30 days, the drain
/// subsystem's shared deadline cap): far above any real grace and small
/// enough that deadline arithmetic on `Instant` can never overflow.
const MAX_DRAIN_GRACE_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, PartialEq, Eq)]
struct Options {
    config_file: PathBuf,
    control_socket: PathBuf,
    control_uid: u32,
    tls_roots: Vec<PathBuf>,
    drain_grace: Option<Duration>,
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
/// backend TLS, WIRE-activation A1), the PROXY v2 backend preamble
/// (WIRE-activation B), and `MySQL` compression (zlib + zstd, WIRE-activation
/// C) are all wired, so `tls`, `proxy-v2`, `zlib`, and `zstd` are advertised
/// and the topology preflight admits plain, tls, proxy, and compressed
/// variants.
const INTEGRATION_CAPABILITIES: &str = "in-process-control-runtime,control-bridge-v1,mysql-listener,health-endpoint,graceful-shutdown,tls,proxy-v2,zlib,zstd";

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

// This is the executable's composition root: keeping the startup resources,
// three-way supervisor, and reverse-order shutdown visible in one function
// makes the fail-closed ownership order auditable.
#[allow(clippy::too_many_lines)]
async fn run(options: Options) -> Result<(), String> {
    // CP-001 owns the process-local lifecycle/config/TLS/log/metrics
    // foundation. The legacy protobuf client below is an outer adapter for
    // responsibilities that still live in Go; its messages never become this
    // runtime's domain model.
    let process_started_unix_millis: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    let process_id = format!("tiproxy-rs-{}", std::process::id());
    let config_owner = load_config_owner(&options, &process_id)?;
    let initial_config = control_config(
        config_owner.handle.source().current().as_ref(),
        options.health_port,
        &config_owner.tls_roots,
        options.drain_grace,
    )?;
    let in_process_registry = OwnershipRegistry::new();
    let in_process = Arc::new(
        InProcessControlRuntime::claim_process(
            &in_process_registry,
            process_id.clone(),
            initial_config,
            Arc::new(JsonStderrSink),
        )
        .map_err(|error| format!("start in-process control runtime: {error}"))?,
    );
    let in_process_config = in_process.handle().config().current();
    let capabilities = vec![
        ControlCapability::PerConnectionClose as u64,
        ControlCapability::ReconcileConnections as u64,
        ControlCapability::ReconcileSessionRehydration as u64,
        ControlCapability::MeteringAbsoluteSnapshots as u64,
        ControlCapability::RustConfigNamespace as u64,
    ];
    let hello = Hello {
        role: Role::RustDataplane as i32,
        process_id,
        process_started_unix_millis,
        supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
        capabilities: capabilities.clone(),
        max_frame_bytes: control_proto::DEFAULT_MAX_FRAME_BYTES,
        build_version: VERSION.to_owned(),
        build_commit: COMMIT.to_owned(),
    };
    let mut wal_name = options.control_socket.as_os_str().to_os_string();
    wal_name.push(".metering.wal");
    let ledger = MeteringLedger::open_persistent(PathBuf::from(wal_name))
        .map_err(|error| format!("open metering WAL: {error}"))?;
    let metering = MeteringSourceRegistry::new(ledger.process_generation())
        .map_err(|error| format!("create metering registry: {error}"))?;
    let dispatch_handler = ControlCommandHandler::with_metering(ledger);
    let mut client =
        ClientConfig::with_defaults(options.control_socket, options.control_uid, hello);
    client.required_capabilities = capabilities;
    let store = config_owner.snapshots.clone();

    // DPL-04: the real session owner replaces DPL-03's parked handler.
    // Sessions share the control client with the runtime; the drain and
    // session-shutdown watches drive the coordinated local shutdown.
    let shared_client = Arc::new(ControlClient::new(client).map_err(|error| error.to_string())?);
    let (drain_tx, drain_rx) = watch::channel(None::<Duration>);
    let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
    let (metering_shutdown_tx, metering_shutdown_rx) = watch::channel(false);
    let loop_config = session_loop_config(in_process_config.drain_grace());
    let (metrics, observations) = MetricsRecorder::channel(DEFAULT_OBSERVATION_CAPACITY);
    let owner: Arc<dyn BoundSessionHandler> = Arc::new(
        EngineSessionOwner::new(
            Arc::clone(&shared_client),
            "default",
            session_shutdown_rx.clone(),
            drain_rx,
            loop_config,
        )
        .with_metrics(metrics.clone())
        .with_metering(metering.clone()),
    );
    let (connection_handler, installer) = DispatchConnectionHandler::new("default", owner);
    let composer = Arc::new(RustConfigComposer::new(
        config_owner.handle.source().clone(),
        options.drain_grace,
    ));
    let (consumer, serving) = DataplaneSnapshotConsumer::new_with_composer(
        Arc::new(SystemMemoryProbe::new()),
        Arc::new(connection_handler),
        composer,
    );
    // Forced shutdown lets each session owner finish its bounded
    // terminal work (close notice + engine join) before the abort
    // backstop fires.
    let consumer =
        consumer.with_force_join_grace(loop_config.cleanup_deadline + Duration::from_secs(1));
    let runtime_handle = in_process.handle();
    let mut modules = ControlModuleSet::new(&runtime_handle);
    modules
        .spawn(config_owner.module)
        .map_err(|error| format!("start config owner module: {error}"))?;
    // Persistent `/config` is part of generation one. Do not let the legacy
    // bridge open SQL listeners against the file-only base while the initial
    // linearizable relist is still outstanding.
    config_owner
        .handle
        .wait_ready()
        .await
        .map_err(|error| format!("initialize config owner: {error}"))?;
    // CP-TOPO self-registration comes online before any SQL admission: register
    // this instance's SQL topology, then wait for its initial registration plan
    // and children to be installed. "Ready" here means the plan's children are
    // installed, not that PD has acknowledged the registration or that a
    // discovery snapshot has been published. A failure after either module is
    // spawned gracefully stops and joins both so a topology lease is revoked
    // instead of an aborted task leaking it until its TTL expires.
    let topology_identity = TopologyRuntimeIdentity {
        version: Arc::from(VERSION),
        git_hash: Arc::from(COMMIT),
        deploy_path: env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from(".")),
        start_timestamp: i64::try_from(process_started_unix_millis / 1000).unwrap_or(i64::MAX),
    };
    let (topology_module, mut topology_handle) = TopologyModule::new(
        Arc::new(config_owner.handle.source().clone()),
        Box::new(ArtifactClusterFactory),
        Arc::new(InterfaceAdvertiseResolver::new(Arc::new(
            interface_advertise_candidates,
        ))),
        topology_identity,
    );
    if let Err(error) = modules.spawn(topology_module) {
        return Err(abort_startup(
            &in_process,
            &mut modules,
            format!("start topology module: {error}"),
        )
        .await);
    }
    if let Err(error) = topology_handle.wait_ready().await {
        return Err(abort_startup(
            &in_process,
            &mut modules,
            format!("initialize topology module: {error}"),
        )
        .await);
    }
    if let Err(error) = modules.spawn(ConfigServingAdapter::new(
        config_owner.handle.source().clone(),
        serving.clone(),
        store.clone(),
        Arc::clone(&in_process),
        options.health_port,
        config_owner.tls_roots,
        options.drain_grace,
    )) {
        return Err(abort_startup(
            &in_process,
            &mut modules,
            format!("start config serving adapter: {error}"),
        )
        .await);
    }
    let runtime = spawn_control_runtime_with_client_and_handler(
        Arc::clone(&shared_client),
        Duration::from_millis(100),
        8,
        store.clone(),
        consumer,
        dispatch_handler,
    );
    if !installer.install(runtime.handle()) {
        runtime.shutdown();
        return Err(abort_startup(
            &in_process,
            &mut modules,
            "install control dispatch handle exactly once".to_owned(),
        )
        .await);
    }
    let metrics_exporter = spawn_metrics_exporter(
        Arc::clone(&shared_client),
        serving.clone(),
        runtime.stats(),
        &metrics,
        observations,
        Duration::from_secs(1),
    );
    let metering_dispatch = runtime.handle();
    let metering_sampler = tokio::spawn(async move {
        run_metering_sampler(
            metering,
            metering_dispatch,
            metering_shutdown_rx,
            Duration::from_secs(1),
        )
        .await
    });

    // Readiness probe for the integration topology: answers 503 until
    // the first applied generation, 200 after. Bound before serving so
    // a bad port fails fast; the task is owned and aborted at exit.
    let health_task = match spawn_health(in_process_config.health_port(), serving.clone()).await {
        Ok(task) => task,
        Err(error) => {
            runtime.shutdown();
            return Err(abort_startup(&in_process, &mut modules, error).await);
        }
    };
    if let Err(error) = in_process.mark_ready() {
        runtime.shutdown();
        return Err(abort_startup(
            &in_process,
            &mut modules,
            format!("mark in-process control runtime ready: {error}"),
        )
        .await);
    }

    // Supervise control and metering together. Either task disappearing must
    // wake this owner: otherwise a sampler panic could leave SQL serving
    // forever, or a control failure could leave the sampler waiting forever.
    // The termination branch joins every session before asking the sampler for
    // its final durable snapshot, so shutdown bytes and final source markers
    // cannot race the sampler's exit.
    let mut control_runtime = tokio::spawn(runtime.join());
    let mut metering_sampler = metering_sampler;
    let mut termination = Box::pin(wait_for_termination_signal());
    let (control_result, sampler_result, serving_result, module_result) = tokio::select! {
        control = &mut control_runtime => {
            let control = match control {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("control runtime supervisor panicked".to_owned()),
            };
            if control.is_err() {
                in_process.fail("legacy_bridge", "runtime_failure");
            } else {
                in_process
                    .begin_shutdown(ShutdownReason::ModuleExit)
                    .map_err(|error| format!("begin module-exit shutdown: {error}"))?;
            }
            let serving_result = stop_drain_and_join_sessions(
                &in_process,
                &serving,
                &drain_tx,
                &session_shutdown_tx,
            ).await;
            metering_shutdown_tx.send_replace(true);
            let sampler = match metering_sampler.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("metering sampler panicked".to_owned()),
            };
            (control, sampler, serving_result, Ok(()))
        }
        sampler = &mut metering_sampler => {
            let sampler = match sampler {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("metering sampler panicked".to_owned()),
            };
            if sampler.is_err() {
                in_process.fail("metering_sampler", "runtime_failure");
            } else {
                in_process
                    .begin_shutdown(ShutdownReason::ModuleExit)
                    .map_err(|error| format!("begin module-exit shutdown: {error}"))?;
            }
            // Readiness becomes false at stop_accepting, before the grace
            // period. Existing sessions then drain and finally receive the
            // force signal. The control shutdown wakes its supervisor.
            let serving_result = stop_drain_and_join_sessions(
                &in_process,
                &serving,
                &drain_tx,
                &session_shutdown_tx,
            ).await;
            metering_shutdown_tx.send_replace(true);
            shared_client.shutdown();
            let control = match control_runtime.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("control runtime supervisor panicked".to_owned()),
            };
            (control, sampler, serving_result, Ok(()))
        }
        () = &mut termination => {
            in_process
                .begin_shutdown(ShutdownReason::Signal)
                .map_err(|error| format!("begin signal shutdown: {error}"))?;
            let serving_result = stop_drain_and_join_sessions(
                &in_process,
                &serving,
                &drain_tx,
                &session_shutdown_tx,
            ).await;
            metering_shutdown_tx.send_replace(true);
            let sampler = match metering_sampler.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("metering sampler panicked".to_owned()),
            };
            shared_client.shutdown();
            let control = match control_runtime.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("control runtime supervisor panicked".to_owned()),
            };
            (control, sampler, serving_result, Ok(()))
        }
        module = modules.join_next() => {
            let failure = match module {
                Some(exit) => match exit.result {
                    Ok(()) => format!("control module {} exited unexpectedly", exit.module),
                    Err(error) => format!("control module {} failed: {error}", exit.module),
                },
                None => "control module executor became empty unexpectedly".to_owned(),
            };
            in_process.fail("control_module", "runtime_failure");
            let serving_result = stop_drain_and_join_sessions(
                &in_process,
                &serving,
                &drain_tx,
                &session_shutdown_tx,
            ).await;
            metering_shutdown_tx.send_replace(true);
            shared_client.shutdown();
            let sampler = match metering_sampler.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("metering sampler panicked".to_owned()),
            };
            let control = match control_runtime.await {
                Ok(result) => result.map_err(|error| error.to_string()),
                Err(_) => Err("control runtime supervisor panicked".to_owned()),
            };
            (control, sampler, serving_result, Err(failure))
        }
    };
    let module_executor_result = join_modules(&mut modules).await;
    if let Some(task) = health_task {
        task.abort();
        let _ = task.await;
    }
    metrics_exporter.shutdown();
    metrics_exporter.join().await;
    let finish_result = in_process
        .finish()
        .map_err(|error| format!("finish in-process control runtime: {error}"));
    sampler_result?;
    control_result?;
    serving_result?;
    module_result?;
    module_executor_result?;
    finish_result?;
    Ok(())
}

/// Gracefully stops and joins already-started control modules when process
/// startup fails after they were spawned. Making shutdown mandatory and
/// advancing to `Stopping` lets each module see the lifecycle change and run its
/// ordered teardown (a topology module revokes its exact lease and joins its
/// children) instead of leaking abruptly aborted tasks. All steps are
/// best-effort; the original startup error is returned unchanged.
async fn abort_startup(
    runtime: &InProcessControlRuntime,
    modules: &mut ControlModuleSet,
    error: String,
) -> String {
    runtime.fail("startup", "startup_failed");
    let _ = runtime.advance_shutdown(LifecyclePhase::Draining);
    let _ = runtime.advance_shutdown(LifecyclePhase::Stopping);
    let _ = join_modules(modules).await;
    let _ = runtime.finish();
    error
}

async fn join_modules(modules: &mut ControlModuleSet) -> Result<(), String> {
    let mut result = Ok(());
    while let Some(exit) = modules.join_next().await {
        if let Err(error) = exit.result {
            result = Err(format!("control module {} failed: {error}", exit.module));
        }
    }
    result
}

/// Stops admission, lets the existing per-session graceful timers run, then
/// forces and joins every session. The metering sampler is deliberately not
/// stopped here: its owner signals it only after this future completes, so
/// its last snapshot sees every final raw counter and final source marker.
async fn stop_drain_and_join_sessions(
    runtime: &InProcessControlRuntime,
    serving: &DataplaneServingHandle,
    drain: &watch::Sender<Option<Duration>>,
    session_shutdown: &watch::Sender<bool>,
) -> Result<(), String> {
    runtime
        .advance_shutdown(LifecyclePhase::Draining)
        .map_err(|error| format!("enter control runtime drain phase: {error}"))?;
    serving.stop_accepting().await;
    // Read after admission stops so a successfully committed dynamic update
    // is the sole process-shutdown deadline. The launch-time snapshot must
    // not silently pin this reloadable Go field for the process lifetime.
    let grace = runtime.handle().config().current().drain_grace();
    drain.send_replace(Some(grace));
    tokio::time::sleep(grace).await;
    session_shutdown.send_replace(true);
    let serving_result = serving
        .shutdown()
        .await
        .map_err(|error: ServerError| format!("shut down SQL listeners: {error}"));
    runtime
        .advance_shutdown(LifecyclePhase::Stopping)
        .map_err(|error| format!("enter control runtime stop phase: {error}"))?;
    serving_result
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

struct ConfigOwner {
    module: ConfigModule,
    handle: ConfigModuleHandle,
    snapshots: SnapshotStore,
    tls_roots: Vec<PathBuf>,
}

fn load_config_owner(options: &Options, process_id: &str) -> Result<ConfigOwner, String> {
    let current_dir = env::current_dir().map_err(|_| "resolve current directory".to_owned())?;
    let base = ConfigModuleOptions {
        config_file: Some(options.config_file.clone()),
        advertise_addr: None,
        current_dir,
        etcd: None,
        election: None,
        persistence_factory: None,
    };
    let (_, bootstrap) = ConfigModule::load(base.clone())
        .map_err(|error| format!("load initial Rust config source: {error}"))?;
    let initial = bootstrap.source().current();

    let mut tls_roots = options.tls_roots.clone();
    tls_roots.extend(
        initial
            .effective()
            .rust_tls_allowed_roots()
            .iter()
            .map(PathBuf::from),
    );
    tls_roots.sort();
    tls_roots.dedup();
    let snapshots = SnapshotStore::new(tls_roots.clone())
        .map_err(|error| format!("create snapshot store: {error}"))?;
    let (etcd, election) = persistence_options(initial.as_ref(), process_id)?;
    let module_options = ConfigModuleOptions {
        etcd,
        election,
        persistence_factory: Some(Arc::new(config_persistence_client)),
        ..base
    };
    // Every accepted generation funnels through one composite validator in a
    // fixed order: serving first (fails a bad TLS/protocol candidate before any
    // topology material is read), then topology (prepares the per-cluster etcd
    // clients that ride the published snapshot as its opaque artifact).
    let serving = Arc::new(ServingCandidateValidator::new(
        snapshots.clone(),
        options.drain_grace,
    ));
    let validator = Arc::new(CompositeCandidateValidator::new(
        serving,
        Arc::new(TopologyCandidateValidator),
    ));
    let (module, handle) = ConfigModule::load_with_validator(module_options, validator)
        .map_err(|error| format!("load validated Rust config owner: {error}"))?;
    if handle.source().current().config_checksum() != initial.config_checksum() {
        return Err("config file changed while initializing Rust config owner".to_owned());
    }
    Ok(ConfigOwner {
        module,
        handle,
        snapshots,
        tls_roots,
    })
}

fn persistence_options(
    snapshot: &control_config::ConfigNamespaceSnapshot,
    process_id: &str,
) -> Result<(Option<EtcdClientConfig>, Option<ElectionConfig>), String> {
    let client = config_persistence_client(snapshot.effective())?;
    if client.is_none() {
        return Ok((None, None));
    }
    let election = ElectionConfig::new(
        "/tiproxy/config/owner",
        process_id,
        format!("/tiproxy/config/session/{process_id}"),
        30,
    )
    .map_err(|error| format!("validate config election: {error}"))?;
    Ok((client, Some(election)))
}

fn config_persistence_client(
    effective: &control_config::EffectiveConfig,
) -> Result<Option<EtcdClientConfig>, String> {
    let Some(persistence) = effective.config_persistence() else {
        return Ok(None);
    };
    let endpoints = persistence
        .pd_addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let tls = etcd_tls(&persistence.cluster_tls)?;
    let client = EtcdClientConfig::new(endpoints, tls)
        .map_err(|error| format!("validate config persistence client: {error}"))?;
    Ok(Some(client))
}

fn etcd_tls(config: &control_config::ClientTlsConfig) -> Result<Option<EtcdTlsConfig>, String> {
    if config.skip_ca_verification {
        return Err("config persistence does not support skip-ca-verification".to_owned());
    }
    let configured = config.ca_path.is_some()
        || config.certificate_path.is_some()
        || config.private_key_path.is_some();
    if !configured {
        return Ok(None);
    }
    let ca_path = config
        .ca_path
        .as_deref()
        .ok_or_else(|| "config persistence TLS requires a CA".to_owned())?;
    let ca = std::fs::read(ca_path).map_err(|_| "read config persistence TLS CA".to_owned())?;
    let certificate = read_optional_tls(config.certificate_path.as_deref(), "certificate")?;
    let key = read_optional_tls(config.private_key_path.as_deref(), "private key")?;
    EtcdTlsConfig::new(ca, certificate, key, None)
        .map(Some)
        .map_err(|error| format!("validate config persistence TLS: {error}"))
}

fn read_optional_tls(path: Option<&Path>, kind: &str) -> Result<Option<Vec<u8>>, String> {
    path.map(|path| std::fs::read(path).map_err(|_| format!("read config persistence TLS {kind}")))
        .transpose()
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
    let mut config_file = env::var_os(CONFIG_FILE_ENV).map(PathBuf::from);
    let mut socket = env::var_os(CONTROL_SOCKET_ENV).map(PathBuf::from);
    let mut uid = env::var(CONTROL_UID_ENV)
        .ok()
        .map(|value| parse_uid(&value))
        .transpose()?;
    let mut tls_roots: Vec<PathBuf> = env::var_os(TLS_ROOTS_ENV)
        .map(|value| env::split_paths(&value).collect())
        .unwrap_or_default();
    let mut drain_grace = None;
    let mut health_port: u16 = 0;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--version" | "-V" => return Ok(Command::Version),
            "--help" | "-h" => return Ok(Command::Help),
            "--integration-capabilities" => return Ok(Command::IntegrationCapabilities),
            "--config" => {
                config_file = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--config requires a path".to_owned())?,
                ));
            }
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
                drain_grace = Some(Duration::from_secs(seconds));
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
        config_file: config_file
            .ok_or_else(|| format!("--config or {CONFIG_FILE_ENV} is required"))?,
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
    "Usage: tiproxy-rs --config <path> --control-socket <absolute-path> --control-uid <uid> \
     [--tls-root <absolute-path>]... [--drain-grace-seconds <n>] [--health-port <n>]\n\
     Environment: TIPROXY_CONFIG, TIPROXY_CONTROL_SOCKET, TIPROXY_CONTROL_UID, TIPROXY_TLS_ROOTS"
}

fn version_output() -> String {
    format!("tiproxy-rs {VERSION} (commit {COMMIT}, built {BUILD_TIME})")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use control_config::{ConfigNamespaceSource, ConfigNamespaceStore};

    use super::{
        Command, INTEGRATION_CAPABILITIES, MAX_DRAIN_GRACE_SECONDS, Options,
        config_persistence_client, parse_options, persistence_options, session_loop_config,
        version_output,
    };
    use crate::config_composition::control_config;

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
            "--config".to_owned(),
            "/etc/tiproxy/tiproxy.toml".to_owned(),
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
                config_file: PathBuf::from("/etc/tiproxy/tiproxy.toml"),
                control_socket: PathBuf::from("/tmp/control.sock"),
                control_uid: 42,
                tls_roots: vec![PathBuf::from("/etc/tiproxy/tls")],
                drain_grace: None,
                health_port: 0,
            }
        );
    }

    #[test]
    fn drain_grace_is_the_session_drain_deadline() {
        let command = parse_options([
            "--config".to_owned(),
            "/etc/tiproxy/tiproxy.toml".to_owned(),
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
        assert_eq!(
            options.drain_grace,
            Some(std::time::Duration::from_secs(45))
        );
        assert_eq!(
            session_loop_config(options.drain_grace.unwrap_or_default()).drain_deadline,
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
            "in-process-control-runtime,control-bridge-v1,mysql-listener,health-endpoint,graceful-shutdown,tls,proxy-v2,zlib,zstd",
            "only what the binary truthfully provides: the plain slice plus wired TLS, PROXY v2, and compression"
        );
        for wired in ["tls", "proxy-v2", "zlib", "zstd"] {
            assert!(
                INTEGRATION_CAPABILITIES.contains(wired),
                "{wired:?} is wired (WIRE-activation A1/B/C), so it must be advertised"
            );
        }
    }

    #[test]
    fn operational_cli_projects_into_rust_control_domain() {
        let options = Options {
            config_file: PathBuf::from("/etc/tiproxy/tiproxy.toml"),
            control_socket: PathBuf::from("/tmp/control.sock"),
            control_uid: 42,
            tls_roots: vec![PathBuf::from("/etc/tiproxy/tls")],
            drain_grace: Some(std::time::Duration::from_secs(45)),
            health_port: 8081,
        };
        let source = ConfigNamespaceStore::from_toml(
            b"enable-traffic-replay = false\n",
            None,
            std::path::Path::new("/tmp"),
        )
        .unwrap_or_else(|error| unreachable!("valid source: {error}"));
        let config = control_config(
            source.current().as_ref(),
            options.health_port,
            &options.tls_roots,
            options.drain_grace,
        )
        .unwrap_or_else(|error| unreachable!("valid control config: {error}"));
        assert_eq!(config.generation(), 1);
        assert_eq!(
            config.drain_grace(),
            options.drain_grace.unwrap_or_default()
        );
        assert_eq!(config.health_port(), options.health_port);
        assert_eq!(config.tls().roots(), options.tls_roots);
    }

    #[test]
    fn persistence_uses_restart_pinned_legacy_pd_addrs() {
        let source = ConfigNamespaceStore::from_toml(
            br#"
[proxy]
pd-addrs = "owner-pd:2379"

[[proxy.backend-clusters]]
name = "a-first"
pd-addrs = "routing-pd:2379"
"#,
            None,
            std::path::Path::new("/tmp"),
        )
        .unwrap_or_else(|error| unreachable!("valid source: {error}"));
        let (client, election) = persistence_options(source.current().as_ref(), "process-a")
            .unwrap_or_else(|error| unreachable!("valid persistence options: {error}"));
        let client = client.unwrap_or_else(|| unreachable!("persistence is configured"));
        assert_eq!(client.endpoints(), ["http://owner-pd:2379"]);
        assert!(election.is_some());
    }

    #[test]
    fn persistence_rejects_skip_ca_instead_of_silently_downgrading_to_plaintext() {
        let source = ConfigNamespaceStore::from_toml(
            b"[security.cluster-tls]\nskip-ca = true\n",
            None,
            std::path::Path::new("/tmp"),
        )
        .unwrap_or_else(|error| unreachable!("valid source model: {error}"));
        assert!(
            config_persistence_client(source.current().effective()).is_err(),
            "skip-ca without a CA must not silently construct a plaintext etcd client"
        );
    }

    #[test]
    fn parses_health_port() {
        let command = parse_options([
            "--config".to_owned(),
            "/etc/tiproxy/tiproxy.toml".to_owned(),
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
                "--config".to_owned(),
                "/etc/tiproxy/tiproxy.toml".to_owned(),
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
            "--config".to_owned(),
            "/etc/tiproxy/tiproxy.toml".to_owned(),
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
                "--config".to_owned(),
                "/etc/tiproxy/tiproxy.toml".to_owned(),
                "--control-socket".to_owned(),
                "control.sock".to_owned(),
                "--control-uid".to_owned(),
                "42".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_options([
                "--config".to_owned(),
                "/etc/tiproxy/tiproxy.toml".to_owned(),
                "--control-socket".to_owned(),
                "/tmp/control.sock".to_owned(),
            ])
            .is_err()
        );
    }
}
