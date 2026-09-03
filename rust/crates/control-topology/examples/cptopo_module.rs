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

//! Real-etcd integration for [`control_topology::TopologyModule`].
//!
//! This drives the actual module (subscribe -> initial apply -> generation
//! reconcile -> lifecycle shutdown) against the shared CP003 embedded-etcd
//! fixture, locking the seams a no-etcd test cannot observe:
//!
//! * generation 1 registers `info` + `ttl` under one lease;
//! * an unrelated hot-reload is a no-op — the lease is unchanged (no flap);
//! * a changed client (a rotation) rebuilds under a fresh lease;
//! * lifecycle shutdown stops and joins the children (this row only locks
//!   children-joined; the exact-lease revoke cleanup is locked by `cptopo_live`
//!   Row 4).
//!
//! The harness reads `CPTOPO_CONNECTION_FILE`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use control_config::{ConfigNamespaceStore, TopologyConfig, TopologyRuntimeIdentity};
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{
    ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
    MetricsPolicy, OwnerToken, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
};
use control_topology::{
    StaticAdvertiseResolver, TopologyClientFactory, TopologyClusterClient, TopologyModule,
    TopologyStatus,
};
use etcd_client::DeleteOptions;
use serde_json::Value;
use tokio::sync::watch;

type AnyError = Box<dyn std::error::Error>;

const ADVERTISE_HOST: &str = "127.0.0.88";
const INFO_KEY: &str = "/topology/tiproxy/127.0.0.88:6000/info";
const TTL_KEY: &str = "/topology/tiproxy/127.0.0.88:6000/ttl";

/// Factory whose built client varies by mode, so the test can force a rebuild
/// (a changed client) or keep a stable client (a no-op).
struct RotatingFactory {
    endpoint: String,
    rotated: Arc<AtomicUsize>,
}

impl TopologyClientFactory for RotatingFactory {
    fn build(&self, config: &TopologyConfig) -> Result<Vec<TopologyClusterClient>, String> {
        // Vary the request timeout to simulate a rotation: the built
        // EtcdClientConfig differs, so the registration plan differs and
        // rebuilds, while the endpoint still points at the live fixture.
        let request_ms = if self.rotated.load(Ordering::SeqCst) == 0 {
            500
        } else {
            700
        };
        let client = EtcdClientConfig::new([self.endpoint.clone()], None)
            .map_err(|error| format!("client config: {error}"))?
            .with_timeouts(
                Duration::from_millis(500),
                Duration::from_millis(request_ms),
                Duration::from_secs(1),
                Duration::from_millis(500),
                Duration::from_secs(1),
            )
            .map_err(|error| format!("client timeouts: {error}"))?;
        Ok(config
            .backend_clusters
            .iter()
            .map(|cluster| TopologyClusterClient {
                cluster_name: Arc::clone(&cluster.name),
                client: client.clone(),
            })
            .collect())
    }
}

struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

fn config_gen(max_connections: u64) -> Vec<u8> {
    format!(
        r#"
[proxy]
addr = "0.0.0.0:6000"
max-connections = {max_connections}

[api]
addr = "0.0.0.0:10080"

[[proxy.backend-clusters]]
name = "cluster-a"
pd-addrs = "pd-a:2379"
ns-servers = ["dns-a:53"]
"#
    )
    .into_bytes()
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), AnyError> {
    let connection_path = std::env::var("CPTOPO_CONNECTION_FILE")?;
    let endpoint = read_endpoint(Path::new(&connection_path))?;
    let probe_config = EtcdClientConfig::new([endpoint.clone()], None)?.with_timeouts(
        Duration::from_millis(500),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_millis(500),
        Duration::from_secs(1),
    )?;

    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "cptopo-module",
        ControlConfig::new(
            1,
            Duration::from_secs(30),
            0,
            TlsPolicy::default(),
            LogLevel::Info,
            MetricsPolicy::default(),
        )?,
        Arc::new(NullSink),
    )?;
    let owner = runtime.handle().module_context().owner().clone();
    delete_prefix(&owner, &probe_config, "/topology/").await?;

    let store = ConfigNamespaceStore::from_toml(&config_gen(100), None, &std::env::current_dir()?)?;
    let rotated = Arc::new(AtomicUsize::new(0));
    let (module, mut handle) = TopologyModule::new(
        Arc::new(store.clone()),
        Box::new(RotatingFactory {
            endpoint: endpoint.clone(),
            rotated: Arc::clone(&rotated),
        }),
        Arc::new(StaticAdvertiseResolver::new(ADVERTISE_HOST)),
        identity(),
    );

    let context = runtime.handle().module_context();
    runtime.mark_ready()?;
    let module_task = tokio::spawn(Box::new(module).run(context));
    tokio::time::timeout(Duration::from_secs(10), handle.wait_ready()).await??;

    // Generation 1: the module registers under a first lease.
    let lease_one = wait_for_lease(&owner, &probe_config, Duration::from_secs(10))
        .await?
        .ok_or("registration never appeared for generation 1")?;
    require(lease_one != 0, "generation 1 lease is zero")?;
    // info and ttl must be published under the same non-zero lease.
    let ttl_lease = wait_for_key_lease(&owner, &probe_config, TTL_KEY, Duration::from_secs(5))
        .await?
        .ok_or("ttl key never appeared for generation 1")?;
    require(
        ttl_lease == lease_one,
        "info and ttl are not under the same lease",
    )?;

    // No-op generation: an unrelated hot-reload must not flap the lease.
    let mut status = handle.status();
    store.apply_toml(&config_gen(200), None, 2, &std::env::current_dir()?)?;
    wait_for_applied(&mut status, 2).await?;
    let lease_after_noop = wait_for_lease(&owner, &probe_config, Duration::from_secs(5))
        .await?
        .ok_or("registration vanished after the no-op generation")?;
    require(
        lease_after_noop == lease_one,
        "an unrelated hot-reload flapped the registration lease",
    )?;

    // Rotation generation: a changed client rebuilds under a fresh lease.
    rotated.store(1, Ordering::SeqCst);
    store.apply_toml(&config_gen(300), None, 3, &std::env::current_dir()?)?;
    wait_for_applied(&mut status, 3).await?;
    let lease_after_rotation =
        wait_for_new_lease(&owner, &probe_config, lease_one, Duration::from_secs(10))
            .await?
            .ok_or("registration was not rebuilt after the rotation")?;
    require(
        lease_after_rotation != lease_one && lease_after_rotation != 0,
        "rotation did not produce a fresh lease",
    )?;

    // Lifecycle shutdown stops and joins the children.
    runtime.begin_shutdown(ShutdownReason::Requested)?;
    tokio::time::timeout(Duration::from_secs(10), module_task).await???;
    runtime.advance_shutdown(LifecyclePhase::Draining)?;
    runtime.advance_shutdown(LifecyclePhase::Stopping)?;
    runtime.finish()?;

    println!("CPTOPO_MODULE_OK");
    Ok(())
}

async fn wait_for_applied(
    status: &mut watch::Receiver<TopologyStatus>,
    generation: u64,
) -> Result<(), AnyError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if status.borrow_and_update().applied_generation >= generation {
            return Ok(());
        }
        tokio::time::timeout(deadline - tokio::time::Instant::now(), status.changed()).await??;
    }
}

async fn wait_for_lease(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    timeout: Duration,
) -> Result<Option<i64>, AnyError> {
    wait_for_key_lease(owner, config, INFO_KEY, timeout).await
}

async fn wait_for_key_lease(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    timeout: Duration,
) -> Result<Option<i64>, AnyError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(lease) = key_lease(owner, config, key).await? {
            return Ok(Some(lease));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_new_lease(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    previous: i64,
    timeout: Duration,
) -> Result<Option<i64>, AnyError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(lease) = key_lease(owner, config, INFO_KEY).await?
            && lease != 0
            && lease != previous
        {
            return Ok(Some(lease));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn key_lease(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
) -> Result<Option<i64>, AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let key = key.as_bytes().to_vec();
    let response = connection
        .execute(move |client| Box::pin(client.get(key, None)))
        .await?;
    Ok(response.kvs().first().map(etcd_client::KeyValue::lease))
}

async fn delete_prefix(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    prefix: &str,
) -> Result<(), AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let prefix = prefix.as_bytes().to_vec();
    connection
        .execute(move |client| {
            Box::pin(client.delete(prefix, Some(DeleteOptions::new().with_prefix())))
        })
        .await?;
    Ok(())
}

fn identity() -> TopologyRuntimeIdentity {
    TopologyRuntimeIdentity {
        version: Arc::from("v-module"),
        git_hash: Arc::from("hash-module"),
        deploy_path: PathBuf::from("/deploy/module"),
        start_timestamp: 1_700_000_000,
    }
}

fn read_endpoint(path: &Path) -> Result<String, AnyError> {
    let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(value["etcd_endpoint"]
        .as_str()
        .ok_or("missing etcd_endpoint")?
        .to_owned())
}

fn require(condition: bool, message: &'static str) -> Result<(), AnyError> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
