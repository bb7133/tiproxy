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

//! CP-TOPO self-registration and discovery evidence against the restartable
//! production-Go embedded-etcd fixture (shared with CP003/CP004).
//!
//! This is the fault matrix that runs the real `registrar::run` and
//! `poll_tidb_topology` against live etcd:
//!
//! * first registration publishes `info` + `ttl` under one non-zero lease;
//! * the discovery poll keeps only `info` records with a live `ttl` sibling;
//! * an externally revoked lease is detected and the registration is rebuilt
//!   under a fresh lease.
//!
//! Shutdown-cleanup and the same-address ABA gate are added once the cleanup
//! semantics decision lands. The harness reads `CPTOPO_CONNECTION_FILE`.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{
    ControlConfig, ControlRuntime, EventSink, LifecyclePhase, LogLevel, MetricsPolicy, OwnerToken,
    OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
};
use control_topology::{TopologyInfo, poll_tidb_topology, run as registrar_run};
use etcd_client::{DeleteOptions, PutOptions};
use serde_json::Value;
use tokio::sync::watch;

type AnyError = Box<dyn std::error::Error>;

const REGISTER_HOST: &str = "127.0.0.99";
const REGISTER_SQL_PORT: u16 = 4000;
const REGISTER_STATUS_PORT: u16 = 10080;

struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), AnyError> {
    let connection_path = std::env::var("CPTOPO_CONNECTION_FILE")?;
    let endpoint = read_endpoint(Path::new(&connection_path))?;
    let config = client_config(&endpoint)?;

    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "cptopo-process",
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
    runtime.mark_ready()?;

    // Isolated topology view for this invocation.
    delete_prefix(&owner, &config, "/topology/").await?;

    let info = TopologyInfo::new(
        REGISTER_HOST,
        REGISTER_SQL_PORT,
        REGISTER_STATUS_PORT,
        "v-cptopo",
        "hash-cptopo",
        "/deploy/cptopo",
        1_700_000_000,
    );
    let addr = info.registration_addr();
    let info_key = format!("/topology/tiproxy/{addr}/info");
    let ttl_key = format!("/topology/tiproxy/{addr}/ttl");

    // --- Row 1: first registration publishes info + ttl under one lease. ---
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connector = EtcdConnector::new(owner.clone(), config.clone());
    let registrar = tokio::spawn(async move {
        let _ = Box::pin(registrar_run(connector, info, shutdown_rx)).await;
    });

    let (info_value, info_lease) =
        wait_for_key(&owner, &config, &info_key, Duration::from_secs(10))
            .await?
            .ok_or("info key never appeared")?;
    let (_, ttl_lease) = wait_for_key(&owner, &config, &ttl_key, Duration::from_secs(10))
        .await?
        .ok_or("ttl key never appeared")?;
    require(info_lease != 0, "info key was not attached to a lease")?;
    require(
        info_lease == ttl_lease,
        "info and ttl keys are not under the same lease",
    )?;
    let published: Value = serde_json::from_slice(&info_value)?;
    require(
        published["port"].as_str() == Some("4000"),
        "published info port is not the string 4000",
    )?;
    require(
        published["status_port"].as_str() == Some("10080"),
        "published info status_port is not the string 10080",
    )?;
    require(
        published.get("labels").is_none(),
        "self info must not carry a labels field",
    )?;

    // --- Row 2: discovery poll keeps only info records with a live ttl. ---
    put(
        &owner,
        &config,
        "/topology/tidb/10.0.0.1:4000/info",
        br#"{"ip":"10.0.0.1","status_port":10080}"#,
    )
    .await?;
    put(
        &owner,
        &config,
        "/topology/tidb/10.0.0.1:4000/ttl",
        b"1700000000",
    )
    .await?;
    put(
        &owner,
        &config,
        "/topology/tidb/10.0.0.2:4000/info",
        br#"{"ip":"10.0.0.2","status_port":10080}"#,
    )
    .await?;
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let snapshot = poll_tidb_topology(&mut connection).await?;
    require(
        snapshot.backends.len() == 1,
        "discovery kept a backend without a live ttl sibling",
    )?;
    require(
        snapshot.backends[0].addr == "10.0.0.1:4000",
        "discovery returned the wrong live backend",
    )?;

    // --- Row 3: an externally revoked lease is rebuilt under a fresh lease. ---
    revoke_lease(&owner, &config, info_lease).await?;
    let rebuilt_lease = wait_for_rebuilt_lease(
        &owner,
        &config,
        &info_key,
        info_lease,
        Duration::from_secs(30),
    )
    .await?
    .ok_or("registration was not rebuilt after lease revoke")?;
    require(
        rebuilt_lease != 0 && rebuilt_lease != info_lease,
        "rebuilt registration did not use a fresh lease",
    )?;

    // Teardown: stop the registrar and the runtime.
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), registrar).await;
    runtime.begin_shutdown(ShutdownReason::Requested)?;
    runtime.advance_shutdown(LifecyclePhase::Draining)?;
    runtime.advance_shutdown(LifecyclePhase::Stopping)?;
    runtime.finish()?;

    println!("CPTOPO_LIVE_OK");
    Ok(())
}

async fn wait_for_key(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    timeout: Duration,
) -> Result<Option<(Vec<u8>, i64)>, AnyError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(entry) = get_key(owner, config, key).await? {
            return Ok(Some(entry));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_rebuilt_lease(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    previous_lease: i64,
    timeout: Duration,
) -> Result<Option<i64>, AnyError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some((_, lease)) = get_key(owner, config, key).await?
            && lease != 0
            && lease != previous_lease
        {
            return Ok(Some(lease));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn get_key(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
) -> Result<Option<(Vec<u8>, i64)>, AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let key = key.as_bytes().to_vec();
    let response = connection
        .execute(move |client| Box::pin(client.get(key, None)))
        .await?;
    Ok(response
        .kvs()
        .first()
        .map(|value| (value.value().to_vec(), value.lease())))
}

async fn put(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    value: &[u8],
) -> Result<(), AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let key = key.as_bytes().to_vec();
    let value = value.to_vec();
    connection
        .execute(move |client| Box::pin(client.put(key, value, None::<PutOptions>)))
        .await?;
    Ok(())
}

async fn revoke_lease(
    owner: &OwnerToken,
    config: &EtcdClientConfig,
    lease_id: i64,
) -> Result<(), AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    connection
        .execute(move |client| Box::pin(client.lease_revoke(lease_id)))
        .await?;
    Ok(())
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

fn client_config(endpoint: &str) -> Result<EtcdClientConfig, AnyError> {
    Ok(
        EtcdClientConfig::new([endpoint.to_owned()], None)?.with_timeouts(
            Duration::from_millis(500),
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_millis(500),
            Duration::from_secs(1),
        )?,
    )
}

fn read_endpoint(path: &Path) -> Result<String, AnyError> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
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
