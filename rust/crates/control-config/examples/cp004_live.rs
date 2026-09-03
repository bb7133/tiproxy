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

//! Runs CP-CFG/NS against the restartable production-Go embedded-etcd fixture.

use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use control_config::source::{decode_log_online, decode_namespace, decode_proxy_online};
use control_config::{
    ConfigModule, ConfigModuleOptions, ConfigMutationError, ConfigNamespaceSource,
    ConfigNamespaceStore,
};
use control_etcd::ElectionConfig;
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{
    ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
    MetricsPolicy, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
};
use etcd_client::{DeleteOptions, PutOptions};
use serde_json::{Value, json};

type AnyError = Box<dyn std::error::Error>;

const CONFIG_PREFIX: &str = "/config/";
const LOG_KEY: &str = "/config/log";
const PROXY_KEY: &str = "/config/proxy";
const SESSION_KEY: &str = "/tiproxy/cp004/session/member-A";

#[derive(Clone)]
struct ConnectionInfo {
    etcd_endpoint: String,
    control_url: String,
}

struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), AnyError> {
    let connection_path = std::env::var("CP004_CONNECTION_FILE")?;
    let connection = read_connection(Path::new(&connection_path))?;
    let client_config = client_config(&connection)?;

    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "cp004-process",
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

    // Every observer invocation starts with an isolated historical /config view.
    delete_prefix(&owner, &client_config, CONFIG_PREFIX).await?;

    let options = ConfigModuleOptions {
        config_file: None,
        advertise_addr: None,
        current_dir: std::env::current_dir()?,
        etcd: Some(client_config.clone()),
        election: Some(ElectionConfig::new(
            "/tiproxy/cp004/election",
            "member-A",
            SESSION_KEY,
            3,
        )?),
        persistence_factory: None,
    };
    let (module, handle) = ConfigModule::load(options)?;
    let module_task = tokio::spawn(Box::new(module).run(runtime.handle().module_context()));
    tokio::time::timeout(Duration::from_secs(10), handle.wait_ready()).await??;
    runtime.mark_ready()?;

    let initial = handle.source().current();
    require(initial.generation() == 1, "initial generation was not one")?;
    let log = decode_log_online(br#"{"level":"warn"}"#)?;
    retry_mutation(|| handle.set_log(log.clone())).await?;
    let after_log = wait_generation(handle.source(), initial.generation() + 1).await?;
    require(
        after_log.source_revision().etcd_revision > 0,
        "owner-fenced log write did not enter the watched source",
    )?;

    if std::env::var_os("CP004_MUTATE_LEASE_ATTACHED").is_some() {
        put_with_lease(&owner, &client_config, LOG_KEY, br#"{"level":"warn"}"#).await?;
    }
    require(
        key_lease(&owner, &client_config, LOG_KEY).await? == 0,
        "persistent /config write was attached to a lease",
    )?;

    let last_good_generation = after_log.generation();
    let last_good_checksum = after_log.config_checksum();
    let invalid_revision = put(
        &owner,
        &client_config,
        PROXY_KEY,
        br#"{"max-connections":"not-a-number"}"#,
    )
    .await?;
    wait_observed_revision(handle.source(), invalid_revision).await?;
    let after_invalid = handle.source().current();
    let invalid_retained = after_invalid.generation() == last_good_generation
        && after_invalid.config_checksum() == last_good_checksum;
    let observed_invalid_retained = if std::env::var_os("CP004_MUTATE_INVALID_OVERWRITE").is_some()
    {
        !invalid_retained
    } else {
        invalid_retained
    };
    require(
        observed_invalid_retained,
        "invalid persistent candidate overwrote the last-good snapshot",
    )?;

    let valid_proxy = br#"{"max-connections":23}"#;
    let valid_revision = put(&owner, &client_config, PROXY_KEY, valid_proxy).await?;
    wait_observed_revision(handle.source(), valid_revision).await?;
    let after_proxy = wait_generation(handle.source(), last_good_generation + 1).await?;
    let observed_generation = if std::env::var_os("CP004_MUTATE_GENERATION_SKIP").is_some() {
        after_proxy.generation().saturating_add(1)
    } else {
        after_proxy.generation()
    };
    require(
        observed_generation == last_good_generation + 1,
        "one accepted watch candidate did not publish one contiguous generation",
    )?;
    require(
        decode_proxy_online(valid_proxy).is_ok(),
        "the accepted proxy fixture was invalid",
    )?;

    let alice = decode_namespace(
        "alpha",
        br#"{"namespace":"alpha","frontend":{"user":"alice"},"backend":{"instances":["127.0.0.1:4000"]}}"#,
    )?;
    retry_mutation(|| handle.set_namespace(alice.clone())).await?;
    let alice_snapshot = handle.source().current();
    require(
        alice_snapshot.generation() == after_proxy.generation() + 1
            && alice_snapshot.namespaces()[0].frontend.user == "alice",
        "successful namespace mutation was acknowledged before publication",
    )?;

    let bob = decode_namespace(
        "alpha",
        br#"{"namespace":"alpha","frontend":{"user":"bob"},"backend":{"instances":["127.0.0.1:4000"]}}"#,
    )?;
    retry_mutation(|| handle.set_namespace(bob.clone())).await?;
    let bob_snapshot = handle.source().current();
    require(
        bob_snapshot.generation() == alice_snapshot.generation() + 1
            && alice_snapshot.namespaces()[0].frontend.user == "alice"
            && bob_snapshot.namespaces()[0].frontend.user == "bob",
        "back-to-back mutation did not publish exactly once or mutated prior snapshot",
    )?;

    let lease = key_lease(&owner, &client_config, SESSION_KEY).await?;
    require(lease != 0, "config election session did not own a lease")?;
    post_control(&connection.control_url, &format!("/revoke?lease={lease}")).await?;
    let stale_result = handle.set_namespace(alice.clone()).await;
    let stale_rejected = matches!(stale_result, Err(ConfigMutationError::NotLeader));
    let observed_stale_rejected = if std::env::var_os("CP004_MUTATE_OLD_OWNER_WRITE").is_some() {
        !stale_rejected
    } else {
        stale_rejected
    };
    require(
        observed_stale_rejected,
        "revoked config owner committed or reported a persistent write",
    )?;
    retry_mutation(|| handle.set_namespace(bob.clone())).await?;

    let before_restart = handle.source().current();
    post_control(&connection.control_url, "/stop").await?;
    tokio::time::sleep(Duration::from_millis(700)).await;
    post_control(&connection.control_url, "/start").await?;
    let restart_revision = retry_put(
        &owner,
        &client_config,
        PROXY_KEY,
        br#"{"max-connections":41}"#,
    )
    .await?;
    post_control(&connection.control_url, "/bump-compact").await?;
    wait_observed_revision(handle.source(), restart_revision).await?;
    let after_restart = wait_generation(handle.source(), before_restart.generation() + 1).await?;
    require(
        after_restart.source_revision().etcd_revision >= restart_revision,
        "restart/compaction relist lost the accepted source revision",
    )?;

    runtime.begin_shutdown(ShutdownReason::Requested)?;
    tokio::time::timeout(Duration::from_secs(10), module_task).await???;
    runtime.advance_shutdown(LifecyclePhase::Draining)?;
    runtime.advance_shutdown(LifecyclePhase::Stopping)?;
    runtime.finish()?;

    println!(
        "{}",
        json!({
            "schema_version": 1,
            "producer": "rust",
            "scenario": "CP-CFG-NS-REAL-ETCD",
            "initial_generation": initial.generation(),
            "final_generation": after_restart.generation(),
            "invalid_revision": invalid_revision,
            "restart_revision": restart_revision,
            "persistent_lease": 0,
            "invalid_last_good_retained": true,
            "old_owner_fenced": true,
            "established_namespace_retained": true,
            "restart_compaction_recovered": true
        })
    );
    Ok(())
}

async fn retry_mutation<F, Fut>(mut operation: F) -> Result<(), AnyError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), ConfigMutationError>>,
{
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match operation().await {
            Ok(()) => return Ok(()),
            Err(ConfigMutationError::NotLeader | ConfigMutationError::Unavailable)
                if Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_generation(
    source: &ConfigNamespaceStore,
    generation: u64,
) -> Result<Arc<control_config::ConfigNamespaceSnapshot>, AnyError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let current = source.current();
        if current.generation() >= generation {
            require(
                current.generation() == generation,
                "accepted generation skipped the expected successor",
            )?;
            return Ok(current);
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for generation {generation}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_observed_revision(
    source: &ConfigNamespaceStore,
    revision: i64,
) -> Result<(), AnyError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if source.observed_source_revision().etcd_revision >= revision {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for etcd revision {revision}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn delete_prefix(
    owner: &control_plane::OwnerToken,
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

async fn put(
    owner: &control_plane::OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    value: &[u8],
) -> Result<i64, AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let key = key.as_bytes().to_vec();
    let value = value.to_vec();
    let response = connection
        .execute(move |client| Box::pin(client.put(key, value, None)))
        .await?;
    Ok(response
        .header()
        .map_or(0, etcd_client::ResponseHeader::revision))
}

async fn retry_put(
    owner: &control_plane::OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    value: &[u8],
) -> Result<i64, AnyError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match put(owner, config, key, value).await {
            Ok(revision) => return Ok(revision),
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn put_with_lease(
    owner: &control_plane::OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
    value: &[u8],
) -> Result<(), AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let lease = connection
        .execute(|client| Box::pin(client.lease_grant(30, None)))
        .await?
        .id();
    let key = key.as_bytes().to_vec();
    let value = value.to_vec();
    connection
        .execute(move |client| {
            Box::pin(client.put(key, value, Some(PutOptions::new().with_lease(lease))))
        })
        .await?;
    Ok(())
}

async fn key_lease(
    owner: &control_plane::OwnerToken,
    config: &EtcdClientConfig,
    key: &str,
) -> Result<i64, AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), config.clone())
        .connect()
        .await?;
    let key = key.as_bytes().to_vec();
    let response = connection
        .execute(move |client| Box::pin(client.get(key, None)))
        .await?;
    response.kvs().first().map_or_else(
        || Err("missing expected etcd key".into()),
        |value| Ok(value.lease()),
    )
}

fn client_config(connection: &ConnectionInfo) -> Result<EtcdClientConfig, AnyError> {
    Ok(
        EtcdClientConfig::new([connection.etcd_endpoint.clone()], None)?.with_timeouts(
            Duration::from_millis(500),
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_millis(500),
            Duration::from_secs(1),
        )?,
    )
}

async fn post_control(control_url: &str, path: &str) -> Result<(), AnyError> {
    reqwest::Client::builder()
        .no_proxy()
        .build()?
        .post(format!("{control_url}{path}"))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn read_connection(path: &Path) -> Result<ConnectionInfo, AnyError> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    Ok(ConnectionInfo {
        etcd_endpoint: value["etcd_endpoint"]
            .as_str()
            .ok_or("missing etcd_endpoint")?
            .to_owned(),
        control_url: value["control_url"]
            .as_str()
            .ok_or("missing control_url")?
            .to_owned(),
    })
}

fn require(condition: bool, message: &'static str) -> Result<(), AnyError> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
