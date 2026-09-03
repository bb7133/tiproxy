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

//! Discriminating reconcile tests for [`control_topology::TopologyModule`].
//!
//! These drive the real module over a `ConfigNamespaceStore` (no etcd) and
//! observe the status watch, so a rejected generation is provably distinct from
//! an applied one and always retains the last-good `applied_generation`. The
//! rebuild-vs-no-flap lease discrimination that needs live etcd is covered by
//! the embedded-etcd integration instead.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use control_config::{ConfigNamespaceStore, TopologyConfig, TopologyRuntimeIdentity};
use control_external::EtcdClientConfig;
use control_plane::{
    ControlConfig, ControlModule, ControlRuntime, EventSink, LifecyclePhase, LogLevel,
    MetricsPolicy, OwnershipRegistry, RuntimeEvent, ShutdownReason, TlsPolicy,
};
use control_topology::{
    RejectionClass, StaticAdvertiseResolver, TopologyClientFactory, TopologyClusterClient,
    TopologyModule, TopologyStatus,
};
use tokio::sync::watch;

type AnyError = Box<dyn std::error::Error>;

/// Factory build behaviour, switchable between generations by the test.
const MODE_MATCH: usize = 0;
const MODE_MISMATCH: usize = 1;
const MODE_DUPLICATE: usize = 2;
const MODE_BUILD_FAIL: usize = 3;

struct SwitchableFactory {
    mode: Arc<AtomicUsize>,
}

impl TopologyClientFactory for SwitchableFactory {
    fn build(&self, config: &TopologyConfig) -> Result<Vec<TopologyClusterClient>, String> {
        let client = || {
            EtcdClientConfig::new(["127.0.0.1:1".to_owned()], None)
                .unwrap_or_else(|_| unreachable!("static endpoint is valid"))
        };
        let names: Vec<Arc<str>> = match self.mode.load(Ordering::SeqCst) {
            MODE_MATCH => config
                .backend_clusters
                .iter()
                .map(|cluster| Arc::clone(&cluster.name))
                .collect(),
            MODE_MISMATCH => vec![Arc::from("unexpected-cluster")],
            MODE_DUPLICATE => {
                let name = Arc::clone(&config.backend_clusters[0].name);
                vec![Arc::clone(&name), name]
            }
            _ => return Err("factory build failed".to_owned()),
        };
        Ok(names
            .into_iter()
            .map(|name| TopologyClusterClient {
                cluster_name: name,
                client: client(),
            })
            .collect())
    }
}

struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &RuntimeEvent) {}
}

/// A config with two backend clusters. `max_connections` is a hot-reloadable
/// field, so varying it publishes a new generation without touching the
/// reload-locked addr/advertise/pd/ha fields.
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

[[proxy.backend-clusters]]
name = "cluster-b"
pd-addrs = "pd-b:2379"
ns-servers = ["dns-b:53"]
"#
    )
    .into_bytes()
}

fn identity() -> TopologyRuntimeIdentity {
    TopologyRuntimeIdentity {
        version: Arc::from("v-test"),
        git_hash: Arc::from("hash-test"),
        deploy_path: PathBuf::from("/deploy/test"),
        start_timestamp: 1_700_000_000,
    }
}

async fn wait_for_observed(
    status: &mut watch::Receiver<TopologyStatus>,
    generation: u64,
) -> Result<TopologyStatus, AnyError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let current = *status.borrow_and_update();
            if current.observed_generation >= generation {
                return Ok(current);
            }
        }
        tokio::time::timeout(deadline - tokio::time::Instant::now(), status.changed()).await??;
    }
}

/// Drives a good generation 1, switches the factory to `gen2_mode`, publishes a
/// second generation, and returns the observed status after it is consumed.
async fn run_two_generations(gen2_mode: usize) -> Result<TopologyStatus, AnyError> {
    let store = ConfigNamespaceStore::from_toml(&config_gen(100), None, &current_dir()?)?;
    let factory_mode = Arc::new(AtomicUsize::new(MODE_MATCH));
    let (module, mut handle) = TopologyModule::new(
        Arc::new(store.clone()),
        Box::new(SwitchableFactory {
            mode: Arc::clone(&factory_mode),
        }),
        Arc::new(StaticAdvertiseResolver::new("10.0.0.1")),
        identity(),
    );

    let registry = OwnershipRegistry::new();
    let runtime = ControlRuntime::claim_process(
        &registry,
        "cptopo-reconcile",
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
    let context = runtime.handle().module_context();
    runtime.mark_ready()?;
    let mut module_task = tokio::spawn(Box::new(module).run(context));

    tokio::select! {
        ready = handle.wait_ready() => { ready?; }
        joined = &mut module_task => {
            return Err(format!("module exited before ready: {joined:?}").into());
        }
        () = tokio::time::sleep(Duration::from_secs(5)) => {
            return Err("timed out waiting for module ready".into());
        }
    }
    let mut status = handle.status();
    let applied = *status.borrow_and_update();
    assert_eq!(
        applied.observed_generation, 1,
        "initial generation observed"
    );
    assert_eq!(applied.applied_generation, 1, "initial generation applied");
    assert_eq!(applied.last_rejection, None, "clean start");

    // Switch the factory behaviour, then publish a new generation.
    factory_mode.store(gen2_mode, Ordering::SeqCst);
    store.apply_toml(&config_gen(200), None, 2, &current_dir()?)?;

    let after = wait_for_observed(&mut status, 2).await?;

    runtime.begin_shutdown(ShutdownReason::Requested)?;
    let _ = tokio::time::timeout(Duration::from_secs(10), module_task).await;
    runtime.advance_shutdown(LifecyclePhase::Draining)?;
    runtime.advance_shutdown(LifecyclePhase::Stopping)?;
    runtime.finish()?;
    Ok(after)
}

async fn assert_rejected(gen2_mode: usize, expected: RejectionClass) -> Result<(), AnyError> {
    let after = run_two_generations(gen2_mode).await?;
    assert_eq!(after.observed_generation, 2, "second generation observed");
    assert_eq!(
        after.applied_generation, 1,
        "rejected generation retains the last-good applied generation"
    );
    assert_eq!(
        after.last_rejection,
        Some(expected),
        "the rejection class is reported"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_set_mismatch_is_rejected_and_retains_last_good() -> Result<(), AnyError> {
    assert_rejected(MODE_MISMATCH, RejectionClass::ClusterSetMismatch).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_cluster_name_is_rejected_and_retains_last_good() -> Result<(), AnyError> {
    assert_rejected(MODE_DUPLICATE, RejectionClass::DuplicateClusterName).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_failure_is_rejected_and_retains_last_good() -> Result<(), AnyError> {
    assert_rejected(MODE_BUILD_FAIL, RejectionClass::ClientBuildFailed).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_generation_advances_applied_without_rejection() -> Result<(), AnyError> {
    // A well-formed later generation (an unrelated hot-reload) is consumed: it
    // advances applied_generation and never sets a rejection.
    let after = run_two_generations(MODE_MATCH).await?;
    assert_eq!(after.observed_generation, 2, "second generation observed");
    assert_eq!(
        after.applied_generation, 2,
        "accepted generation is applied"
    );
    assert_eq!(
        after.last_rejection, None,
        "no rejection on an accepted generation"
    );
    Ok(())
}

fn current_dir() -> Result<PathBuf, AnyError> {
    Ok(std::env::current_dir()?)
}
