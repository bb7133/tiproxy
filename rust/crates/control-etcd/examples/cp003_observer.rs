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

//! Runs CP-ETCD against a restartable embedded etcd dependency.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use control_etcd::{
    ElectionConfig, ElectionError, ElectionSession, ElectionSnapshot, ElectionState,
    RecoveryOutcome, RetirementReason, WatchOutcome,
};
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{OwnerScope, OwnerToken, OwnershipRegistry};
use serde_json::{Value, json};

type AnyError = Box<dyn std::error::Error>;

#[derive(Clone)]
struct ConnectionInfo {
    etcd_endpoint: String,
    control_url: String,
}

struct ScenarioEvidence {
    initial_lease: i64,
    initial_revision: i64,
    recovered_revision: i64,
    retry_count: u64,
    successor_lease: i64,
    successor_revision: i64,
    compaction_recoveries: u64,
    process_death_expired: bool,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let connection_path = std::env::var("CP003_CONNECTION_FILE")?;
    let connection = read_connection(Path::new(&connection_path))?;
    if std::env::var_os("CP003_OWNER_CHILD").is_some() {
        return Box::pin(run_owner_child(connection)).await;
    }

    let registry = OwnershipRegistry::new();
    let process_lease = registry.claim(OwnerScope::Process, "cp003-parent")?;
    let owner = process_lease.token();
    let client_config = client_config(&connection)?;
    let evidence = Box::pin(run_scenarios(&owner, &client_config, &connection)).await?;
    emit_observations(&evidence);
    drop(process_lease);
    Ok(())
}

async fn run_scenarios(
    owner: &OwnerToken,
    client_config: &EtcdClientConfig,
    connection: &ConnectionInfo,
) -> Result<ScenarioEvidence, AnyError> {
    let (mut session, initial, recovered) =
        Box::pin(transient_and_compaction(owner, client_config, connection)).await?;

    let successor_config = election_config("member-B", "member-B", 2)?;
    let successor =
        ElectionSession::campaign(owner.clone(), client_config.clone(), successor_config);
    tokio::pin!(successor);
    let waiting_deadline = Instant::now() + Duration::from_millis(2_500);
    while Instant::now() < waiting_deadline {
        tokio::select! {
            result = &mut successor => {
                let _unexpected_leader = result?;
                return Err("successor acquired leadership before predecessor retirement".into());
            }
            () = tokio::time::sleep(Duration::from_millis(400)) => {
                require(
                    session.keep_alive().await? == RecoveryOutcome::Restored
                        && session.snapshot().state == ElectionState::Leader,
                    "predecessor did not stay leader while successor waited",
                )?;
            }
        }
    }

    let revoke_path = format!("/revoke?lease={}", initial.lease_id);
    post_control(&connection.control_url, &revoke_path).await?;
    let retired = session.recover().await?;
    require(
        retired == RecoveryOutcome::Retired(RetirementReason::LeaseNotFound)
            && session.snapshot().state == ElectionState::Retired
            && !session.snapshot().retains_local_ownership(),
        "revoked lease did not retire before successor ownership",
    )?;
    require(
        !key_exists(owner, client_config, "/tiproxy/cp003/session/member-A").await?,
        "lease-attached session key survived revocation",
    )?;
    require(
        session.recover().await? == retired && session.keep_alive().await? == retired,
        "definitively retired session was not monotonic",
    )?;

    let successor = tokio::time::timeout(Duration::from_secs(8), &mut successor).await??;
    let successor_snapshot = Box::pin(validate_successor(
        successor,
        owner,
        client_config,
        &initial,
    ))
    .await?;
    let process_death_expired = prove_process_death(owner, client_config).await?;
    require(
        process_death_expired,
        "process death did not expire the ephemeral session key",
    )?;

    Ok(ScenarioEvidence {
        initial_lease: initial.lease_id,
        initial_revision: initial.session_revision,
        recovered_revision: recovered.observed_revision,
        retry_count: recovered.retry_count,
        successor_lease: successor_snapshot.lease_id,
        successor_revision: successor_snapshot.session_revision,
        compaction_recoveries: session.snapshot().compaction_recoveries,
        process_death_expired,
    })
}

async fn transient_and_compaction(
    owner: &OwnerToken,
    client_config: &EtcdClientConfig,
    connection: &ConnectionInfo,
) -> Result<(ElectionSession, ElectionSnapshot, ElectionSnapshot), AnyError> {
    let config = election_config("member-A", "member-A", 2)?;
    let mut session =
        ElectionSession::campaign(owner.clone(), client_config.clone(), config).await?;
    let initial = session.snapshot();
    require(
        initial.state == ElectionState::Leader
            && initial.lease_id != 0
            && initial.session_revision > 0,
        "initial Rust election was not a confirmed leader",
    )?;

    post_control(&connection.control_url, "/stop").await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    require(
        session.keep_alive().await.is_err(),
        "stopped etcd did not interrupt keepalive",
    )?;
    let uncertain = session.snapshot();
    require(
        uncertain.state == ElectionState::Uncertain
            && uncertain.retains_local_ownership()
            && !uncertain.may_commit_owner_work()
            && uncertain.retirement_reason.is_none(),
        "transient outage crossed or bypassed the retirement fence",
    )?;
    require(
        matches!(
            session
                .fenced_put("/tiproxy/cp003/blocked", "blocked")
                .await,
            Err(ElectionError::NotLeader)
        ),
        "uncertain owner committed a new owner-only transaction",
    )?;

    post_control(&connection.control_url, "/start").await?;
    let recovered = recover_until_ready(&mut session).await?;
    require(
        recovered.lease_id == initial.lease_id
            && recovered.session_revision == initial.session_revision
            && recovered.observed_revision >= initial.observed_revision
            && recovered.state == ElectionState::Leader,
        "transient recovery changed the exact lease or leader revision",
    )?;

    post_control(&connection.control_url, "/bump-compact").await?;
    session.resume_watch().await?;
    let watch_outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let outcome = session.watch_once().await?;
            if outcome != WatchOutcome::Progress {
                return Ok::<_, ElectionError>(outcome);
            }
        }
    })
    .await??;
    require(
        watch_outcome == WatchOutcome::CompactionRecovered
            && session.snapshot().compaction_recoveries == 1
            && session.snapshot().state == ElectionState::Leader,
        "compacted watch did not relist and resume without false retirement",
    )?;
    Ok((session, initial, recovered))
}

async fn validate_successor(
    mut successor: ElectionSession,
    owner: &OwnerToken,
    client_config: &EtcdClientConfig,
    initial: &ElectionSnapshot,
) -> Result<ElectionSnapshot, AnyError> {
    let successor_snapshot = successor.snapshot();
    require(
        successor_snapshot.state == ElectionState::Leader
            && successor_snapshot.lease_id != initial.lease_id
            && successor_snapshot.session_revision > initial.session_revision,
        "successor did not acquire a new monotonic lease/revision",
    )?;
    successor
        .fenced_put("/tiproxy/cp003/owner-only", "committed")
        .await?;
    require(
        key_exists(owner, client_config, "/tiproxy/cp003/owner-only").await?,
        "confirmed leader transaction was not committed",
    )?;
    successor.shutdown().await?;
    Ok(successor_snapshot)
}

async fn recover_until_ready(session: &mut ElectionSession) -> Result<ElectionSnapshot, AnyError> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match session.recover().await {
            Ok(RecoveryOutcome::Restored) => return Ok(session.snapshot()),
            Ok(RecoveryOutcome::Retired(reason)) => {
                return Err(
                    format!("session retired during transient recovery: {reason:?}").into(),
                );
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn prove_process_death(
    owner: &OwnerToken,
    client_config: &EtcdClientConfig,
) -> Result<bool, AnyError> {
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .env("CP003_OWNER_CHILD", "1")
        .env(
            "CP003_CONNECTION_FILE",
            std::env::var("CP003_CONNECTION_FILE")?,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing owner-child stdout")?;
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader.read_line(&mut ready)?;
    let ready: Value = serde_json::from_str(&ready)?;
    require(ready["ready"] == true, "owner child did not become ready")?;
    let session_key = ready["session_key"]
        .as_str()
        .ok_or("owner child omitted session key")?;
    require(
        key_exists(owner, client_config, session_key).await?,
        "owner-child ephemeral key was absent before process death",
    )?;
    child.kill()?;
    let _ = child.wait()?;

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if !key_exists(owner, client_config, session_key).await? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn run_owner_child(connection: ConnectionInfo) -> Result<(), AnyError> {
    let registry = OwnershipRegistry::new();
    let process_lease = registry.claim(OwnerScope::Process, "cp003-child")?;
    let client_config = client_config(&connection)?;
    let session_key = "/tiproxy/cp003/process-death/session";
    let config = ElectionConfig::new(
        "/tiproxy/cp003/process-death/election",
        "process-child",
        session_key,
        2,
    )?;
    let mut session =
        ElectionSession::campaign(process_lease.token(), client_config, config).await?;
    println!("{}", json!({"ready": true, "session_key": session_key}));
    std::io::stdout().flush()?;
    loop {
        tokio::time::sleep(Duration::from_millis(400)).await;
        match session.keep_alive().await {
            Ok(RecoveryOutcome::Restored) => {}
            Ok(RecoveryOutcome::Retired(reason)) => {
                return Err(format!("owner child retired unexpectedly: {reason:?}").into());
            }
            Err(_) => {
                let _ = session.recover().await?;
            }
        }
    }
}

fn election_config(
    member_id: &str,
    session_suffix: &str,
    ttl: i64,
) -> Result<ElectionConfig, control_etcd::ElectionConfigError> {
    ElectionConfig::new(
        "/tiproxy/cp003/election",
        member_id,
        format!("/tiproxy/cp003/session/{session_suffix}"),
        ttl,
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

async fn key_exists(
    owner: &OwnerToken,
    client_config: &EtcdClientConfig,
    key: &str,
) -> Result<bool, AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), client_config.clone())
        .connect()
        .await?;
    let key = key.as_bytes().to_vec();
    let response = connection
        .execute(move |client| Box::pin(client.get(key, None)))
        .await?;
    Ok(!response.kvs().is_empty())
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

fn emit_observations(evidence: &ScenarioEvidence) {
    let transient_state = if std::env::var_os("CP003_MUTATE_TRANSIENT_RETIRE").is_some() {
        "retired"
    } else {
        "leader"
    };
    let successor_lease_changed = if std::env::var_os("CP003_MUTATE_LEASE_REUSE").is_some() {
        0
    } else {
        i64::from(evidence.successor_lease != evidence.initial_lease)
    };
    println!(
        "{}",
        json!({
            "schema_version": 1,
            "producer": "rust",
            "observations": [
                {
                    "scenario_id": "CP-FAULT-ETCD-TRANSIENT",
                    "step": 0,
                    "contracts": ["CP-ELECT-001"],
                    "subject": {"namespace": "process", "cluster": "loopback", "generation": 1},
                    "outcome": "recovered",
                    "effects": ["no_false_retirement", "owner_identity_retained", "revision_monotonic"],
                    "state": [
                        {"key": "lease_id", "value": "retained"},
                        {"key": "owner_id", "value": "member-A"},
                        {"key": "owner_state", "value": transient_state},
                        {"key": "retirement_reason", "value": "none"},
                        {"key": "session_revision", "value": "retained"}
                    ],
                    "counters": [
                        {"key": "lease_id_present", "value": i64::from(evidence.initial_lease != 0)},
                        {"key": "retry_count", "value": i64::try_from(evidence.retry_count).unwrap_or(i64::MAX)},
                        {"key": "revision_monotonic", "value": i64::from(evidence.recovered_revision >= evidence.initial_revision)}
                    ]
                },
                {
                    "scenario_id": "CP-FAULT-LEASE-LOSS",
                    "step": 0,
                    "contracts": ["CP-ELECT-001"],
                    "subject": {"namespace": "process", "cluster": "loopback", "generation": 2},
                    "outcome": "transferred",
                    "effects": ["ephemeral_key_removed", "old_owner_retired_first", "single_successor_elected"],
                    "state": [
                        {"key": "lease_id", "value": "renewed"},
                        {"key": "owner_id", "value": "member-B"},
                        {"key": "owner_state", "value": "leader"},
                        {"key": "retirement_reason", "value": "lease_not_found"},
                        {"key": "session_revision", "value": "monotonic"}
                    ],
                    "counters": [
                        {"key": "active_owner_count", "value": 1},
                        {"key": "lease_changed", "value": successor_lease_changed},
                        {"key": "revision_monotonic", "value": i64::from(evidence.successor_revision > evidence.initial_revision)}
                    ]
                },
                {
                    "scenario_id": "CP-FAULT-ELECTION-WATCH-COMPACTION",
                    "step": 0,
                    "contracts": ["CP-ELECT-001"],
                    "subject": {"namespace": "process", "cluster": "loopback", "generation": 1},
                    "outcome": "resumed",
                    "effects": ["fresh_leader_relisted", "owner_identity_retained", "watch_revision_advanced"],
                    "state": [
                        {"key": "owner_id", "value": "member-A"},
                        {"key": "owner_state", "value": "leader"},
                        {"key": "retirement_reason", "value": "none"}
                    ],
                    "counters": [
                        {"key": "compaction_recoveries", "value": i64::try_from(evidence.compaction_recoveries).unwrap_or(i64::MAX)}
                    ]
                },
                {
                    "scenario_id": "CP-FAULT-ETCD-PROCESS-DEATH",
                    "step": 0,
                    "contracts": ["CP-ELECT-001"],
                    "subject": {"namespace": "process", "cluster": "loopback", "generation": 2},
                    "outcome": "expired",
                    "effects": ["ephemeral_key_removed", "process_killed", "ttl_enforced"],
                    "state": [{"key": "owner_state", "value": "retired"}],
                    "counters": [{"key": "ephemeral_key_present", "value": i64::from(!evidence.process_death_expired)}]
                }
            ]
        })
    );
}

fn require(condition: bool, message: &'static str) -> Result<(), AnyError> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
