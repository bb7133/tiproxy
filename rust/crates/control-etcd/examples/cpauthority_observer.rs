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

//! Live retained-authority observations against the CP-ETCD embedded fixture.

use std::error::Error;
use std::time::Duration;

use control_etcd::{ElectionConfig, ElectionSession, ElectionState, RecoveryOutcome};
use control_external::{EtcdClientConfig, EtcdConnector};
use control_plane::{OwnerScope, OwnerToken, OwnershipRegistry};
use serde_json::Value;
use tokio::time::Instant;

type AnyError = Box<dyn Error + Send + Sync>;

struct Fixture {
    direct: String,
    proxy: String,
    control: String,
    http: reqwest::Client,
}

impl Fixture {
    async fn post(&self, path: &str) -> Result<(), AnyError> {
        self.http
            .post(format!("{}{path}", self.control))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn state(&self) -> Result<Value, AnyError> {
        Ok(serde_json::from_slice(
            &self
                .http
                .get(format!("{}/cleanup-state", self.control))
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?,
        )?)
    }
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let file = std::env::var("CP003_CONNECTION_FILE")?;
    let value: Value = serde_json::from_slice(&std::fs::read(file)?)?;
    let fixture = Fixture {
        direct: value["etcd_endpoint"]
            .as_str()
            .ok_or("direct endpoint")?
            .into(),
        proxy: value["proxy_endpoint"]
            .as_str()
            .ok_or("proxy endpoint")?
            .into(),
        control: value["control_url"].as_str().ok_or("control URL")?.into(),
        http: reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?,
    };
    tokio::time::timeout(Duration::from_secs(50), Box::pin(observe(&fixture))).await??;
    println!("CP-AUTHORITY all live rows passed");
    Ok(())
}

async fn observe(fixture: &Fixture) -> Result<(), AnyError> {
    let registry = OwnershipRegistry::new();
    let owner = registry.claim(OwnerScope::Process, "cp-authority")?;
    Box::pin(transient_retirement(fixture, &owner.token())).await?;
    Box::pin(held_cleanup(fixture, &owner.token(), "Resign")).await?;
    Box::pin(held_cleanup(fixture, &owner.token(), "LeaseRevoke")).await?;
    Box::pin(canceled_shutdown(fixture, &owner.token())).await?;
    Box::pin(drop_paths(fixture, &owner.token())).await?;
    let session = session(&owner.token(), &fixture.direct, "process").await?;
    let authority = session.authority();
    let permit = authority.capture_work().ok_or("initial work permit")?;
    drop(owner);
    ensure(
        !authority.retains_local_ownership()
            && authority.capture_work().is_none()
            && !permit.still_current()
            && permit.with_current(|| 1).is_none(),
        "original-process-owner",
    )?;
    drop(session);
    Ok(())
}

async fn transient_retirement(fixture: &Fixture, owner: &OwnerToken) -> Result<(), AnyError> {
    let mut session = session(owner, &fixture.direct, "transient").await?;
    let authority = session.authority();
    let permit = authority.capture_work().ok_or("initial work permit")?;
    let initial = session.snapshot();
    // No state watch is polled during these authority checks.
    let mut watch = session.subscribe();
    fixture.post("/stop").await?;
    ensure(session.keep_alive().await.is_err(), "outage-observed")?;
    ensure(
        authority.retains_local_ownership()
            && authority.capture_work().is_none()
            && !permit.still_current(),
        "uncertain-revokes-work-only",
    )?;
    ensure(
        permit.with_current(|| 1).is_none(),
        "uncertain-publication-rejected",
    )?;
    fixture.post("/start").await?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if matches!(session.recover().await, Ok(RecoveryOutcome::Restored)) {
            break;
        }
        ensure(Instant::now() < deadline, "same-session-recovery")?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let recovered = session.snapshot();
    ensure(
        initial.lease_id == recovered.lease_id
            && initial.session_revision == recovered.session_revision,
        "same-lease-and-revision",
    )?;
    ensure(
        authority.retains_local_ownership()
            && !permit.still_current()
            && permit.with_current(|| 1).is_none(),
        "recovery-does-not-revive-permit",
    )?;
    let fresh = authority.capture_work().ok_or("fresh recovered permit")?;
    ensure(
        fresh.still_current() && fresh.with_current(|| 7) == Some(7),
        "recovery-mints-fresh-permit",
    )?;
    fixture
        .post(&format!("/revoke?lease={}", initial.lease_id))
        .await?;
    ensure(
        matches!(session.recover().await?, RecoveryOutcome::Retired(_)),
        "definitive-retirement-observed",
    )?;
    ensure(
        !authority.retains_local_ownership()
            && !fresh.still_current()
            && fresh.with_current(|| 1).is_none(),
        "retirement-without-watch-consumer",
    )?;
    ensure(
        watch.borrow_and_update().state == ElectionState::Retired,
        "retirement-diagnostic",
    )?;
    ensure(
        matches!(session.recover().await?, RecoveryOutcome::Retired(_))
            && authority.capture_work().is_none(),
        "terminal-session-does-not-reopen",
    )?;
    Ok(())
}

async fn held_cleanup(fixture: &Fixture, owner: &OwnerToken, method: &str) -> Result<(), AnyError> {
    let session = session(owner, &fixture.proxy, method).await?;
    let lease = session.snapshot().lease_id;
    let authority = session.authority();
    let permit = authority.capture_work().ok_or("cleanup permit")?;
    fixture.post(&format!("/hold-cleanup?rpc={method}")).await?;
    let shutdown = tokio::spawn(session.shutdown());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if fixture.state().await?["entered"] == true {
            break;
        }
        if shutdown.is_finished() {
            // A skipped cleanup is rejected by the real retained lease/key,
            // rather than counting a wait timeout as the mutation's evidence.
            ensure(
                !lease_exists(owner, &fixture.direct, lease).await?,
                "remote-cleanup-removes-lease",
            )?;
            return Err("cleanup RPC did not enter its real hold".into());
        }
        ensure(Instant::now() < deadline, "cleanup-hold-entered")?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    ensure(
        !shutdown.is_finished() && owner.is_current(),
        "held-cleanup-same-process",
    )?;
    ensure(
        !authority.retains_local_ownership()
            && authority.capture_work().is_none()
            && !permit.still_current()
            && permit.with_current(|| 1).is_none(),
        "shutdown-revokes-before-rpc-release",
    )?;
    fixture.post("/release-cleanup").await?;
    shutdown.await??;
    ensure(
        !lease_exists(owner, &fixture.direct, lease).await?,
        "remote-cleanup-removes-lease",
    )?;
    let completed = fixture.state().await?;
    ensure(
        completed["completed"]["Resign"].as_u64().unwrap_or(0) > 0
            && completed["completed"]["LeaseRevoke"].as_u64().unwrap_or(0) > 0,
        "both-cleanup-rpcs-completed",
    )?;
    println!("CP-AUTHORITY held {method} passed");
    Ok(())
}

async fn canceled_shutdown(fixture: &Fixture, owner: &OwnerToken) -> Result<(), AnyError> {
    let session = session(owner, &fixture.proxy, "cancel-shutdown").await?;
    let lease = session.snapshot().lease_id;
    let authority = session.authority();
    let permit = authority.capture_work().ok_or("cancel permit")?;
    fixture.post("/hold-cleanup?rpc=LeaseRevoke").await?;
    let shutdown = tokio::spawn(session.shutdown());
    let deadline = Instant::now() + Duration::from_secs(3);
    while fixture.state().await?["entered"] != true {
        ensure(
            !shutdown.is_finished() && Instant::now() < deadline,
            "canceled-shutdown-hold-entered",
        )?;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    shutdown.abort();
    ensure(
        shutdown.await.is_err()
            && !authority.retains_local_ownership()
            && authority.capture_work().is_none()
            && !permit.still_current()
            && permit.with_current(|| 1).is_none(),
        "polled-shutdown-cancellation-revokes",
    )?;
    // Drop performs no I/O. The actual lease is still present while its revoke
    // is held; the fixture removes it after the cancellation evidence is read.
    ensure(
        lease_exists(owner, &fixture.direct, lease).await?,
        "canceled-cleanup-left-remote-lease",
    )?;
    fixture.post("/release-cleanup").await?;
    fixture.post(&format!("/revoke?lease={lease}")).await?;
    Ok(())
}

async fn drop_paths(fixture: &Fixture, owner: &OwnerToken) -> Result<(), AnyError> {
    let direct = session(owner, &fixture.direct, "drop").await?;
    let authority = direct.authority();
    let permit = authority.capture_work().ok_or("drop permit")?;
    drop(direct);
    ensure(
        !authority.retains_local_ownership() && !permit.still_current(),
        "session-drop-revokes",
    )?;

    let unpolled = session(owner, &fixture.direct, "unpolled").await?;
    let authority = unpolled.authority();
    let future = unpolled.shutdown();
    ensure(
        authority.retains_local_ownership(),
        "unpolled-shutdown-has-not-entered",
    )?;
    drop(future);
    ensure(
        !authority.retains_local_ownership(),
        "unpolled-shutdown-drop-revokes",
    )?;

    let aborted = session(owner, &fixture.direct, "abort").await?;
    let authority = aborted.authority();
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
        drop(aborted);
    });
    task.abort();
    ensure(
        task.await.is_err() && !authority.retains_local_ownership(),
        "aborted-task-drop-revokes",
    )?;
    Ok(())
}

async fn session(
    owner: &OwnerToken,
    endpoint: &str,
    name: &str,
) -> Result<ElectionSession, AnyError> {
    let root = format!("/tiproxy/cpauthority/{}/{name}", std::process::id());
    Ok(ElectionSession::campaign(
        owner.clone(),
        client(endpoint)?,
        ElectionConfig::new(
            format!("{root}/election"),
            "owner",
            format!("{root}/session"),
            15,
        )?,
    )
    .await?)
}

fn client(endpoint: &str) -> Result<EtcdClientConfig, AnyError> {
    Ok(
        EtcdClientConfig::new([endpoint.to_owned()], None)?.with_timeouts(
            Duration::from_millis(500),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_millis(500),
            Duration::from_secs(1),
        )?,
    )
}

async fn lease_exists(owner: &OwnerToken, endpoint: &str, lease: i64) -> Result<bool, AnyError> {
    let mut connection = EtcdConnector::new(owner.clone(), client(endpoint)?)
        .connect()
        .await?;
    Ok(connection
        .execute(move |client| Box::pin(client.lease_time_to_live(lease, None)))
        .await?
        .ttl()
        > 0)
}

fn ensure(condition: bool, row: &'static str) -> Result<(), AnyError> {
    if condition {
        Ok(())
    } else {
        Err(format!("CP-AUTHORITY row failed: {row}").into())
    }
}
