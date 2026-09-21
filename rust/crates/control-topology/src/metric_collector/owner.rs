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

//! A scoped election task and retained local/observed-peer provenance.

use super::{
    Arc, Duration, GenerationGate, MetricCapture, Mutex, PoisonError, Shared, service, watch,
};
use crate::metric_owner::{PeerSet, election_name};
use crate::owner_metrics::ElectionOwnerHistory;
use control_etcd::{ElectionAuthority, ElectionConfig, ElectionSession, ElectionState};
use control_external::IoFence;

pub(super) struct Scope {
    capture: MetricCapture,
    serving: Arc<service::Binding>,
    gate: GenerationGate,
    boundary: Mutex<()>,
    external_stop: watch::Receiver<bool>,
}
impl IoFence for Scope {
    fn is_live(&self) -> bool {
        self.gate.is_live()
            && !*self.external_stop.borrow()
            && self.capture.still_current()
            && self.serving.is_live()
    }
}

impl Scope {
    fn with_current<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let _guard = self.boundary.lock().unwrap_or_else(PoisonError::into_inner);
        // Hold the stop watch read guard through the synchronous boundary too.
        let stop = self.external_stop.borrow();
        (self.gate.is_live() && !*stop && self.capture.still_current() && self.serving.is_live())
            .then(action)
    }
    fn revoke(&self) {
        let _guard = self.boundary.lock().unwrap_or_else(PoisonError::into_inner);
        self.gate.revoke();
    }
}

pub(super) struct LocalOwner {
    pub authority: ElectionAuthority,
    // Only an additional negative consistency check against locally observed
    // etcd records. These diagnostics can never grant authority or mint work.
    lease: i64,
    created: i64,
    member: Vec<u8>,
}
impl LocalOwner {
    pub fn from_session(session: &ElectionSession) -> Arc<Self> {
        let snapshot = session.snapshot();
        Arc::new(Self {
            authority: session.authority(),
            lease: snapshot.lease_id,
            created: snapshot.session_revision,
            member: snapshot.member_id,
        })
    }
    pub fn matches_observation(&self, cluster: &str, zone: &str, peers: &PeerSet) -> bool {
        peers.members.get(zone).is_some_and(|record| {
            record.lease == self.lease
                && record.created == self.created
                && record.value == self.member
                && record.key
                    == format!("{}/{:x}", election_name(cluster, zone), self.lease).as_bytes()
        })
    }
}
#[derive(Clone)]
pub(super) enum Proof {
    Local(Arc<LocalOwner>),
    Peer(Arc<PeerSet>),
    Scope(Arc<Scope>),
    Role(Arc<RoleCapture>),
}
impl Proof {
    pub fn is_live(&self) -> bool {
        match self {
            Self::Local(owner) => owner.authority.retains_local_ownership(),
            Self::Peer(peer) => peer.is_live(),
            Self::Scope(scope) => scope.is_live(),
            Self::Role(role) => role.is_live(),
        }
    }
    pub fn is_local(&self, local: &Arc<LocalOwner>) -> bool {
        matches!(self, Self::Local(owner) if Arc::ptr_eq(owner, local))
    }
}
pub(super) fn with_retained<T>(proofs: &[&Proof], action: impl FnOnce() -> T) -> Option<T> {
    match proofs.split_first() {
        None => Some(action()),
        Some((Proof::Local(owner), remaining)) => owner
            .authority
            .with_retained(|| with_retained(remaining, action))
            .flatten(),
        Some((Proof::Peer(peer), remaining)) => peer
            .with_current(|| with_retained(remaining, action))
            .flatten(),
        Some((Proof::Scope(scope), remaining)) => scope
            .with_current(|| with_retained(remaining, action))
            .flatten(),
        Some((Proof::Role(role), remaining)) => role
            .with_current(|| with_retained(remaining, action))
            .flatten(),
    }
}

pub(super) struct RoleCapture {
    receiver: watch::Receiver<Option<Arc<LocalOwner>>>,
    pub captured: Option<Arc<LocalOwner>>,
}
impl RoleCapture {
    fn with_current<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let current = self.receiver.borrow();
        (self.receiver.has_changed().is_ok()
            && same_local(self.captured.as_ref(), current.as_ref()))
        .then(action)
    }
    pub fn is_live(&self) -> bool {
        self.receiver.has_changed().is_ok()
            && same_local(self.captured.as_ref(), self.receiver.borrow().as_ref())
    }
}
pub(super) fn same_local(
    first: Option<&Arc<LocalOwner>>,
    second: Option<&Arc<LocalOwner>>,
) -> bool {
    match (first, second) {
        (None, None) => true,
        (Some(first), Some(second)) => Arc::ptr_eq(first, second),
        _ => false,
    }
}
struct ScopeGuard(Arc<Scope>);
impl Drop for ScopeGuard {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

pub(super) struct OwnerWorker {
    scope: Arc<Scope>,
    shutdown: watch::Sender<bool>,
    current: watch::Receiver<Option<Arc<LocalOwner>>>,
    task: Option<tokio::task::JoinHandle<()>>,
    pub zone: String,
}
impl OwnerWorker {
    pub fn start(
        shared: &Shared,
        capture: MetricCapture,
        cluster: String,
        zone: String,
        external_stop: watch::Receiver<bool>,
    ) -> Self {
        let scope = Arc::new(Scope {
            capture,
            serving: Arc::clone(&shared.serving),
            gate: GenerationGate::new(),
            boundary: Mutex::new(()),
            external_stop,
        });
        let (shutdown, stop) = watch::channel(false);
        let (current, receiver) = watch::channel(None);
        let active = Arc::clone(&scope);
        let scoped_zone = zone.clone();
        let owner_history = shared.owner_history();
        let task = tokio::spawn(async move {
            Box::pin(run(
                active,
                cluster,
                scoped_zone,
                stop,
                current,
                owner_history,
            ))
            .await;
        });
        Self {
            scope,
            shutdown,
            current: receiver,
            task: Some(task),
            zone,
        }
    }
    pub fn capture_role(&self) -> Arc<RoleCapture> {
        Arc::new(RoleCapture {
            receiver: self.current.clone(),
            captured: self.current.borrow().clone(),
        })
    }
    pub fn is_finished(&self) -> bool {
        self.task
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }
    pub fn scope(&self) -> Arc<Scope> {
        Arc::clone(&self.scope)
    }
    pub async fn restart(
        &mut self,
        shared: &Shared,
        capture: MetricCapture,
        cluster: String,
        zone: String,
    ) {
        let external_stop = self.scope.external_stop.clone();
        self.retire().await;
        *self = Self::start(shared, capture, cluster, zone, external_stop);
    }
    pub async fn stop(mut self) {
        self.retire().await;
    }
    async fn retire(&mut self) {
        self.scope.revoke();
        self.shutdown.send_replace(true);
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(Duration::from_secs(30), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for OwnerWorker {
    fn drop(&mut self) {
        self.scope.revoke();
        self.shutdown.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run(
    scope: Arc<Scope>,
    cluster: String,
    zone: String,
    mut stop: watch::Receiver<bool>,
    current: watch::Sender<Option<Arc<LocalOwner>>>,
    owner_history: Option<Arc<ElectionOwnerHistory>>,
) {
    let _guard = ScopeGuard(Arc::clone(&scope));
    let address = scope.serving.address.to_string();
    let presence = format!(
        "/tiproxy/metric_sessions/{}/{}/{}",
        service::encode_query(&address),
        service::encode_query(&cluster),
        service::encode_query(&zone)
    );
    // Kept alongside the config because `ElectionConfig` does not expose the
    // name back, and this is the exact key `server_owner` labels with.
    let election_key = election_name(&cluster, &zone);
    let Ok(config) = ElectionConfig::new(election_key.clone(), address, presence, 15) else {
        return;
    };
    while scope.is_live() && !*stop.borrow() {
        let started = tokio::select! {
            biased;
            _ = stop.changed() => break,
            result = scope.capture.campaign_metric_owner(&cluster, config.clone(), Arc::clone(&scope) as Arc<dyn IoFence>) => result,
        };
        let Ok(mut session) = started else {
            tokio::select! { _ = stop.changed() => break, () = tokio::time::sleep(Duration::from_millis(500)) => {} }
            continue;
        };
        if !scope.is_live() {
            let _ = session.shutdown().await;
            break;
        }
        let local = LocalOwner::from_session(&session);
        current.send_replace(Some(local));
        // Go `onElected`. The key is the one this worker campaigned on, so
        // the label is its own election rather than anything derived at the
        // exposition.
        //
        // The matching `onRetired` is a guard, not a statement after the
        // await: this task is torn down with `abort()`, which drops the
        // future at its next suspension point and would skip any line that
        // followed. A `server_owner` series left behind by an aborted worker
        // would claim an election this process no longer holds.
        let owned = owner_history
            .as_ref()
            .map(|history| OwnedElection::won(Arc::clone(history), election_key.clone()));
        Box::pin(maintain(&mut session, &scope, &mut stop)).await;
        drop(owned);
        current.send_replace(None);
        let _ = session.shutdown().await;
    }
}
/// Holds `server_owner` for one election, releasing it on drop.
///
/// Drop runs when the task is aborted as well as when the loop exits
/// normally, which a trailing statement would not.
struct OwnedElection {
    history: Arc<ElectionOwnerHistory>,
    key: String,
}

impl OwnedElection {
    fn won(history: Arc<ElectionOwnerHistory>, key: String) -> Self {
        history.won(&key);
        Self { history, key }
    }
}

impl Drop for OwnedElection {
    fn drop(&mut self) {
        self.history.retired(&self.key);
    }
}

async fn maintain(session: &mut ElectionSession, scope: &Scope, stop: &mut watch::Receiver<bool>) {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while scope.is_live() && !*stop.borrow() {
        match session.snapshot().state {
            ElectionState::Retired | ElectionState::Stopped => break,
            ElectionState::Uncertain => {
                tokio::select! { biased; _ = stop.changed() => break, _ = session.recover() => {} }
                if session.snapshot().state == ElectionState::Uncertain {
                    tokio::select! { _ = stop.changed() => break, () = tokio::time::sleep(Duration::from_millis(500)) => {} }
                }
            }
            _ => {
                tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    _ = heartbeat.tick() => { let _ = session.keep_alive().await; }
                    _ = session.watch_once() => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "/tiproxy/metric_reader/owner";

    /// The worker is torn down with `abort()`, which drops the future at its
    /// next suspension point. A retirement written as a statement after the
    /// await would never run, leaving `server_owner` claiming an election
    /// this process no longer holds.
    #[tokio::test]
    async fn aborting_the_worker_still_retires_its_election() {
        let history = Arc::new(ElectionOwnerHistory::new());
        let (started, mut observe) = watch::channel(false);
        let owned = Arc::clone(&history);
        let task = tokio::spawn(async move {
            let _election = OwnedElection::won(owned, KEY.to_owned());
            started.send_replace(true);
            // Park forever: the only way out is the abort.
            std::future::pending::<()>().await;
        });
        let _ = observe.wait_for(|started| *started).await;
        assert_eq!(
            history.snapshot().owned.len(),
            1,
            "the election is held while the worker runs"
        );

        task.abort();
        let _ = task.await;
        assert!(
            history.snapshot().owned.is_empty(),
            "an aborted worker releases its election"
        );
    }

    /// The ordinary exit releases it too, through the same guard.
    #[tokio::test]
    async fn a_normal_exit_retires_its_election() {
        let history = Arc::new(ElectionOwnerHistory::new());
        {
            let _election = OwnedElection::won(Arc::clone(&history), KEY.to_owned());
            assert_eq!(history.snapshot().owned.len(), 1);
        }
        assert!(history.snapshot().owned.is_empty());
    }
}
