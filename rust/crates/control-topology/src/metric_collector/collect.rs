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

//! Immediate-first cluster rounds with bounded joins and qualified publication.

use super::{
    Arc, BTreeMap, ClusterResult, Duration, GenerationGate, JoinSet, MetricCapture, MetricError,
    QueryId, QueryResult, ReaderState, Shared, owner, service, watch,
};
use crate::MetricReadError;
use crate::metric_owner::{PeerObservation, PeerSet, cluster_prefix, select_owners};
use crate::metrics::{History, decode_backend, decode_owner_history, decode_prometheus};
use control_external::{HttpTarget, IoFence};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
enum RoundError {
    Stale,
    Read,
    Decode,
    Task,
}
impl From<MetricReadError> for RoundError {
    fn from(error: MetricReadError) -> Self {
        if matches!(error, MetricReadError::Stale) {
            Self::Stale
        } else {
            Self::Read
        }
    }
}
impl From<MetricError> for RoundError {
    fn from(_: MetricError) -> Self {
        Self::Decode
    }
}

struct State {
    queries: Option<super::QueryLifetime>,
    lineage: Arc<()>,
    reader: ReaderState,
    history: History,
    export: Arc<[u8]>,
    owner: Option<Arc<owner::LocalOwner>>,
    peers: Option<Arc<PeerSet>>,
    proofs: Vec<owner::Proof>,
    observation: PeerObservation,
}
impl Default for State {
    fn default() -> Self {
        Self {
            queries: None,
            lineage: Arc::new(()),
            reader: ReaderState::default(),
            history: History::default(),
            export: Arc::from([]),
            owner: None,
            peers: None,
            proofs: Vec::new(),
            observation: PeerObservation::default(),
        }
    }
}
impl State {
    fn set_queries(&mut self, next: Option<super::QueryLifetime>) {
        if matches!((&self.queries, &next), (Some(old), Some(next)) if !old.incarnation.same_as(&next.incarnation))
        {
            // Query removal/recreation discards both Prometheus and backend
            // history, but does not restart the actual election owner.
            self.lineage = Arc::new(());
            self.reader = ReaderState::default();
            self.history = History::default();
            self.export = Arc::from([]);
            self.proofs.clear();
        }
        self.queries = next;
    }
    fn reset_backend(&mut self) {
        if self.reader.source() == crate::metrics::Source::Backend {
            self.lineage = Arc::new(());
        }
        self.reader.reset_backend();
        self.history = History::default();
        self.export = Arc::from([]);
        self.proofs.clear();
    }
    fn result(&self) -> ClusterResult {
        ClusterResult {
            queries: self.queries.clone(),
            lineage: Arc::clone(&self.lineage),
            gate: GenerationGate::new(),
            reader: self.reader.clone(),
            backend_proofs: self.proofs.clone(),
            owner: self.owner.clone(),
            export: Arc::clone(&self.export),
        }
    }
}

pub(super) async fn run_cluster(
    shared: Arc<Shared>,
    capture: MetricCapture,
    cluster: String,
    mut stop: watch::Receiver<bool>,
) {
    let zone = shared
        .source
        .proxy_zone()
        .map_or_else(String::new, |zone| zone.to_string());
    let mut owner = owner::OwnerWorker::start(
        &shared,
        capture.clone(),
        cluster.clone(),
        zone,
        stop.clone(),
    );
    let mut state = State::default();
    let mut ticks = tokio::time::interval(capture.policy().interval());
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased; _ = stop.changed() => break, _ = ticks.tick() => {} }
        if *stop.borrow() {
            break;
        }
        if !capture.still_current() {
            continue;
        }
        if owner.is_finished() {
            break;
        }
        state.set_queries(shared.query_lifetime());
        let rules = shared.queries(state.queries.as_ref());
        // Stop revokes the scope directly; finish this bounded round so every
        // spawned backend is joined before the owner worker is shut down.
        let round = round(&shared, &capture, &cluster, &rules, &mut owner, &mut state).await;
        if matches!(round, Err(RoundError::Task)) {
            break;
        }
    }
    owner.stop().await;
}

async fn round(
    shared: &Shared,
    capture: &MetricCapture,
    cluster: &str,
    rules: &[QueryId],
    owner: &mut owner::OwnerWorker,
    state: &mut State,
) -> Result<(), RoundError> {
    match read_prom(capture, cluster, rules).await {
        Ok(results) => {
            if !capture.still_current() {
                return Err(RoundError::Stale);
            }
            if state.reader.source() != crate::metrics::Source::Prometheus {
                state.lineage = Arc::new(());
            }
            state.reader.complete_prom(results);
            if !shared.publish(capture, cluster, state.result(), None) {
                return Err(RoundError::Stale);
            }
            return Ok(());
        }
        Err(RoundError::Stale) => return Err(RoundError::Stale),
        Err(_) => {}
    }
    let zone = shared
        .source
        .proxy_zone()
        .map_or_else(String::new, |zone| zone.to_string());
    if owner.zone != zone {
        owner
            .restart(shared, capture.clone(), cluster.to_owned(), zone)
            .await;
        state.observation = PeerObservation::default();
        state.reset_backend();
        state.owner = None;
        state.peers = None;
    }
    backend_round(shared, capture, cluster, rules, owner, state).await
}

fn now_nanos() -> Result<i64, RoundError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RoundError::Read)?
            .as_nanos(),
    )
    .map_err(|_| RoundError::Read)
}
fn seconds(millis: i64) -> String {
    let value = i128::from(millis);
    format!(
        "{}{}.{:03}",
        if value < 0 { "-" } else { "" },
        value.abs() / 1000,
        value.abs() % 1000
    )
}
fn prom_target(rule: QueryId, expression: &str, end_ms: i64) -> Result<HttpTarget, RoundError> {
    let query = service::encode_query(expression);
    let path = if let Some((start, end, step)) = rule.spec().window(end_ms)? {
        format!(
            "/api/v1/query_range?query={query}&start={}&end={}&step={}",
            seconds(start),
            seconds(end),
            seconds(step)
        )
    } else {
        format!("/api/v1/query?query={query}")
    };
    HttpTarget::new(path).map_err(|_| RoundError::Read)
}
async fn read_prom(
    capture: &MetricCapture,
    cluster: &str,
    rules: &[QueryId],
) -> Result<BTreeMap<QueryId, QueryResult>, RoundError> {
    let prom = capture.poll_prometheus(cluster).await?;
    let port = u16::try_from(prom.port).map_err(|_| RoundError::Read)?;
    let end_ms = now_nanos()? / 1_000_000;
    let mut results = BTreeMap::new();
    for &rule in rules {
        let mut last = Err(RoundError::Read);
        for expression in rule.spec().expressions() {
            let target = prom_target(rule, &expression, end_ms)?;
            last = prom_query(capture, &prom.ip, port, &target).await;
            if matches!(&last, Ok(result) if !result.is_empty()) {
                break;
            }
            if matches!(&last, Err(RoundError::Stale)) {
                return Err(RoundError::Stale);
            }
        }
        let mut result = last?;
        result.attach_cluster(cluster);
        result.updated_nanos = now_nanos()?;
        results.insert(rule, result);
    }
    Ok(results)
}
async fn prom_query(
    capture: &MetricCapture,
    host: &str,
    port: u16,
    target: &HttpTarget,
) -> Result<QueryResult, RoundError> {
    let result = tokio::time::timeout(capture.policy().prom_timeout(), async {
        let mut retry = Duration::from_millis(500);
        loop {
            match capture.get_prom_once(host, port, target).await {
                Ok(bytes) => return decode_prometheus(&bytes, "", 0).map_err(RoundError::from),
                Err(MetricReadError::Http(error)) if error.is_retryable() => {
                    tokio::time::sleep(retry).await;
                    retry = (retry + retry / 2).min(Duration::from_secs(1));
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await;
    if !capture.still_current() {
        return Err(RoundError::Stale);
    }
    result.map_err(|_| RoundError::Read)?
}

struct RoundFence {
    scope: Arc<owner::Scope>,
    role: Arc<owner::RoleCapture>,
    peers: Arc<PeerSet>,
    work: Option<control_etcd::ElectionWorkPermit>,
}
impl IoFence for RoundFence {
    fn is_live(&self) -> bool {
        self.scope.is_live()
            && self.role.is_live()
            && self.peers.is_live()
            && self
                .work
                .as_ref()
                .is_none_or(control_etcd::ElectionWorkPermit::still_current)
    }
}
async fn observe_owners(
    capture: &MetricCapture,
    cluster: &str,
    observation: &mut PeerObservation,
) -> Result<Arc<PeerSet>, RoundError> {
    let prefix = cluster_prefix(cluster);
    let records = capture.poll_metric_owners(cluster, &prefix).await?;
    Ok(observation.observe(select_owners(&prefix, records)).0)
}

// Keep the Go read/merge/missing/purge/publication order visible in one place.
#[allow(clippy::too_many_lines)]
async fn backend_round(
    shared: &Shared,
    capture: &MetricCapture,
    cluster: &str,
    rules: &[QueryId],
    owner: &owner::OwnerWorker,
    state: &mut State,
) -> Result<(), RoundError> {
    let peers = observe_owners(capture, cluster, &mut state.observation).await?;
    let role = owner.capture_role();
    if !owner::same_local(state.owner.as_ref(), role.captured.as_ref())
        || state
            .peers
            .as_ref()
            .is_none_or(|previous| !Arc::ptr_eq(previous, &peers))
    {
        state.reset_backend();
        state.owner.clone_from(&role.captured);
        state.peers = Some(Arc::clone(&peers));
    }
    let work = role
        .captured
        .as_ref()
        .and_then(|local| local.authority.capture_work());
    if role.captured.as_ref().is_some_and(|local| {
        work.is_none() || !local.matches_observation(cluster, &owner.zone, &peers)
    }) {
        return Err(RoundError::Stale);
    }
    let fence = Arc::new(RoundFence {
        scope: owner.scope(),
        role: Arc::clone(&role),
        peers: Arc::clone(&peers),
        work,
    });
    let topology = capture.poll_cluster_topology(cluster).await;
    let mut succeeded = topology.is_ok();
    if matches!(&topology, Err(MetricReadError::Stale)) {
        return Err(RoundError::Stale);
    }
    let backends = topology.map_or_else(|_| Vec::new(), |topology| topology.backends);
    let addresses = |excluded: &[String]| -> Vec<String> {
        backends
            .iter()
            .filter(|backend| {
                !excluded.iter().any(|zone| {
                    backend
                        .backend
                        .labels
                        .get("zone")
                        .is_some_and(|value| value == zone)
                })
            })
            .map(|backend| address(&backend.backend.ip, backend.backend.status_port))
            .collect()
    };
    let all = addresses(&[]);
    let selected = if fence.work.is_some() {
        let zones: Vec<_> = peers
            .zones()
            .into_iter()
            .filter(|zone| zone != &owner.zone)
            .collect();
        addresses(&zones)
    } else {
        Vec::new()
    };
    let mut history = state.history.clone();
    read_backends(
        capture,
        cluster,
        rules,
        &selected,
        Arc::clone(&fence),
        &mut history,
    )
    .await?;
    for peer in peers.addresses() {
        if !fence.is_live() {
            return Err(RoundError::Stale);
        }
        if peer == shared.serving.address.to_string() {
            continue;
        }
        let target = HttpTarget::new(format!(
            "/api/backend/metrics?cluster={}",
            service::encode_query(cluster)
        ))
        .map_err(|_| RoundError::Read)?;
        let fetched = cluster_get(capture, cluster, &peer, &target, fence.as_ref()).await;
        let observed = observe_owners(capture, cluster, &mut state.observation).await?;
        if !Arc::ptr_eq(&observed, &peers) || !fence.is_live() {
            return Err(RoundError::Stale);
        }
        match fetched {
            Ok(bytes) => {
                match decode_owner_history(&bytes).and_then(|incoming| history.merge(incoming)) {
                    Ok(()) => {}
                    Err(_) => succeeded = false,
                }
            }
            Err(RoundError::Stale) => return Err(RoundError::Stale),
            Err(_) => succeeded = false,
        }
    }
    let missing = history.missing(rules, &all);
    read_backends(
        capture,
        cluster,
        rules,
        &missing,
        Arc::clone(&fence),
        &mut history,
    )
    .await?;
    if !fence.is_live() || !capture.still_current() {
        return Err(RoundError::Stale);
    }
    let updated = now_nanos()?;
    history.purge(rules, updated / 1_000_000);
    let labels: Vec<_> = selected
        .iter()
        .map(|addr| crate::metrics::address_label(addr))
        .collect();
    let export = history
        .owner_json(&labels)
        .map_or_else(|_| Arc::clone(&state.export), Arc::from);
    let mut reader = state.reader.clone();
    reader.complete_backend(history.results(rules, cluster, updated), succeeded);
    let mut proofs = vec![
        owner::Proof::Peer(peers),
        owner::Proof::Scope(owner.scope()),
        owner::Proof::Role(role),
    ];
    if let Some(local) = &state.owner {
        proofs.push(owner::Proof::Local(Arc::clone(local)));
    }
    let lineage = if reader.source() == state.reader.source() {
        Arc::clone(&state.lineage)
    } else {
        Arc::new(())
    };
    let result = ClusterResult {
        queries: state.queries.clone(),
        lineage: Arc::clone(&lineage),
        gate: GenerationGate::new(),
        reader: reader.clone(),
        backend_proofs: proofs.clone(),
        owner: state.owner.clone(),
        export: Arc::clone(&export),
    };
    if !shared.publish(capture, cluster, result, fence.work.as_ref()) {
        return Err(RoundError::Stale);
    }
    state.lineage = lineage;
    state.history = history;
    state.reader = reader;
    state.export = export;
    state.proofs = proofs;
    Ok(())
}

fn address(host: &str, port: u64) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn split_address(address: &str) -> Result<(&str, u16), RoundError> {
    let (host, port) = address.rsplit_once(':').ok_or(RoundError::Read)?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    Ok((host, port.parse().map_err(|_| RoundError::Read)?))
}
async fn cluster_get(
    capture: &MetricCapture,
    cluster: &str,
    address: &str,
    target: &HttpTarget,
    fence: &dyn IoFence,
) -> Result<Vec<u8>, RoundError> {
    let (host, port) = split_address(address)?;
    for attempt in 0..=capture.policy().max_retries() {
        if !fence.is_live() || !capture.still_current() {
            return Err(RoundError::Stale);
        }
        match capture
            .get_cluster_once(cluster, host, port, target, fence)
            .await
        {
            Ok(bytes) => return Ok(bytes),
            Err(MetricReadError::Http(error))
                if error.is_retryable() && attempt < capture.policy().max_retries() =>
            {
                tokio::time::sleep(capture.policy().retry_interval()).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(RoundError::Read)
}
async fn read_backends(
    capture: &MetricCapture,
    cluster: &str,
    rules: &[QueryId],
    addresses: &[String],
    fence: Arc<RoundFence>,
    history: &mut History,
) -> Result<(), RoundError> {
    if rules.is_empty() {
        return Ok(());
    }
    join_backends(
        addresses,
        fence.as_ref(),
        |address| {
            let capture = capture.clone();
            let cluster = cluster.to_owned();
            let fence = Arc::clone(&fence);
            let rules = rules.to_vec();
            async move {
                let target = HttpTarget::new("/metrics").map_err(|_| RoundError::Read)?;
                let bytes =
                    cluster_get(&capture, &cluster, &address, &target, fence.as_ref()).await?;
                let text = std::str::from_utf8(&bytes).map_err(|_| RoundError::Decode)?;
                let names: Vec<_> = rules.iter().flat_map(|rule| rule.spec().names).collect();
                let selected: String = text
                    .split_inclusive('\n')
                    .filter(|line| names.iter().any(|name| line.starts_with(**name)))
                    .collect();
                let metrics = decode_backend(selected.as_bytes())?;
                Ok((
                    crate::metrics::address_label(&address),
                    metrics,
                    now_nanos()? / 1_000_000,
                ))
            }
        },
        |(label, metrics, time)| {
            history
                .observe(rules, &label, &metrics, time)
                .map_err(Into::into)
        },
    )
    .await
}

// Completed HTTP/parse errors are missing observations in Go. Join failures and
// invalidated work are different: cancel and drain the whole owned batch before
// returning, so callers cannot publish a completed partial round.
async fn join_backends<T, F, Fut>(
    addresses: &[String],
    fence: &dyn IoFence,
    run: F,
    mut complete: impl FnMut(T) -> Result<(), RoundError>,
) -> Result<(), RoundError>
where
    T: Send + 'static,
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<T, RoundError>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut addresses = addresses.iter();
    loop {
        while tasks.len() < 100 {
            let Some(address) = addresses.next() else {
                break;
            };
            if !fence.is_live() {
                tasks.shutdown().await;
                return Err(RoundError::Stale);
            }
            tasks.spawn(run(address.clone()));
        }
        let Some(result) = tasks.join_next().await else {
            break;
        };
        let failure = match result {
            Ok(Ok(value)) => complete(value).err(),
            Ok(Err(RoundError::Stale)) => Some(RoundError::Stale),
            Ok(Err(_)) => None,
            Err(_) => Some(RoundError::Task),
        };
        if let Some(error) = failure {
            tasks.shutdown().await;
            return Err(error);
        }
    }
    if fence.is_live() {
        Ok(())
    } else {
        Err(RoundError::Stale)
    }
}

#[cfg(test)]
mod tests;
