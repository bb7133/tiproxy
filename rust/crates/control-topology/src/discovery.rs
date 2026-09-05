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

//! The discovery poll (the I/O half of topology discovery).
//!
//! [`poll_tidb_topology`] reads the live `TiDB` topology from a backend
//! cluster's etcd and returns the liveness-filtered snapshot, mirroring Go
//! `infosync.InfoSyncer::GetTiDBTopology` (`pkg/manager/infosync/info.go`): it
//! prefix-reads `/topology/tidb/` and `/keyspaces/tidb/`, concatenates the
//! key/value pairs, and feeds the shared pure parser [`parse_tidb_topology`].
//!
//! The read goes through [`control_external::EtcdConnection`], so it is fenced
//! by the process [`control_plane::OwnerToken`]. The parsing itself is unit
//! tested in [`crate::model`]; [`poll_tidb_topology`]'s live range read is
//! covered by the embedded-etcd integration test that exercises registration,
//! and [`poll_prometheus`]'s live prefix range read is covered by the
//! `tests/prometheus_etcd.rs` embedded-etcd integration test.

use std::future::Future;
use std::time::Duration;

use control_external::{EtcdConnection, EtcdOperationError};
use etcd_client::GetOptions;

use crate::model::{PrometheusInfo, TopologySnapshot, parse_tidb_topology};

/// Classic (non-keyspace) `TiDB` topology prefix. Matches Go
/// `tidbTopologyInformationPath`.
const TIDB_TOPOLOGY_PREFIX: &str = "/topology/tidb/";
/// Keyspace-scoped `TiDB` topology prefix. Matches Go
/// `tidbKeyspaceTopologyInformationPath`.
const TIDB_KEYSPACE_TOPOLOGY_PREFIX: &str = "/keyspaces/tidb/";

/// Reads the live `TiDB` topology and returns a liveness-filtered snapshot.
///
/// Both prefixes are read with a single ranged get each; a backend appears only
/// when its `info` record still has a live `ttl` sibling, exactly as the shared
/// parser enforces.
///
/// # Errors
///
/// Returns [`EtcdOperationError::StaleOwner`] if the owner generation is
/// released around either read, or [`EtcdOperationError::Dependency`] for a
/// transport or server failure.
pub async fn poll_tidb_topology(
    connection: &mut EtcdConnection,
) -> Result<TopologySnapshot, EtcdOperationError> {
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for prefix in [TIDB_TOPOLOGY_PREFIX, TIDB_KEYSPACE_TOPOLOGY_PREFIX] {
        let key = prefix.to_owned();
        let response = connection
            .execute(move |client| Box::pin(client.get(key, Some(GetOptions::new().with_prefix()))))
            .await?;
        entries.reserve(response.kvs().len());
        for kv in response.kvs() {
            entries.push((kv.key().to_vec(), kv.value().to_vec()));
        }
    }
    Ok(parse_tidb_topology(&entries))
}

/// Prometheus topology prefix. Matches Go `promTopologyPath`.
const PROMETHEUS_TOPOLOGY_PREFIX: &str = "/topology/prometheus";
/// Per-attempt Prometheus read timeout. Matches Go `getPromTimeout`.
const GET_PROM_TIMEOUT: Duration = Duration::from_secs(2);
/// Total Prometheus read attempts: one initial plus `getPromRetryCnt = 3`
/// retries, matching Go `etcd.GetKVs` under `retry.Retry`.
const GET_PROM_MAX_ATTEMPTS: u32 = 4;

/// Why a Prometheus discovery poll failed.
#[derive(Debug)]
pub enum PrometheusError {
    /// The etcd read failed: a stale owner aborts immediately, and a transport
    /// dependency failure is reported only after the retry budget is exhausted.
    Etcd(#[allow(dead_code)] EtcdOperationError),
    /// Every attempt exceeded the per-attempt deadline.
    Timeout,
    /// The first Prometheus record was not a valid `PrometheusInfo`.
    Malformed,
}

/// One Prometheus prefix-read attempt, yielding the record values in etcd key
/// order. Injectable so the `GetKVs` retry policy is unit-tested without a live
/// etcd server.
trait PrometheusFetch {
    /// Performs one prefix read, returning the record values (etcd key order).
    fn fetch(&mut self) -> impl Future<Output = Result<Vec<Vec<u8>>, EtcdOperationError>> + Send;

    /// Whether the owner generation is still current. Re-checked in the
    /// timeout branch, where the fetch future is dropped before its own
    /// post-await owner fence can run, so a retired owner is not mistaken for a
    /// plain timeout.
    fn owner_is_current(&self) -> bool;
}

/// The production fetch: one owner-fenced prefix read through the etcd
/// connection.
struct ConnectionFetch<'connection>(&'connection mut EtcdConnection);

impl PrometheusFetch for ConnectionFetch<'_> {
    async fn fetch(&mut self) -> Result<Vec<Vec<u8>>, EtcdOperationError> {
        self.0
            .execute(|client| {
                Box::pin(async move {
                    let response = client
                        .get(
                            PROMETHEUS_TOPOLOGY_PREFIX,
                            Some(GetOptions::new().with_prefix()),
                        )
                        .await?;
                    Ok(response
                        .kvs()
                        .iter()
                        .map(|kv| kv.value().to_vec())
                        .collect())
                })
            })
            .await
    }

    fn owner_is_current(&self) -> bool {
        self.0.owner_is_current()
    }
}

/// Selects the first Prometheus record by etcd key order (etcd returns a range
/// ascending by key, so the first value is `kvs[0]`) and parses it. An empty
/// prefix is `Ok(None)` (Go `ErrNoProm`); a present-but-malformed first record is
/// an error (Go's `json.Unmarshal` error), never silently `None`.
fn select_prometheus(values: &[Vec<u8>]) -> Result<Option<PrometheusInfo>, PrometheusError> {
    match values.first() {
        None => Ok(None),
        Some(value) => PrometheusInfo::from_json(value)
            .map(Some)
            .ok_or(PrometheusError::Malformed),
    }
}

/// Drives the `GetKVs` retry policy over an injectable fetch: up to
/// `max_attempts` reads, each bounded by `per_attempt`, retrying **only** a
/// transport dependency failure or a per-attempt timeout (Go retries only the
/// RPC). A successful read — including an empty one — is not retried, and a
/// malformed first record is returned as an error without retry. A stale owner
/// aborts immediately without consuming further attempts.
///
/// A per-attempt timeout drops the in-flight fetch future before it can run its
/// own post-await owner fence, so the owner is re-checked here: a timeout under a
/// retired owner is a typed `StaleOwner` abort (no further attempts), not a
/// retryable timeout.
async fn poll_with<F: PrometheusFetch>(
    fetcher: &mut F,
    max_attempts: u32,
    per_attempt: Duration,
) -> Result<Option<PrometheusInfo>, PrometheusError> {
    let mut last = PrometheusError::Timeout;
    for _ in 0..max_attempts {
        match tokio::time::timeout(per_attempt, fetcher.fetch()).await {
            Ok(Ok(values)) => return select_prometheus(&values),
            Ok(Err(EtcdOperationError::StaleOwner)) => {
                return Err(PrometheusError::Etcd(EtcdOperationError::StaleOwner));
            }
            Ok(Err(dependency)) => last = PrometheusError::Etcd(dependency),
            Err(_elapsed) => {
                if !fetcher.owner_is_current() {
                    return Err(PrometheusError::Etcd(EtcdOperationError::StaleOwner));
                }
                last = PrometheusError::Timeout;
            }
        }
    }
    Err(last)
}

/// Reads the live Prometheus endpoint from a backend cluster's etcd, mirroring
/// Go `infosync.InfoSyncer::GetPromInfo` (`pkg/manager/infosync/info.go`) over
/// `etcd.GetKVs`: a prefix read of `/topology/prometheus` with the 4-attempt,
/// 2-second, RPC-failure-only retry policy, taking the first record by key
/// order.
///
/// # Errors
///
/// Returns [`PrometheusError::Etcd`] for a stale owner (immediate) or a
/// transport failure that outlasts the retry budget, [`PrometheusError::Timeout`]
/// when every attempt exceeds the per-attempt deadline, or
/// [`PrometheusError::Malformed`] when the first record is not a valid
/// `PrometheusInfo`. An empty prefix is `Ok(None)`.
pub async fn poll_prometheus(
    connection: &mut EtcdConnection,
) -> Result<Option<PrometheusInfo>, PrometheusError> {
    poll_with(
        &mut ConnectionFetch(connection),
        GET_PROM_MAX_ATTEMPTS,
        GET_PROM_TIMEOUT,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use control_external::EtcdOperationError;

    use super::{
        GET_PROM_MAX_ATTEMPTS, PrometheusError, PrometheusFetch, poll_with, select_prometheus,
    };

    fn value(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    /// A retryable transport dependency failure.
    fn dependency() -> EtcdOperationError {
        EtcdOperationError::Dependency(etcd_client::Error::InvalidArgs("injected".to_owned()))
    }

    enum Outcome {
        Ok(Vec<Vec<u8>>),
        Dependency,
        Stale,
        /// Sleeps past the per-attempt deadline with the owner still current
        /// (a plain timeout that should be retried).
        Slow(Duration),
        /// Retires the owner and then sleeps past the deadline, modelling a
        /// retire during a hung RPC: the fetch future is dropped by the timeout
        /// before its own post-await owner fence runs, so the driver's timeout
        /// branch must observe the retired owner.
        SlowRetire(Duration),
    }

    struct FakeFetch {
        outcomes: VecDeque<Outcome>,
        calls: usize,
        owner_current: Arc<AtomicBool>,
    }

    impl FakeFetch {
        fn new(outcomes: Vec<Outcome>) -> Self {
            Self {
                outcomes: outcomes.into(),
                calls: 0,
                owner_current: Arc::new(AtomicBool::new(true)),
            }
        }
    }

    impl PrometheusFetch for FakeFetch {
        async fn fetch(&mut self) -> Result<Vec<Vec<u8>>, EtcdOperationError> {
            self.calls += 1;
            match self.outcomes.pop_front() {
                Some(Outcome::Ok(values)) => Ok(values),
                Some(Outcome::Dependency) | None => Err(dependency()),
                Some(Outcome::Stale) => Err(EtcdOperationError::StaleOwner),
                Some(Outcome::Slow(delay)) => {
                    tokio::time::sleep(delay).await;
                    Ok(Vec::new())
                }
                Some(Outcome::SlowRetire(delay)) => {
                    // Retire before sleeping, so by the time the outer timeout
                    // fires and the driver re-checks ownership it is already
                    // stale — the realistic retire-during-hang ordering.
                    self.owner_current.store(false, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    Ok(Vec::new())
                }
            }
        }

        fn owner_is_current(&self) -> bool {
            self.owner_current.load(Ordering::SeqCst)
        }
    }

    fn prom(ip: &str, port: i64) -> String {
        format!(r#"{{"ip":"{ip}","port":{port}}}"#)
    }

    #[test]
    fn select_takes_the_first_record_not_a_later_one() {
        // Two records: the FIRST (etcd key order) must be chosen. A `.last()`
        // regression would pick the second.
        let values = [value(&prom("1.1.1.1", 1)), value(&prom("2.2.2.2", 2))];
        let selected = select_prometheus(&values)
            .unwrap_or_else(|_| unreachable!("valid records select"))
            .unwrap_or_else(|| unreachable!("a present record is Some"));
        assert_eq!(selected.ip, "1.1.1.1");
        assert_eq!(selected.port, 1);
    }

    #[test]
    fn select_empty_is_none() {
        let selected =
            select_prometheus(&[]).unwrap_or_else(|_| unreachable!("empty is a valid Ok(None)"));
        assert!(selected.is_none());
    }

    #[test]
    fn select_malformed_first_record_is_an_error() {
        assert!(matches!(
            select_prometheus(&[value("{not json")]),
            Err(PrometheusError::Malformed)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retries_up_to_the_full_budget_then_succeeds() {
        // Three transport failures then a success on the fourth attempt must
        // succeed under the four-attempt budget; a `4 -> 3` regression fails.
        let mut fetch = FakeFetch::new(vec![
            Outcome::Dependency,
            Outcome::Dependency,
            Outcome::Dependency,
            Outcome::Ok(vec![value(&prom("9.9.9.9", 9090))]),
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_secs(1))
            .await
            .unwrap_or_else(|_| unreachable!("the fourth attempt succeeds"))
            .unwrap_or_else(|| unreachable!("a present record is Some"));
        assert_eq!(result.ip, "9.9.9.9");
        assert_eq!(fetch.calls, 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exhausting_the_budget_reports_the_dependency_failure() {
        let mut fetch = FakeFetch::new(vec![
            Outcome::Dependency,
            Outcome::Dependency,
            Outcome::Dependency,
            Outcome::Dependency,
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_secs(1)).await;
        assert!(matches!(result, Err(PrometheusError::Etcd(_))));
        assert_eq!(fetch.calls, 4, "the whole budget is consumed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stale_owner_aborts_without_retrying() {
        let mut fetch = FakeFetch::new(vec![Outcome::Stale, Outcome::Ok(vec![value("{}")])]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            Err(PrometheusError::Etcd(EtcdOperationError::StaleOwner))
        ));
        assert_eq!(fetch.calls, 1, "a stale owner consumes no further attempts");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_empty_read_is_not_retried() {
        let mut fetch = FakeFetch::new(vec![
            Outcome::Ok(Vec::new()),
            Outcome::Ok(vec![value("{}")]),
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_secs(1))
            .await
            .unwrap_or_else(|_| unreachable!("an empty read is a successful Ok(None)"));
        assert!(result.is_none());
        assert_eq!(fetch.calls, 1, "a successful empty read is not retried");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_per_attempt_timeout_is_retried() {
        // The first attempt sleeps past the per-attempt deadline (timeout ->
        // retry); the second returns a record.
        let mut fetch = FakeFetch::new(vec![
            Outcome::Slow(Duration::from_millis(400)),
            Outcome::Ok(vec![value(&prom("3.3.3.3", 3))]),
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_millis(50))
            .await
            .unwrap_or_else(|_| unreachable!("the second attempt returns in time"))
            .unwrap_or_else(|| unreachable!("a present record is Some"));
        assert_eq!(result.ip, "3.3.3.3");
        assert_eq!(fetch.calls, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timeout_under_a_retired_owner_aborts_as_stale() {
        // A retire during a hung RPC: the attempt times out, and the driver's
        // timeout branch must observe the retired owner and abort as StaleOwner
        // WITHOUT consuming a second attempt. Removing the owner re-check makes
        // this a plain retryable Timeout.
        let mut fetch = FakeFetch::new(vec![
            Outcome::SlowRetire(Duration::from_millis(400)),
            Outcome::Ok(vec![value("{}")]),
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_millis(50)).await;
        assert!(matches!(
            result,
            Err(PrometheusError::Etcd(EtcdOperationError::StaleOwner))
        ));
        assert_eq!(
            fetch.calls, 1,
            "a retired owner aborts without a further attempt"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retire_and_hang_on_the_last_attempt_is_stale_not_timeout() {
        // Three transport failures exhaust to the fourth attempt, which hangs
        // under a retired owner: the result must be StaleOwner, never the final
        // Timeout.
        let mut fetch = FakeFetch::new(vec![
            Outcome::Dependency,
            Outcome::Dependency,
            Outcome::Dependency,
            Outcome::SlowRetire(Duration::from_millis(400)),
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_millis(50)).await;
        assert!(matches!(
            result,
            Err(PrometheusError::Etcd(EtcdOperationError::StaleOwner))
        ));
        assert_eq!(fetch.calls, 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_malformed_first_record_is_not_retried() {
        // A successful read whose first record is malformed is a hard error at
        // the driver level (not just the pure selector): the later valid attempt
        // is never reached.
        let mut fetch = FakeFetch::new(vec![
            Outcome::Ok(vec![value("{not json")]),
            Outcome::Ok(vec![value(&prom("9.9.9.9", 9090))]),
        ]);
        let result = poll_with(&mut fetch, GET_PROM_MAX_ATTEMPTS, Duration::from_secs(1)).await;
        assert!(matches!(result, Err(PrometheusError::Malformed)));
        assert_eq!(fetch.calls, 1, "a malformed successful read is not retried");
    }
}
