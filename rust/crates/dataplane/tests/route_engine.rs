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

//! DPL-02 model tests: the route/dial engine against a scripted adapter
//! (Go `RouterAdapter` semantics: one request, assignments pushed after
//! every failed result) and a scripted dialer, under Tokio's paused-time
//! deterministic scheduler. The two-backend failure matrix, budget
//! bounds, deterministic backoff, exactly-once assignment retirement,
//! terminal adapter answers, control loss, and handshake-driven
//! re-selection are covered explicitly.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use control_proto::v1::{ErrorCode, ErrorSource, RouteAssignment, RouteResult};
use dataplane::route::{
    AcquireError, BackendDialer, CenteredJitter, DialFailure, DialSchedule, JitterSource,
    RouteChannel, RouteChannelError, RouteEngine, SplitMixJitter,
};
use tokio::time::Instant;

const CONN_ID: u64 = 7;

fn assignment(id: &str, backend: &str, address: &str) -> RouteAssignment {
    RouteAssignment {
        connection_id: CONN_ID,
        assignment_id: id.to_owned(),
        backend_id: backend.to_owned(),
        backend_address: address.to_owned(),
        cluster_name: "cluster-a".to_owned(),
        keyspace: "ks".to_owned(),
        healthy: true,
        local: true,
        code: ErrorCode::Ok.into(),
        detail: String::new(),
    }
}

fn terminal(code: ErrorCode, detail: &str) -> RouteAssignment {
    RouteAssignment {
        connection_id: CONN_ID,
        code: code.into(),
        detail: detail.to_owned(),
        ..assignment("", "", "")
    }
}

/// Scripted adapter: assignments are delivered in order, each awaited
/// only after the previous one's failed result (the engine's await *is*
/// the adapter's push); every result is recorded.
#[derive(Default)]
struct FakeAdapter {
    assignments: VecDeque<RouteAssignment>,
    results: Vec<RouteResult>,
    requests: u32,
    /// When the queue empties, answer this instead of hanging.
    on_empty: Option<RouteChannelError>,
}

impl RouteChannel for FakeAdapter {
    async fn request_route(
        &mut self,
        _excluded_backend_ids: Vec<String>,
    ) -> Result<(), RouteChannelError> {
        self.requests += 1;
        Ok(())
    }

    async fn next_assignment(&mut self) -> Result<RouteAssignment, RouteChannelError> {
        match self.assignments.pop_front() {
            Some(assignment) => Ok(assignment),
            None => match self.on_empty {
                Some(error) => Err(error),
                None => std::future::pending().await,
            },
        }
    }

    async fn report_result(&mut self, result: RouteResult) -> Result<(), RouteChannelError> {
        self.results.push(result);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Connect,
    Refuse,
    Hang,
}

/// Scripted dialer keyed by address; records each attempt's address,
/// cluster, and start time for schedule assertions.
struct FakeDialer {
    outcomes: HashMap<String, Outcome>,
    attempts: Vec<(String, String, Instant)>,
}

impl FakeDialer {
    fn new(outcomes: &[(&str, Outcome)]) -> Self {
        Self {
            outcomes: outcomes
                .iter()
                .map(|(addr, outcome)| ((*addr).to_owned(), *outcome))
                .collect(),
            attempts: Vec::new(),
        }
    }
}

impl BackendDialer for FakeDialer {
    const CLUSTER_AWARE: bool = true;

    type Conn = String;

    async fn dial(&mut self, address: &str, cluster_name: &str) -> Result<String, DialFailure> {
        self.attempts
            .push((address.to_owned(), cluster_name.to_owned(), Instant::now()));
        match self.outcomes.get(address) {
            Some(Outcome::Connect) => Ok(address.to_owned()),
            Some(Outcome::Refuse) => Err(DialFailure::Connect),
            Some(Outcome::Hang) | None => std::future::pending().await,
        }
    }
}

fn schedule() -> DialSchedule {
    // Centered jitter (the default) makes every delay exactly nominal.
    DialSchedule::default()
}

fn engine(
    adapter: FakeAdapter,
    dialer: FakeDialer,
    schedule: DialSchedule,
) -> RouteEngine<FakeAdapter, FakeDialer> {
    RouteEngine::new(adapter, dialer, schedule, CenteredJitter, CONN_ID)
}

fn results_for<'r>(results: &'r [RouteResult], id: &str) -> Vec<&'r RouteResult> {
    results
        .iter()
        .filter(|result| result.assignment_id == id)
        .collect()
}

/// Backend A fails, backend B connects: the failed result retires A
/// (score released), the engine awaits the pushed B, backs off exactly
/// one initial interval, and surfaces B's metadata. Exactly one result
/// per assignment id.
#[tokio::test(start_paused = true)]
async fn second_backend_connects_after_first_fails() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    adapter
        .assignments
        .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
    let dialer = FakeDialer::new(&[
        ("10.0.0.1:4000", Outcome::Refuse),
        ("10.0.0.2:4000", Outcome::Connect),
    ]);
    let start = Instant::now();
    let mut engine = engine(adapter, dialer, schedule());
    let acquired = match engine.acquire(Vec::new()).await {
        Ok(acquired) => acquired,
        Err(error) => unreachable!("acquire failed: {error:?}"),
    };
    assert_eq!(acquired.conn, "10.0.0.2:4000");
    assert_eq!(acquired.backend.backend_id, "tidb-b");
    assert_eq!(acquired.backend.cluster_name, "cluster-a");
    assert_eq!(acquired.assignment_id, "a-2");
    assert_eq!(acquired.attempts, 2);
    assert_eq!(
        start.elapsed(),
        Duration::from_millis(100),
        "one initial backoff between the attempts"
    );

    let (engine_channel, _) = engine.into_parts();
    assert_eq!(engine_channel.requests, 1, "one RouteRequest total");
    let failed = results_for(&engine_channel.results, "a-1");
    assert_eq!(failed.len(), 1, "A retired exactly once");
    assert!(!failed[0].connected);
    assert_eq!(failed[0].error_source(), ErrorSource::BackendNetwork);
    assert_eq!(failed[0].code(), ErrorCode::BackendDialFailed);
    let connected = results_for(&engine_channel.results, "a-2");
    assert_eq!(connected.len(), 1, "B retired exactly once");
    assert!(connected[0].connected);
}

/// Every candidate down: each failed assignment is retired exactly once
/// and the adapter's `NO_BACKEND` terminal is surfaced deterministically.
#[tokio::test(start_paused = true)]
async fn all_backends_down_reaches_no_backend() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    adapter
        .assignments
        .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
    adapter
        .assignments
        .push_back(terminal(ErrorCode::NoBackend, "no backend available"));
    let dialer = FakeDialer::new(&[
        ("10.0.0.1:4000", Outcome::Refuse),
        ("10.0.0.2:4000", Outcome::Refuse),
    ]);
    let mut engine = engine(adapter, dialer, schedule());
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("all-down must not connect")
    };
    assert_eq!(
        error,
        AcquireError::NoBackend {
            detail: "no backend available".to_owned()
        }
    );
    let (channel, _) = engine.into_parts();
    assert_eq!(results_for(&channel.results, "a-1").len(), 1);
    assert_eq!(results_for(&channel.results, "a-2").len(), 1);
    assert_eq!(channel.results.len(), 2, "the terminal needs no result");
}

/// A hanging backend consumes exactly the per-dial timeout and reports a
/// timeout-classified failure; the next candidate still connects.
#[tokio::test(start_paused = true)]
async fn per_dial_timeout_bounds_each_attempt() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    adapter
        .assignments
        .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
    let dialer = FakeDialer::new(&[
        ("10.0.0.1:4000", Outcome::Hang),
        ("10.0.0.2:4000", Outcome::Connect),
    ]);
    let start = Instant::now();
    let mut engine = engine(adapter, dialer, schedule());
    let acquired = match engine.acquire(Vec::new()).await {
        Ok(acquired) => acquired,
        Err(error) => unreachable!("acquire failed: {error:?}"),
    };
    assert_eq!(acquired.conn, "10.0.0.2:4000");
    // 1s hang (per-dial bound) + 100ms backoff + instant second dial.
    assert_eq!(start.elapsed(), Duration::from_millis(1100));
    let (channel, _) = engine.into_parts();
    let timed_out = results_for(&channel.results, "a-1");
    assert_eq!(timed_out.len(), 1);
    assert!(!timed_out[0].connected);
}

/// The total budget bounds the acquisition: with every candidate failing
/// and assignments never running out, the engine stops at the budget,
/// having retired every assignment it consumed exactly once.
#[tokio::test(start_paused = true)]
async fn total_budget_bounds_acquisition() {
    let mut adapter = FakeAdapter::default();
    for index in 0..64 {
        adapter
            .assignments
            .push_back(assignment(&format!("a-{index}"), "tidb-a", "10.0.0.1:4000"));
    }
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Refuse)]);
    let config = DialSchedule {
        total: Duration::from_secs(3),
        ..schedule()
    };
    let start = Instant::now();
    let mut engine = engine(adapter, dialer, config);
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("must exhaust")
    };
    assert!(
        matches!(error, AcquireError::BudgetExhausted { .. }),
        "{error:?}"
    );
    assert!(
        start.elapsed() <= Duration::from_secs(3),
        "bounded by the total budget: {:?}",
        start.elapsed()
    );
    let stats = engine.stats();
    assert!(
        engine.unretired_assignment().is_some(),
        "the final assignment is handed to close accounting"
    );
    let (channel, _) = engine.into_parts();
    assert_eq!(
        u32::try_from(channel.results.len()).unwrap_or(u32::MAX),
        stats.assignments - 1,
        "every re-selected assignment retired; the terminal one is not"
    );
    for result in &channel.results {
        assert!(!result.connected);
    }
}

/// With centered jitter the backoff schedule is exactly Go's nominal
/// series: 100ms, 200ms, 400ms, 800ms, 1600ms, then capped at 2s.
#[tokio::test(start_paused = true)]
async fn backoff_schedule_matches_go_nominal_series() {
    let mut adapter = FakeAdapter {
        on_empty: Some(RouteChannelError::ControlLost),
        ..FakeAdapter::default()
    };
    for index in 0..7 {
        adapter
            .assignments
            .push_back(assignment(&format!("a-{index}"), "tidb-a", "10.0.0.1:4000"));
    }
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Refuse)]);
    let config = DialSchedule {
        total: Duration::from_secs(60),
        ..schedule()
    };
    let mut engine = engine(adapter, dialer, config);
    // Exhaust the scripted assignments, then fail terminally.
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("must not connect")
    };
    assert_eq!(error, AcquireError::Channel(RouteChannelError::ControlLost));
    let (_, dialer) = engine.into_parts();
    let times: Vec<Duration> = dialer
        .attempts
        .windows(2)
        .map(|pair| pair[1].2.duration_since(pair[0].2))
        .collect();
    assert_eq!(
        times,
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
            Duration::from_millis(1600),
            Duration::from_millis(2000),
        ],
        "nominal exponential series, capped"
    );
}

/// A terminal internal routing failure is surfaced with its code.
#[tokio::test(start_paused = true)]
async fn terminal_routing_error_is_surfaced() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(terminal(ErrorCode::Internal, "router broke"));
    let dialer = FakeDialer::new(&[]);
    let mut engine = engine(adapter, dialer, schedule());
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!()
    };
    assert_eq!(
        error,
        AcquireError::Routing {
            code: ErrorCode::Internal,
            detail: "router broke".to_owned()
        }
    );
}

/// Control loss mid-acquisition surfaces as a channel error with no
/// assignment left unretired.
#[tokio::test(start_paused = true)]
async fn control_loss_mid_acquisition() {
    let mut adapter = FakeAdapter {
        on_empty: Some(RouteChannelError::ControlLost),
        ..FakeAdapter::default()
    };
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Refuse)]);
    let mut engine = engine(adapter, dialer, schedule());
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!()
    };
    assert_eq!(error, AcquireError::Channel(RouteChannelError::ControlLost));
    let (channel, _) = engine.into_parts();
    assert_eq!(
        results_for(&channel.results, "a-1").len(),
        1,
        "the consumed assignment was retired before the loss surfaced"
    );
}

/// Handshake-driven re-selection: after a connected backend's
/// authentication fails and the Go handler permits a retry, the engine
/// resumes on the adapter's next pushed assignment under a fresh budget;
/// both assignments end with exactly one result each.
#[tokio::test(start_paused = true)]
async fn handshake_failure_reselects_distinct_backend() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    adapter
        .assignments
        .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
    let dialer = FakeDialer::new(&[
        ("10.0.0.1:4000", Outcome::Connect),
        ("10.0.0.2:4000", Outcome::Connect),
    ]);
    let mut engine = engine(adapter, dialer, schedule());
    let first = match engine.acquire(Vec::new()).await {
        Ok(acquired) => acquired,
        Err(error) => unreachable!("first acquire failed: {error:?}"),
    };
    assert_eq!(first.backend.backend_id, "tidb-a");

    // Authentication failed against tidb-a; the handler permitted a
    // retry and the adapter pushed the next assignment.
    let second = match engine.reacquire_after_handshake().await {
        Ok(acquired) => acquired,
        Err(error) => unreachable!("re-selection failed: {error:?}"),
    };
    assert_eq!(second.backend.backend_id, "tidb-b", "distinct backend");
    let (channel, _) = engine.into_parts();
    assert_eq!(channel.requests, 1, "re-selection reuses the exchange");
    for id in ["a-1", "a-2"] {
        let results = results_for(&channel.results, id);
        assert_eq!(results.len(), 1, "{id} retired exactly once");
        assert!(results[0].connected);
    }
}

/// When the remaining budget cannot fit the next backoff, no failed
/// result is sent (the session stops re-selecting): the pending
/// assignment goes to `ConnectionEvent(CLOSED)` accounting — nothing
/// leaks router score.
#[tokio::test(start_paused = true)]
async fn pre_dial_exhaustion_hands_assignment_to_close_accounting() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    adapter
        .assignments
        .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
    let dialer = FakeDialer::new(&[
        ("10.0.0.1:4000", Outcome::Refuse),
        ("10.0.0.2:4000", Outcome::Connect),
    ]);
    // Budget fits the first dial but not the backoff before the second.
    let config = DialSchedule {
        total: Duration::from_millis(50),
        ..schedule()
    };
    let mut engine = engine(adapter, dialer, config);
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("budget cannot fit the retry")
    };
    assert!(matches!(error, AcquireError::BudgetExhausted { .. }));
    assert_eq!(
        engine.unretired_assignment(),
        Some("a-2"),
        "the unattempted assignment goes to close accounting, not a failed result"
    );
    let (channel, _) = engine.into_parts();
    assert_eq!(
        results_for(&channel.results, "a-1").len(),
        1,
        "failed dial retired"
    );
    assert!(
        results_for(&channel.results, "a-2").is_empty(),
        "no failed result for a locally-terminal outcome"
    );
}

/// Session teardown mid-dial: cancelling the `acquire` future sends no
/// failed result (which would make the adapter reserve another backend
/// for a dying session); the consumed assignment surfaces through
/// `unretired_assignment` for `ConnectionEvent(CLOSED)` accounting.
#[tokio::test(start_paused = true)]
async fn cancelled_acquire_leaves_assignment_to_close_accounting() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Hang)]);
    let mut engine = engine(adapter, dialer, schedule());
    {
        let acquire = engine.acquire(Vec::new());
        tokio::pin!(acquire);
        let raced = tokio::time::timeout(Duration::from_millis(500), &mut acquire).await;
        assert!(
            raced.is_err(),
            "the dial is mid-flight when the close lands"
        );
        // The future drops here: teardown mid-dial.
    }
    assert_eq!(
        engine.unretired_assignment(),
        Some("a-1"),
        "close accounting owns the in-flight assignment"
    );
    let (channel, _) = engine.into_parts();
    assert!(
        channel.results.is_empty(),
        "no failed result on teardown: CLOSED retires it Go-side"
    );
}

/// A cluster-unaware dialer must not silently ignore a non-empty
/// cluster scope: the engine fails closed with the typed error and the
/// assignment goes to close accounting.
#[tokio::test(start_paused = true)]
async fn cluster_scope_fails_closed_on_unaware_dialer() {
    struct DirectOnly;
    impl BackendDialer for DirectOnly {
        // CLUSTER_AWARE stays the default: false.
        type Conn = ();

        async fn dial(&mut self, _address: &str, _cluster_name: &str) -> Result<(), DialFailure> {
            Ok(())
        }
    }
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    let mut engine = RouteEngine::new(
        adapter,
        DirectOnly,
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("must fail closed")
    };
    assert_eq!(
        error,
        AcquireError::ClusterUnsupported {
            cluster_name: "cluster-a".to_owned()
        }
    );
    assert_eq!(engine.unretired_assignment(), Some("a-1"));

    // An empty cluster scope dials fine on the same dialer.
    let mut adapter = FakeAdapter::default();
    adapter.assignments.push_back(RouteAssignment {
        cluster_name: String::new(),
        ..assignment("a-2", "tidb-b", "10.0.0.2:4000")
    });
    let mut engine = RouteEngine::new(
        adapter,
        DirectOnly,
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );
    assert!(engine.acquire(Vec::new()).await.is_ok());
}

/// The assignment's exact `cluster_name` reaches every dial attempt
/// (Go `BackendDialer.DialContext` passthrough).
#[tokio::test(start_paused = true)]
async fn cluster_name_passes_through_to_every_dial() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    adapter
        .assignments
        .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
    let dialer = FakeDialer::new(&[
        ("10.0.0.1:4000", Outcome::Refuse),
        ("10.0.0.2:4000", Outcome::Connect),
    ]);
    let mut engine = engine(adapter, dialer, schedule());
    assert!(engine.acquire(Vec::new()).await.is_ok());
    let (_, dialer) = engine.into_parts();
    assert_eq!(dialer.attempts.len(), 2);
    for (_, cluster, _) in &dialer.attempts {
        assert_eq!(cluster, "cluster-a", "exact passthrough on every dial");
    }
}

/// `SplitMixJitter` is deterministic per input, in-range, and
/// desynchronized across assignments and connections; extreme and
/// non-finite injected jitter maps to the documented delay bounds.
#[tokio::test(start_paused = true)]
async fn jitter_semantics_are_deterministic_and_bounded() {
    struct Fixed(f64);
    impl JitterSource for Fixed {
        fn jitter(&mut self, _assignment_id: &str, _attempt: u32) -> f64 {
            self.0
        }
    }

    let mut a = SplitMixJitter::for_connection(7);
    let mut b = SplitMixJitter::for_connection(7);
    let mut c = SplitMixJitter::for_connection(8);
    let same = a.jitter("assign-1", 1);
    assert!((0.0..=1.0).contains(&same));
    assert!(
        (same - b.jitter("assign-1", 1)).abs() < f64::EPSILON,
        "deterministic"
    );
    assert!(
        (same - c.jitter("assign-1", 1)).abs() > f64::EPSILON,
        "connections desynchronize"
    );
    assert!(
        (same - a.jitter("assign-2", 1)).abs() > f64::EPSILON,
        "assignments desynchronize"
    );

    // Extreme jitter: with RandomizationFactor 0.5 the first delay is
    // nominal 100ms scaled into [50ms, 150ms]; non-finite jitter falls
    // back to centered (100ms). Observed through real waits.
    for (raw, expected_ms) in [(0.0, 50), (1.0, 150), (f64::NAN, 100)] {
        let mut adapter = FakeAdapter::default();
        adapter
            .assignments
            .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
        adapter
            .assignments
            .push_back(assignment("a-2", "tidb-b", "10.0.0.2:4000"));
        let dialer = FakeDialer::new(&[
            ("10.0.0.1:4000", Outcome::Refuse),
            ("10.0.0.2:4000", Outcome::Connect),
        ]);
        let start = Instant::now();
        let mut engine = RouteEngine::new(
            adapter,
            dialer,
            DialSchedule::default(),
            Fixed(raw),
            CONN_ID,
        );
        assert!(engine.acquire(Vec::new()).await.is_ok());
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(expected_ms),
            "raw jitter {raw} maps to {expected_ms}ms"
        );
    }
}

/// The total budget bounds even an in-flight dial (Go's dialCtx is a
/// child of bctx): with total < per-dial and a hanging first dial, the
/// engine stops exactly at the total deadline and the assignment goes
/// to close accounting.
#[tokio::test(start_paused = true)]
async fn total_budget_cuts_a_hanging_dial() {
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Hang)]);
    let config = DialSchedule {
        total: Duration::from_millis(300),
        per_dial: Duration::from_secs(1),
        ..DialSchedule::default()
    };
    let start = Instant::now();
    let mut engine = engine(adapter, dialer, config);
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("hanging dial past the budget must not connect")
    };
    assert!(matches!(
        error,
        AcquireError::BudgetExhausted {
            last_failure: Some(DialFailure::Timeout)
        }
    ));
    assert_eq!(
        start.elapsed(),
        Duration::from_millis(300),
        "cut exactly at the total deadline, not per-dial"
    );
    assert_eq!(
        engine.unretired_assignment(),
        Some("a-1"),
        "the in-flight assignment goes to close accounting"
    );
    let (channel, _) = engine.into_parts();
    assert!(channel.results.is_empty());
}

/// A result send that fails (or is cancelled mid-send) must not shed
/// the retirement obligation: `unretired` stays set and the report
/// count is untouched, so CLOSED accounting still covers the
/// assignment the adapter may consider open.
#[tokio::test(start_paused = true)]
async fn failed_or_cancelled_report_keeps_the_obligation() {
    // Case 1: the send fails with ControlLost.
    struct FailingReport {
        assignments: VecDeque<RouteAssignment>,
    }
    impl RouteChannel for FailingReport {
        async fn request_route(
            &mut self,
            _excluded_backend_ids: Vec<String>,
        ) -> Result<(), RouteChannelError> {
            Ok(())
        }
        async fn next_assignment(&mut self) -> Result<RouteAssignment, RouteChannelError> {
            self.assignments
                .pop_front()
                .ok_or(RouteChannelError::ControlLost)
        }
        async fn report_result(&mut self, _result: RouteResult) -> Result<(), RouteChannelError> {
            Err(RouteChannelError::ControlLost)
        }
    }
    struct HangingReport {
        assignments: VecDeque<RouteAssignment>,
    }
    impl RouteChannel for HangingReport {
        async fn request_route(
            &mut self,
            _excluded_backend_ids: Vec<String>,
        ) -> Result<(), RouteChannelError> {
            Ok(())
        }
        async fn next_assignment(&mut self) -> Result<RouteAssignment, RouteChannelError> {
            self.assignments
                .pop_front()
                .ok_or(RouteChannelError::ControlLost)
        }
        async fn report_result(&mut self, _result: RouteResult) -> Result<(), RouteChannelError> {
            std::future::pending().await
        }
    }
    let mut assignments = VecDeque::new();
    assignments.push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Refuse)]);
    let mut engine = RouteEngine::new(
        FailingReport { assignments },
        dialer,
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );
    let Err(error) = engine.acquire(Vec::new()).await else {
        unreachable!("send failure must surface")
    };
    assert_eq!(error, AcquireError::Channel(RouteChannelError::ControlLost));
    assert_eq!(
        engine.unretired_assignment(),
        Some("a-1"),
        "failed send keeps the obligation"
    );
    assert_eq!(engine.stats().results_reported, 0, "no phantom report");

    // Case 2: the report future is cancelled mid-send.
    let mut assignments = VecDeque::new();
    assignments.push_back(assignment("a-1", "tidb-a", "10.0.0.1:4000"));
    let dialer = FakeDialer::new(&[("10.0.0.1:4000", Outcome::Refuse)]);
    let mut engine = RouteEngine::new(
        HangingReport { assignments },
        dialer,
        DialSchedule::default(),
        CenteredJitter,
        CONN_ID,
    );
    {
        let acquire = engine.acquire(Vec::new());
        tokio::pin!(acquire);
        let raced = tokio::time::timeout(Duration::from_millis(200), &mut acquire).await;
        assert!(raced.is_err(), "the report send is mid-flight");
        // Cancelled here: teardown while the result was in the queue.
    }
    assert_eq!(
        engine.unretired_assignment(),
        Some("a-1"),
        "cancelled send keeps the obligation"
    );
    assert_eq!(engine.stats().results_reported, 0);
}

/// Only an explicit OK is a backend-carrying assignment: UNSPECIFIED
/// (the proto default) and an OK assignment missing required backend
/// fields are typed protocol terminals, never dialed.
#[tokio::test(start_paused = true)]
async fn unspecified_and_malformed_assignments_are_terminal() {
    // UNSPECIFIED code.
    let mut adapter = FakeAdapter::default();
    adapter
        .assignments
        .push_back(terminal(ErrorCode::Unspecified, "default fields"));
    let dialer = FakeDialer::new(&[]);
    let mut unspecified_engine = engine(adapter, dialer, schedule());
    let Err(error) = unspecified_engine.acquire(Vec::new()).await else {
        unreachable!("UNSPECIFIED must be terminal")
    };
    assert_eq!(
        error,
        AcquireError::Routing {
            code: ErrorCode::Unspecified,
            detail: "default fields".to_owned()
        }
    );
    let (_, dialer) = unspecified_engine.into_parts();
    assert!(dialer.attempts.is_empty(), "never dialed");

    // OK but missing backend_address.
    let mut adapter = FakeAdapter::default();
    adapter.assignments.push_back(RouteAssignment {
        backend_address: String::new(),
        ..assignment("a-1", "tidb-a", "ignored")
    });
    let dialer = FakeDialer::new(&[]);
    let mut malformed_engine = engine(adapter, dialer, schedule());
    let Err(error) = malformed_engine.acquire(Vec::new()).await else {
        unreachable!("malformed OK must be terminal")
    };
    assert_eq!(
        error,
        AcquireError::MalformedAssignment {
            field: "backend_address"
        }
    );
    let (_, dialer) = malformed_engine.into_parts();
    assert!(dialer.attempts.is_empty(), "never dialed");
}
