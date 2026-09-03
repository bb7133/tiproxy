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

//! DPL-01 model tests: the single-owner loop with fake transports and a
//! recording effect handler, under Tokio's paused-time deterministic
//! scheduler. Critical interleavings (redirect × command boundary ×
//! shutdown) are enumerated explicitly with quiesced hand-offs, plus a
//! shutdown-precheck domination case and a genuine three-select-arm
//! race (handler gate + pump relay proof, arms without any precheck);
//! the pump architecture is exercised with a multi-await
//! classifier under select-arm noise, a read-ahead bound proof, and a
//! terminal-cleanup budget/ordering proof.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use dataplane::session::{
    EffectHandler, SessionControl, SessionEnd, SessionEventSource, SessionLoop, SessionLoopConfig,
};
use session_core::fsm::{SessionEffect, SessionEvent, SessionState};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

/// Yields scripted events, then either ends the transport or parks forever.
struct FakeSource {
    events: VecDeque<SessionEvent>,
    park_when_empty: bool,
}

impl FakeSource {
    fn scripted(events: &[SessionEvent]) -> Self {
        Self {
            events: events.iter().copied().collect(),
            park_when_empty: false,
        }
    }

    fn parking(events: &[SessionEvent]) -> Self {
        Self {
            events: events.iter().copied().collect(),
            park_when_empty: true,
        }
    }
}

impl SessionEventSource for FakeSource {
    async fn next_event(&mut self) -> Option<SessionEvent> {
        match self.events.pop_front() {
            Some(event) => Some(event),
            None if self.park_when_empty => std::future::pending().await,
            None => None,
        }
    }
}

/// A live transport the test feeds while the loop runs; `None` (channel
/// closed) is transport exhaustion.
struct ChannelSource {
    rx: mpsc::Receiver<SessionEvent>,
}

impl ChannelSource {
    fn new() -> (mpsc::Sender<SessionEvent>, Self) {
        let (tx, rx) = mpsc::channel(32);
        (tx, Self { rx })
    }
}

impl SessionEventSource for ChannelSource {
    async fn next_event(&mut self) -> Option<SessionEvent> {
        self.rx.recv().await
    }
}

/// A classifier whose `next_event` awaits **twice** per event (two
/// "half-packets"), holding partial state across the await — the shape
/// that a select-cancelled future would corrupt. The pump must poll it to
/// completion, so no half may ever be lost or re-read.
struct MultiAwaitSource {
    halves: mpsc::Receiver<SessionEvent>,
    completed: Arc<AtomicU64>,
}

impl SessionEventSource for MultiAwaitSource {
    async fn next_event(&mut self) -> Option<SessionEvent> {
        // First half: the event kind arrives.
        let first = self.halves.recv().await?;
        // Partial state (`first`) is live across this second await; a
        // dropped future here would lose it.
        let second = self.halves.recv().await?;
        assert_eq!(first, second, "half-packets torn apart by cancellation");
        self.completed.fetch_add(1, Ordering::SeqCst);
        Some(first)
    }
}

/// Counts completed transport reads: the counter increments only after
/// an event is fully consumed from the inner channel, so it measures how
/// far ahead of the loop the classifier has actually read.
struct CountingSource {
    rx: mpsc::Receiver<SessionEvent>,
    completed_reads: Arc<AtomicU64>,
}

impl CountingSource {
    fn new() -> (mpsc::Sender<SessionEvent>, Arc<AtomicU64>, Self) {
        let (tx, rx) = mpsc::channel(32);
        let completed_reads = Arc::new(AtomicU64::new(0));
        (
            tx,
            Arc::clone(&completed_reads),
            Self {
                rx,
                completed_reads,
            },
        )
    }
}

impl SessionEventSource for CountingSource {
    async fn next_event(&mut self) -> Option<SessionEvent> {
        let event = self.rx.recv().await?;
        self.completed_reads.fetch_add(1, Ordering::SeqCst);
        Some(event)
    }
}

/// Flags its own drop: the source stands in for the transport, so the
/// flag marks the instant the transport's resources release.
struct DropFlagSource {
    inner: FakeSource,
    dropped: Arc<AtomicBool>,
}

impl Drop for DropFlagSource {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl SessionEventSource for DropFlagSource {
    async fn next_event(&mut self) -> Option<SessionEvent> {
        self.inner.next_event().await
    }
}

/// Records effects; optionally spawns children per effect and answers
/// backend probes from a script while counting probe calls.
#[derive(Default)]
struct Recorder {
    effects: Arc<Mutex<Vec<SessionEffect>>>,
    spawn_stuck_child_on_forward: bool,
    /// On `CloseBackend`, spawn a teardown child that finishes only after
    /// a paused-time delay and then flips the flag: proves cleanup drains
    /// instead of aborting.
    spawn_slow_teardown_child: Option<(Duration, Arc<AtomicBool>)>,
    backend_alive: Arc<Mutex<VecDeque<bool>>>,
    probe_calls: Arc<AtomicU64>,
    /// When set, the first `ForwardCommandToBackend` blocks the loop
    /// mid-apply until the test releases the gate — a real barrier for
    /// loading select arms while the loop is provably not selecting.
    forward_gate: Option<Arc<tokio::sync::Semaphore>>,
    /// Spawn an instantly-completing child on `ForwardCommandToBackend`
    /// (before any gate) that flips the flag when it finishes, so the
    /// finished-child select arm is **provably** ready while the loop is
    /// gated.
    spawn_instant_child_on_forward: Option<Arc<AtomicBool>>,
}

impl Recorder {
    fn effects(&self) -> Arc<Mutex<Vec<SessionEffect>>> {
        Arc::clone(&self.effects)
    }
}

fn locked<T: Clone>(cell: &Arc<Mutex<T>>) -> T {
    match cell.lock() {
        Ok(inner) => inner.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

impl EffectHandler for Recorder {
    async fn execute(&mut self, effect: SessionEffect, children: &mut JoinSet<()>) {
        if effect == SessionEffect::ForwardCommandToBackend
            && let Some(done) = &self.spawn_instant_child_on_forward
        {
            let done = Arc::clone(done);
            children.spawn(async move {
                done.store(true, Ordering::SeqCst);
            });
        }
        if effect == SessionEffect::ForwardCommandToBackend
            && let Some(gate) = self.forward_gate.take()
        {
            // Hold the loop here until the test opens the gate.
            let permit = gate.acquire().await;
            drop(permit);
        }
        if self.spawn_stuck_child_on_forward && effect == SessionEffect::ForwardCommandToBackend {
            children.spawn(async {
                std::future::pending::<()>().await;
            });
        }
        if effect == SessionEffect::CloseBackend
            && let Some((delay, flag)) = &self.spawn_slow_teardown_child
        {
            let delay = *delay;
            let flag = Arc::clone(flag);
            children.spawn(async move {
                tokio::time::sleep(delay).await;
                flag.store(true, Ordering::SeqCst);
            });
        }
        match self.effects.lock() {
            Ok(mut effects) => effects.push(effect),
            Err(poisoned) => poisoned.into_inner().push(effect),
        }
    }

    async fn backend_active(&mut self) -> bool {
        self.probe_calls.fetch_add(1, Ordering::SeqCst);
        match self.backend_alive.lock() {
            Ok(mut alive) => alive.pop_front().unwrap_or(true),
            Err(poisoned) => poisoned.into_inner().pop_front().unwrap_or(true),
        }
    }
}

/// Wraps a `Recorder` and, on `CloseBackend`, spawns a teardown child
/// that spins (paused-time sleeps) until the source-drop flag is
/// observed, then records that it saw the drop.
struct SpinUntilDropHandler {
    inner: Recorder,
    source_dropped: Arc<AtomicBool>,
    seen_drop: Arc<AtomicBool>,
}

impl EffectHandler for SpinUntilDropHandler {
    async fn execute(&mut self, effect: SessionEffect, children: &mut JoinSet<()>) {
        if effect == SessionEffect::CloseBackend {
            let dropped = Arc::clone(&self.source_dropped);
            let seen = Arc::clone(&self.seen_drop);
            children.spawn(async move {
                while !dropped.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                seen.store(true, Ordering::SeqCst);
            });
            // Also record the effect itself.
            self.inner
                .execute(SessionEffect::CloseBackend, children)
                .await;
            return;
        }
        self.inner.execute(effect, children).await;
    }

    async fn backend_active(&mut self) -> bool {
        self.inner.backend_active().await
    }
}

fn channels() -> (
    mpsc::Sender<SessionControl>,
    mpsc::Receiver<SessionControl>,
    watch::Sender<bool>,
    watch::Receiver<bool>,
) {
    let (control_tx, control_rx) = mpsc::channel(8);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    (control_tx, control_rx, shutdown_tx, shutdown_rx)
}

const HANDSHAKE: [SessionEvent; 4] = [
    SessionEvent::ConnectionAccepted,
    SessionEvent::ClientHandshakeResponse,
    SessionEvent::BackendGreetingReceived,
    SessionEvent::BackendAuthOk,
];

/// Runs every ready task to quiescence under the paused-time
/// current-thread scheduler without advancing the clock: all hand-offs in
/// these tests are ready-driven, so a bounded yield burst is a
/// deterministic barrier.
async fn quiesce() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

fn count(effects: &[SessionEffect], wanted: SessionEffect) -> usize {
    effects.iter().filter(|effect| **effect == wanted).count()
}

/// The scripted lifecycle runs to `Closed` through the FSM with effects in
/// order and nothing left running.
#[tokio::test(start_paused = true)]
async fn scripted_lifecycle_completes_cleanly() {
    let mut events = HANDSHAKE.to_vec();
    events.extend([
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnDone,
        SessionEvent::ClientCommandQuit,
        SessionEvent::TeardownComplete,
    ]);
    let (_control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder::default();
    let effects = handler.effects();
    let summary = SessionLoop::new(
        FakeSource::scripted(&events),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;

    assert_eq!(summary.end, SessionEnd::Closed);
    assert_eq!(summary.final_state, SessionState::Closed);
    assert_eq!(summary.rejected_events, 0);
    assert!(!summary.control_detached);
    assert_eq!(summary.cleanup.aborted_children, 0);
    assert!(summary.cleanup.within_deadline);
    assert_eq!(
        locked(&effects),
        vec![
            SessionEffect::SendProxyGreeting,
            SessionEffect::DialBackend,
            SessionEffect::ForwardHandshakeToBackend,
            SessionEffect::AttachBackend,
            SessionEffect::ForwardAuthResultToClient,
            SessionEffect::ForwardCommandToBackend,
            SessionEffect::ForwardResponseToClient,
            SessionEffect::ReleaseBackend,
            SessionEffect::CloseBackend,
            SessionEffect::CloseClient,
            SessionEffect::ClassifySessionEnd,
        ]
    );
}

/// A process-local coordinated drain can override the deadline captured when
/// the session was admitted. This is the dynamic-config path used at process
/// shutdown; ordinary control-plane graceful-close commands keep the admitted
/// default.
#[tokio::test(start_paused = true)]
async fn coordinated_drain_uses_latest_deadline_override() {
    let (control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let mut events = HANDSHAKE.to_vec();
    events.extend([
        SessionEvent::ClientCommand,
        SessionEvent::BackendResponseTxnOpen,
    ]);
    let looped = SessionLoop::new(
        FakeSource::parking(&events),
        Recorder::default(),
        control_rx,
        shutdown_rx,
        SessionLoopConfig {
            drain_deadline: Duration::from_secs(60),
            ..SessionLoopConfig::default()
        },
    );
    let run = tokio::spawn(looped.run());
    quiesce().await;
    let _ = control_tx
        .send(SessionControl::GracefulCloseAfter(Duration::from_secs(7)))
        .await;
    quiesce().await;

    tokio::time::advance(Duration::from_secs(6)).await;
    quiesce().await;
    assert!(!run.is_finished(), "override must not close early");

    tokio::time::advance(Duration::from_secs(1)).await;
    let summary = match run.await {
        Ok(summary) => summary,
        Err(error) => unreachable!("session loop panicked: {error}"),
    };
    assert_eq!(summary.end, SessionEnd::Closed);
    assert_eq!(summary.final_state, SessionState::Closed);
}

/// A client EOF with a stuck child still releases everything: the child
/// gets the drain window, is aborted only after it, and joins within the
/// second bound.
#[tokio::test(start_paused = true)]
async fn eof_aborts_stuck_children_after_drain_window() {
    let mut events = HANDSHAKE.to_vec();
    events.push(SessionEvent::ClientCommand);
    // Transport ends abruptly afterwards (client vanished).
    let (_control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder {
        spawn_stuck_child_on_forward: true,
        ..Recorder::default()
    };
    let summary = SessionLoop::new(
        FakeSource::scripted(&events),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;

    assert_eq!(summary.end, SessionEnd::TransportExhausted);
    assert_eq!(summary.final_state, SessionState::Closed);
    assert_eq!(summary.cleanup.aborted_children, 1, "stuck child aborted");
    assert!(
        summary.cleanup.within_deadline,
        "abort joined within the bound"
    );
}

/// Cleanup **drains before aborting**: a teardown child spawned by
/// `CloseBackend` that needs (paused) time to finish is allowed to
/// complete — it is not aborted, and its completion is observable.
#[tokio::test(start_paused = true)]
async fn teardown_children_drain_to_completion() {
    let mut events = HANDSHAKE.to_vec();
    events.push(SessionEvent::ClientCommandQuit);
    events.push(SessionEvent::TeardownComplete);
    let finished = Arc::new(AtomicBool::new(false));
    let (_control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder {
        // Inside the 5s cleanup deadline, but requires real draining.
        spawn_slow_teardown_child: Some((Duration::from_secs(2), Arc::clone(&finished))),
        ..Recorder::default()
    };
    let summary = SessionLoop::new(
        FakeSource::scripted(&events),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;

    assert_eq!(summary.end, SessionEnd::Closed);
    assert_eq!(summary.final_state, SessionState::Closed);
    assert!(
        finished.load(Ordering::SeqCst),
        "teardown child ran to completion"
    );
    assert_eq!(
        summary.cleanup.aborted_children, 0,
        "draining, not aborting"
    );
    assert!(summary.cleanup.within_deadline);
}

/// Every arrival order of a redirect command, a real transport command
/// boundary (`BackendResponseTxnDone`), and server shutdown completes
/// without deadlock, with teardown effects exactly once. Stimuli are
/// quiesced between steps, so each order is actually exercised.
#[tokio::test(start_paused = true)]
async fn redirect_command_shutdown_interleavings_never_deadlock() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Signal {
        Redirect,
        CommandBoundary,
        Shutdown,
    }
    let permutations: [[Signal; 3]; 6] = [
        [Signal::Redirect, Signal::CommandBoundary, Signal::Shutdown],
        [Signal::Redirect, Signal::Shutdown, Signal::CommandBoundary],
        [Signal::CommandBoundary, Signal::Redirect, Signal::Shutdown],
        [Signal::CommandBoundary, Signal::Shutdown, Signal::Redirect],
        [Signal::Shutdown, Signal::Redirect, Signal::CommandBoundary],
        [Signal::Shutdown, Signal::CommandBoundary, Signal::Redirect],
    ];
    for permutation in permutations {
        let (event_tx, source) = ChannelSource::new();
        let (control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
        let handler = Recorder::default();
        let effects = handler.effects();
        let looped = SessionLoop::new(
            source,
            handler,
            control_rx,
            shutdown_rx,
            SessionLoopConfig::default(),
        );
        let run = tokio::spawn(looped.run());
        for event in HANDSHAKE {
            let _ = event_tx.send(event).await;
        }
        // A command is in flight when the stimuli start.
        let _ = event_tx.send(SessionEvent::ClientCommand).await;
        quiesce().await;
        for signal in permutation {
            match signal {
                Signal::Redirect => {
                    let _ = control_tx.send(SessionControl::Redirect).await;
                }
                Signal::CommandBoundary => {
                    // The real transport boundary: the backend finishes the
                    // in-flight command out of transaction.
                    let _ = event_tx.send(SessionEvent::BackendResponseTxnDone).await;
                }
                Signal::Shutdown => {
                    let _ = shutdown_tx.send(true);
                }
            }
            quiesce().await;
        }
        // Whatever the order, the session must have been shut down.
        let summary = match tokio::time::timeout(Duration::from_secs(120), run).await {
            Ok(Ok(summary)) => summary,
            Ok(Err(join_error)) => unreachable!("loop panicked: {join_error}"),
            Err(_) => unreachable!("deadlock: {permutation:?}"),
        };
        assert_eq!(summary.end, SessionEnd::ServerShutdown, "{permutation:?}");
        assert_eq!(summary.final_state, SessionState::Closed, "{permutation:?}");
        assert!(summary.cleanup.within_deadline, "{permutation:?}");
        let recorded = locked(&effects);
        assert_eq!(
            count(&recorded, SessionEffect::ClassifySessionEnd),
            1,
            "teardown exactly once: {permutation:?}"
        );
        assert_eq!(
            count(&recorded, SessionEffect::CloseClient),
            1,
            "client closed exactly once: {permutation:?}"
        );
    }
}

/// Three stimuli **provably pending** while the loop is blocked inside a
/// gated handler call: a control command queued, the transport boundary
/// demonstrably relayed by the pump into the loop-facing channel
/// (completed-read counter), and shutdown set. On release the
/// `next_action` precheck observes the pre-existing shutdown **before
/// entering the select**, so shutdown dominates the pending work — the
/// outcome must be one clean shutdown with exactly-once teardown. (The
/// genuine three-select-arm race, with no precheck involved, is
/// `three_select_arms_race_cleanly` below.)
#[tokio::test(start_paused = true)]
async fn pending_stimuli_shutdown_precheck_dominates() {
    let (event_tx, reads, source) = CountingSource::new();
    let (control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let handler = Recorder {
        forward_gate: Some(Arc::clone(&gate)),
        ..Recorder::default()
    };
    let effects = handler.effects();
    let looped = SessionLoop::new(
        source,
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    for event in HANDSHAKE {
        let _ = event_tx.send(event).await;
    }
    // The command's ForwardCommandToBackend blocks on the gate: the loop
    // is now provably inside apply, not inside select.
    let _ = event_tx.send(SessionEvent::ClientCommand).await;
    quiesce().await;
    assert_eq!(reads.load(Ordering::SeqCst), 5, "loop is gated mid-apply");

    // Load every stimulus while the loop cannot observe any of them.
    let _ = control_tx.send(SessionControl::Redirect).await;
    let _ = event_tx.send(SessionEvent::BackendResponseTxnDone).await;
    quiesce().await;
    // The pump has finished relaying the boundary event into the
    // loop-facing one-slot channel: the transport stimulus is pending at
    // the loop's own channel, not upstream.
    assert_eq!(reads.load(Ordering::SeqCst), 6, "boundary relayed by pump");
    let _ = shutdown_tx.send(true);

    // Open the gate: the precheck sees shutdown before any select poll.
    gate.add_permits(1);
    let summary = match tokio::time::timeout(Duration::from_secs(120), run).await {
        Ok(Ok(summary)) => summary,
        Ok(Err(join_error)) => unreachable!("loop panicked: {join_error}"),
        Err(_) => unreachable!("deadlock with pending stimuli"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.final_state, SessionState::Closed);
    let recorded = locked(&effects);
    assert_eq!(count(&recorded, SessionEffect::ClassifySessionEnd), 1);
    assert_eq!(count(&recorded, SessionEffect::CloseClient), 1);
}

/// A **genuine** three-select-arm race: none of these arms has a
/// precheck, so on gate release the loop's very next `tokio::select!`
/// polls three simultaneously ready arms — a queued control command, a
/// finished child, and a pumped transport boundary event. The biased
/// order must hold observably: the redirect is queued first (control
/// beats the boundary event, so the redirect is already pending when
/// the boundary lands and fires `StartRedirectHandshake` exactly once),
/// the finished child is a no-op, and nothing is lost or rejected.
#[tokio::test(start_paused = true)]
async fn three_select_arms_race_cleanly() {
    let (event_tx, reads, source) = CountingSource::new();
    let (control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let child_done = Arc::new(AtomicBool::new(false));
    let handler = Recorder {
        forward_gate: Some(Arc::clone(&gate)),
        spawn_instant_child_on_forward: Some(Arc::clone(&child_done)),
        ..Recorder::default()
    };
    let effects = handler.effects();
    let looped = SessionLoop::new(
        source,
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    for event in HANDSHAKE {
        let _ = event_tx.send(event).await;
    }
    // The command's effect spawns an instantly-completing child, then
    // blocks on the gate: the loop is inside apply, not selecting.
    let _ = event_tx.send(SessionEvent::ClientCommand).await;
    quiesce().await;
    assert_eq!(reads.load(Ordering::SeqCst), 5, "loop is gated mid-apply");

    // Arm 1: control (queued redirect).
    let _ = control_tx.send(SessionControl::Redirect).await;
    // Arm 2: the child has already finished during the quiesce; its
    // join_next result is waiting.
    // Arm 3: the transport boundary, provably relayed into the
    // loop-facing channel by the pump.
    let _ = event_tx.send(SessionEvent::BackendResponseTxnDone).await;
    quiesce().await;
    assert_eq!(reads.load(Ordering::SeqCst), 6, "boundary relayed by pump");
    // The loop is still gated inside the handler, so the JoinSet cannot
    // have been reaped: a completed child here proves the join_next arm
    // is ready.
    assert!(
        child_done.load(Ordering::SeqCst),
        "child finished while the loop was gated"
    );

    // Release: the next select polls all three ready arms at once (no
    // precheck applies to any of them).
    gate.add_permits(1);
    quiesce().await;
    let recorded = locked(&effects);
    assert_eq!(
        count(&recorded, SessionEffect::ForwardResponseToClient),
        1,
        "boundary event survived the race"
    );
    assert_eq!(
        count(&recorded, SessionEffect::StartRedirectHandshake),
        1,
        "control won the biased race: the redirect was already queued at the boundary"
    );

    let _ = shutdown_tx.send(true);
    let summary = match tokio::time::timeout(Duration::from_secs(120), run).await {
        Ok(Ok(summary)) => summary,
        Ok(Err(join_error)) => unreachable!("loop panicked: {join_error}"),
        Err(_) => unreachable!("deadlock after the select race"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.final_state, SessionState::Closed);
    assert_eq!(summary.rejected_events, 0, "nothing lost or duplicated");
    let recorded = locked(&effects);
    assert_eq!(count(&recorded, SessionEffect::ClassifySessionEnd), 1);
    assert_eq!(count(&recorded, SessionEffect::CloseClient), 1);
}

/// The pump classifies at most one event ahead of the loop: while the
/// loop is blocked mid-apply and the one-slot channel is full, the
/// classifier does not consume further transport events.
#[tokio::test(start_paused = true)]
async fn classifier_reads_at_most_one_ahead() {
    let (event_tx, reads, source) = CountingSource::new();
    let (_control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let handler = Recorder {
        forward_gate: Some(Arc::clone(&gate)),
        ..Recorder::default()
    };
    let effects = handler.effects();
    let looped = SessionLoop::new(
        source,
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    for event in HANDSHAKE {
        let _ = event_tx.send(event).await;
    }
    let _ = event_tx.send(SessionEvent::ClientCommand).await;
    quiesce().await;
    // 5 events consumed; the loop is gated inside the command's effect.
    assert_eq!(reads.load(Ordering::SeqCst), 5);

    // Three more transport events are available. The pump may take
    // exactly one (into the free slot); the reserve-before-read contract
    // forbids classifying the second while the slot is occupied.
    let _ = event_tx.send(SessionEvent::BackendResponsePart).await;
    let _ = event_tx.send(SessionEvent::BackendResponsePart).await;
    let _ = event_tx.send(SessionEvent::BackendResponseTxnDone).await;
    quiesce().await;
    assert_eq!(
        reads.load(Ordering::SeqCst),
        6,
        "one event ahead at most; no speculative classification"
    );

    // Release the gate: everything flows and the command completes.
    gate.add_permits(1);
    quiesce().await;
    assert_eq!(
        reads.load(Ordering::SeqCst),
        8,
        "backlog drains after release"
    );
    let recorded = locked(&effects);
    assert_eq!(count(&recorded, SessionEffect::ForwardResponseToClient), 3);

    let _ = shutdown_tx.send(true);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.rejected_events, 0);
}

/// Terminal cleanup honors **one absolute budget** and stops the pump
/// first: with a stuck child, the whole terminal sequence (pump stop +
/// drain window + abort join) elapses at most `cleanup_deadline`, and
/// the source (transport stand-in) is dropped before a teardown child —
/// which spins until it observes that drop — completes.
#[tokio::test(start_paused = true)]
async fn terminal_cleanup_budget_and_source_release_order() {
    // Case 1: source released before the teardown child finishes.
    let source_dropped = Arc::new(AtomicBool::new(false));
    let teardown_seen_drop = Arc::new(AtomicBool::new(false));
    let mut events = HANDSHAKE.to_vec();
    events.push(SessionEvent::ClientCommandQuit);
    // Parking: the pump stays blocked inside `next_event`, holding the
    // source (transport stand-in), until terminal cleanup stops it. If
    // the pump were stopped after the child drain, the spinner below
    // could never finish and would be aborted instead.
    let source = DropFlagSource {
        inner: FakeSource::parking(&events),
        dropped: Arc::clone(&source_dropped),
    };
    let (_control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let handler = SpinUntilDropHandler {
        inner: Recorder::default(),
        source_dropped: Arc::clone(&source_dropped),
        seen_drop: Arc::clone(&teardown_seen_drop),
    };
    let start = tokio::time::Instant::now();
    let summary = SessionLoop::new(
        source,
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;
    assert_eq!(summary.end, SessionEnd::Closed);
    assert!(source_dropped.load(Ordering::SeqCst));
    assert!(
        teardown_seen_drop.load(Ordering::SeqCst),
        "teardown child observed the source drop before completing"
    );
    assert_eq!(summary.cleanup.aborted_children, 0);
    assert!(summary.cleanup.within_deadline);
    assert!(
        start.elapsed() <= Duration::from_secs(5),
        "well inside the budget: {:?}",
        start.elapsed()
    );

    // Case 2: a stuck child bounds the whole terminal sequence to one
    // cleanup_deadline.
    let mut events = HANDSHAKE.to_vec();
    events.push(SessionEvent::ClientCommand);
    let (_control_tx2, control_rx, _shutdown_tx2, shutdown_rx) = channels();
    let handler = Recorder {
        spawn_stuck_child_on_forward: true,
        ..Recorder::default()
    };
    let start = tokio::time::Instant::now();
    let summary = SessionLoop::new(
        FakeSource::scripted(&events),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;
    assert_eq!(summary.end, SessionEnd::TransportExhausted);
    assert_eq!(summary.cleanup.aborted_children, 1);
    let elapsed = start.elapsed();
    assert!(
        elapsed <= Duration::from_secs(5) + Duration::from_millis(50),
        "terminal sequence bounded by one cleanup_deadline: {elapsed:?}"
    );
}

/// Server shutdown closes an idle authenticated session immediately and
/// seals the FSM.
#[tokio::test(start_paused = true)]
async fn server_shutdown_closes_idle_session() {
    let (_control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder::default();
    let effects = handler.effects();
    let looped = SessionLoop::new(
        FakeSource::parking(&HANDSHAKE),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    quiesce().await;
    let _ = shutdown_tx.send(true);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.final_state, SessionState::Closed);
    let recorded = locked(&effects);
    assert!(recorded.contains(&SessionEffect::ReleaseBackend));
    assert!(recorded.contains(&SessionEffect::CloseClient));
}

/// A shutdown signal that predates the loop (`watch` already true at
/// start) is observed: the session closes as `ServerShutdown` with
/// teardown exactly once instead of waiting for a change that never
/// comes.
#[tokio::test(start_paused = true)]
async fn preexisting_shutdown_is_not_missed() {
    let (_control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let _ = shutdown_tx.send(true);
    let handler = Recorder::default();
    let effects = handler.effects();
    let summary = SessionLoop::new(
        FakeSource::parking(&[]),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.final_state, SessionState::Closed);
    let recorded = locked(&effects);
    assert_eq!(count(&recorded, SessionEffect::CloseClient), 1);
    assert_eq!(count(&recorded, SessionEffect::ClassifySessionEnd), 1);
}

/// The handshake deadline fires for a stalled pre-auth session; after the
/// `BackendAuthOk` **transition itself** it is disarmed — an authenticated
/// session that then goes fully idle (probe disabled, no further events)
/// survives far past the deadline.
#[tokio::test(start_paused = true)]
async fn handshake_deadline_only_before_authentication() {
    // Stalled pre-auth session: the deadline closes it.
    let (_control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let summary = SessionLoop::new(
        FakeSource::parking(&[SessionEvent::ConnectionAccepted]),
        Recorder::default(),
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;
    assert_eq!(summary.end, SessionEnd::Closed, "deadline sealed the FSM");
    assert_eq!(summary.final_state, SessionState::Closed);

    // Authenticated then **completely idle**: no probe, no transport
    // event, no control traffic. Only the post-transition disarm keeps
    // this session alive past the handshake deadline.
    let config = SessionLoopConfig {
        backend_check_interval: Duration::ZERO,
        ..SessionLoopConfig::default()
    };
    let (_control_tx2, control_rx, shutdown_tx, shutdown_rx) = channels();
    let looped = SessionLoop::new(
        FakeSource::parking(&HANDSHAKE),
        Recorder::default(),
        control_rx,
        shutdown_rx,
        config,
    );
    let run = tokio::spawn(looped.run());
    quiesce().await;
    // Far past the 30s handshake deadline; a still-armed timer would fire
    // here and close the session as `Closed`.
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert!(!run.is_finished(), "idle authenticated session survives");
    let _ = shutdown_tx.send(true);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown, "not timed out");
}

/// A dead backend probe injects `BackendIoError` and the session tears
/// down through the FSM.
#[tokio::test(start_paused = true)]
async fn dead_backend_probe_closes_session() {
    let (_control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder::default();
    match handler.backend_alive.lock() {
        Ok(mut alive) => {
            alive.push_back(true);
            alive.push_back(false);
        }
        Err(poisoned) => {
            let mut alive = poisoned.into_inner();
            alive.push_back(true);
            alive.push_back(false);
        }
    }
    let effects = handler.effects();
    let summary = SessionLoop::new(
        FakeSource::parking(&HANDSHAKE),
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    )
    .run()
    .await;
    assert_eq!(
        summary.end,
        SessionEnd::Closed,
        "probe failure sealed the FSM"
    );
    assert_eq!(summary.final_state, SessionState::Closed);
    let recorded = locked(&effects);
    assert!(recorded.contains(&SessionEffect::ReleaseBackend));
}

/// KA-003: the probe never runs while a command is in flight. Probe ticks
/// spanning an in-flight command do not call `backend_active`; returning
/// to `Ready` resumes probing.
#[tokio::test(start_paused = true)]
async fn probe_skips_in_flight_commands() {
    let (event_tx, source) = ChannelSource::new();
    let (_control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder::default();
    let probes = Arc::clone(&handler.probe_calls);
    let config = SessionLoopConfig {
        backend_check_interval: Duration::from_secs(1),
        ..SessionLoopConfig::default()
    };
    let looped = SessionLoop::new(source, handler, control_rx, shutdown_rx, config);
    let run = tokio::spawn(looped.run());
    for event in HANDSHAKE {
        let _ = event_tx.send(event).await;
    }
    quiesce().await;
    // Idle at Ready: ticks probe. Quiesce after the clock advance so
    // every due tick is fully processed before the count is read.
    tokio::time::sleep(Duration::from_secs(3)).await;
    quiesce().await;
    let idle_probes = probes.load(Ordering::SeqCst);
    assert!(idle_probes >= 2, "idle probes ticked: {idle_probes}");

    // In-flight command: ticks continue but must not probe.
    let _ = event_tx.send(SessionEvent::ClientCommand).await;
    quiesce().await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        probes.load(Ordering::SeqCst),
        idle_probes,
        "no probe while a command is in flight"
    );

    // Response completes; probing resumes.
    let _ = event_tx.send(SessionEvent::BackendResponseTxnDone).await;
    quiesce().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        probes.load(Ordering::SeqCst) > idle_probes,
        "probing resumes at the boundary"
    );

    let _ = shutdown_tx.send(true);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
}

/// Control-v1 last-good semantics: the per-session control channel
/// closing does **not** tear down the session. Traffic continues to full
/// command completion afterwards; only transport exhaustion ends it, and
/// the detachment is reported. FSM rejections are counted without
/// changing the machine.
#[tokio::test(start_paused = true)]
async fn control_detach_keeps_session_serving() {
    let (event_tx, source) = ChannelSource::new();
    let (control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder::default();
    let effects = handler.effects();
    let looped = SessionLoop::new(
        source,
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    for event in HANDSHAKE {
        let _ = event_tx.send(event).await;
    }
    // An illegal event at Ready: a backend auth result out of phase.
    let _ = event_tx.send(SessionEvent::BackendAuthOk).await;
    quiesce().await;

    // The control plane detaches mid-session.
    drop(control_tx);
    quiesce().await;
    assert!(!run.is_finished(), "control loss must not end the session");

    // The session still serves a complete command afterwards.
    let _ = event_tx.send(SessionEvent::ClientCommand).await;
    let _ = event_tx.send(SessionEvent::BackendResponseTxnDone).await;
    quiesce().await;
    let recorded = locked(&effects);
    assert_eq!(count(&recorded, SessionEffect::ForwardCommandToBackend), 1);
    assert_eq!(count(&recorded, SessionEffect::ForwardResponseToClient), 1);

    // Only the transport ends it.
    drop(event_tx);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::TransportExhausted);
    assert_eq!(summary.final_state, SessionState::Closed);
    assert!(summary.control_detached, "detachment reported");
    assert_eq!(summary.rejected_events, 1);
}

/// The pump owns classifier polling: a source that awaits twice per event
/// (partial state across the await) survives heavy select-arm noise —
/// every event arrives exactly once, in order, with no torn halves.
#[tokio::test(start_paused = true)]
async fn multi_await_classifier_survives_select_noise() {
    const COMMANDS: u64 = 10;
    let (half_tx, halves) = mpsc::channel::<SessionEvent>(4);
    let completed = Arc::new(AtomicU64::new(0));
    let source = MultiAwaitSource {
        halves,
        completed: Arc::clone(&completed),
    };
    let (_control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
    let handler = Recorder::default();
    let effects = handler.effects();
    let looped = SessionLoop::new(
        source,
        handler,
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());

    let mut script: Vec<SessionEvent> = HANDSHAKE.to_vec();
    for _ in 0..COMMANDS {
        script.push(SessionEvent::ClientCommand);
        script.push(SessionEvent::BackendResponseTxnDone);
    }
    for event in script {
        // First half, then select-arm noise (a watch write that keeps the
        // shutdown arm winning races without shutting down), then the
        // second half. Under the old in-select polling this interleaving
        // cancels the classifier future between the halves.
        let _ = half_tx.send(event).await;
        let _ = shutdown_tx.send(false);
        tokio::task::yield_now().await;
        let _ = shutdown_tx.send(false);
        let _ = half_tx.send(event).await;
        let _ = shutdown_tx.send(false);
        quiesce().await;
    }
    let expected = 4 + COMMANDS * 2;
    assert_eq!(
        completed.load(Ordering::SeqCst),
        expected,
        "every classified event completed exactly once"
    );
    let recorded = locked(&effects);
    assert_eq!(
        count(&recorded, SessionEffect::ForwardCommandToBackend),
        usize::try_from(COMMANDS).unwrap_or(usize::MAX),
    );
    assert_eq!(
        count(&recorded, SessionEffect::ForwardResponseToClient),
        usize::try_from(COMMANDS).unwrap_or(usize::MAX),
    );

    let _ = shutdown_tx.send(true);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.rejected_events, 0, "no torn or duplicated events");
}
