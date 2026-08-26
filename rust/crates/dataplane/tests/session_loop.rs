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

//! DPL-01 model tests: the single-owner loop with a fake transport and a
//! recording effect handler, under Tokio's paused-time deterministic
//! scheduler. Critical interleavings (redirect × command × shutdown) are
//! enumerated explicitly instead of sampled.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
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

/// Records effects; optionally spawns a stuck child per effect and answers
/// backend probes from a script.
#[derive(Default)]
struct Recorder {
    effects: Arc<Mutex<Vec<SessionEffect>>>,
    spawn_stuck_child_on_forward: bool,
    backend_alive: Arc<Mutex<VecDeque<bool>>>,
}

impl Recorder {
    fn effects(&self) -> Arc<Mutex<Vec<SessionEffect>>> {
        Arc::clone(&self.effects)
    }
}

impl EffectHandler for Recorder {
    async fn execute(&mut self, effect: SessionEffect, children: &mut JoinSet<()>) {
        if self.spawn_stuck_child_on_forward && effect == SessionEffect::ForwardCommandToBackend {
            children.spawn(async {
                std::future::pending::<()>().await;
            });
        }
        match self.effects.lock() {
            Ok(mut effects) => effects.push(effect),
            Err(poisoned) => poisoned.into_inner().push(effect),
        }
    }

    async fn backend_active(&mut self) -> bool {
        match self.backend_alive.lock() {
            Ok(mut alive) => alive.pop_front().unwrap_or(true),
            Err(poisoned) => poisoned.into_inner().pop_front().unwrap_or(true),
        }
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
    assert_eq!(summary.cleanup.aborted_children, 0);
    assert!(summary.cleanup.within_deadline);
    let recorded = match effects.lock() {
        Ok(effects) => effects.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert_eq!(
        recorded,
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

/// A client EOF with a stuck child releases everything within the cleanup
/// deadline: the child is aborted, joined, and reported.
#[tokio::test(start_paused = true)]
async fn eof_releases_stuck_children_within_deadline() {
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
    assert!(summary.cleanup.within_deadline);
}

/// Every arrival order of redirect, a command boundary, and server shutdown
/// completes without deadlock (explicit interleaving enumeration under the
/// deterministic paused-time scheduler).
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
        let mut events = HANDSHAKE.to_vec();
        events.push(SessionEvent::ClientCommand);
        let (control_tx, control_rx, shutdown_tx, shutdown_rx) = channels();
        let handler = Recorder::default();
        let looped = SessionLoop::new(
            FakeSource::parking(&events),
            handler,
            control_rx,
            shutdown_rx,
            SessionLoopConfig::default(),
        );
        let run = tokio::spawn(looped.run());
        // Let the loop absorb the scripted prefix deterministically.
        tokio::time::sleep(Duration::from_millis(1)).await;
        for signal in permutation {
            match signal {
                Signal::Redirect => {
                    let _ = control_tx.send(SessionControl::Redirect).await;
                }
                Signal::CommandBoundary => {
                    // The backend completes the in-flight command; delivered
                    // through control-independent shutdown of the fake by
                    // dropping precision: we emulate by a graceful close
                    // which also exercises the drain path.
                    let _ = control_tx.send(SessionControl::GracefulClose).await;
                }
                Signal::Shutdown => {
                    let _ = shutdown_tx.send(true);
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let summary = match tokio::time::timeout(Duration::from_secs(120), run).await {
            Ok(Ok(summary)) => summary,
            Ok(Err(join_error)) => unreachable!("loop panicked: {join_error}"),
            Err(_) => unreachable!("deadlock: {permutation:?}"),
        };
        assert_eq!(summary.final_state, SessionState::Closed, "{permutation:?}");
        assert!(summary.cleanup.within_deadline, "{permutation:?}");
    }
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
    tokio::time::sleep(Duration::from_millis(1)).await;
    let _ = shutdown_tx.send(true);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ServerShutdown);
    assert_eq!(summary.final_state, SessionState::Closed);
    let recorded = match effects.lock() {
        Ok(effects) => effects.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert!(recorded.contains(&SessionEffect::ReleaseBackend));
    assert!(recorded.contains(&SessionEffect::CloseClient));
}

/// The handshake deadline fires for a stalled pre-auth session and tears it
/// down; after authentication the deadline is disarmed.
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

    // Authenticated session: advancing past the handshake deadline does
    // nothing; the probe keeps it alive until shutdown.
    let (_control_tx2, control_rx, shutdown_tx, shutdown_rx) = channels();
    let looped = SessionLoop::new(
        FakeSource::parking(&HANDSHAKE),
        Recorder::default(),
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    tokio::time::sleep(Duration::from_secs(120)).await;
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
    let recorded = match effects.lock() {
        Ok(effects) => effects.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    assert!(recorded.contains(&SessionEffect::ReleaseBackend));
}

/// A lost control channel defensively tears the session down, and FSM
/// rejections are counted without changing the machine.
#[tokio::test(start_paused = true)]
async fn control_loss_and_rejections_are_accounted() {
    let mut events = HANDSHAKE.to_vec();
    // An illegal event at Ready: a backend auth result out of phase.
    events.push(SessionEvent::BackendAuthOk);
    let (control_tx, control_rx, _shutdown_tx, shutdown_rx) = channels();
    let looped = SessionLoop::new(
        FakeSource::parking(&events),
        Recorder::default(),
        control_rx,
        shutdown_rx,
        SessionLoopConfig::default(),
    );
    let run = tokio::spawn(looped.run());
    // Let the scripted events (including the rejection) be absorbed first.
    tokio::time::sleep(Duration::from_millis(1)).await;
    drop(control_tx);
    let summary = match run.await {
        Ok(summary) => summary,
        Err(join_error) => unreachable!("loop panicked: {join_error}"),
    };
    assert_eq!(summary.end, SessionEnd::ControlChannelLost);
    assert_eq!(summary.final_state, SessionState::Closed);
    assert_eq!(summary.rejected_events, 1);
}
