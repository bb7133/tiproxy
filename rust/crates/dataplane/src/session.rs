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

//! Single-owner session event loop (DPL-01).
//!
//! One task owns all mutable session state — the SES-00 FSM, timers, and
//! the child-operation set. There is no session mutex anywhere: effect
//! handlers borrow `&mut` slices of the loop's state for the duration of
//! one call, and child operations live in the session's [`JoinSet`], so
//! nothing detaches and nothing is shared.
//!
//! The transport classifier runs in its **own tracked pump task**: the
//! loop moves the [`SessionEventSource`] into a dedicated task that polls
//! `next_event` futures sequentially to completion and submits each
//! classified event through a bounded channel. The loop side selects on
//! that channel's `recv`, which is cancel-safe, so a classifier future is
//! **never dropped mid-read** no matter which select arm wins — the
//! cancel-safety of source implementations is structural, not documentary.
//!
//! The loop composes, in biased order: shutdown, control commands, the
//! armed deadline timer, the backend probe, finished child operations, and
//! pumped transport events. Every accepted event drives
//! [`SessionFsm::on_event`]; every returned effect goes to the injected
//! [`EffectHandler`], which may spawn **tracked** children but cannot own
//! session state.
//!
//! Control-plane loss follows the control-protocol v1 **last-good**
//! semantics: the per-session control channel closing must not tear down
//! an established SQL session. The loop disables the control arm and keeps
//! forwarding traffic; redirects and graceful closes simply stop arriving
//! until the control plane re-attaches through a new channel. Only the
//! transport, the client, or the server shutdown signal end the session.
//!
//! Cleanup on every exit path (client/backend EOF, cancel, error, or
//! normal close) runs under **one absolute budget**:
//! [`SessionLoopConfig::cleanup_deadline`] covers the whole terminal
//! sequence. The pump is stopped and joined **first** — the source (and
//! the transport it owns) releases before any teardown child is waited
//! on — then children get the remaining budget to finish normally
//! (teardown effects spawned into the set complete exactly once), and
//! only children still running at the deadline are aborted and joined
//! within the same absolute bound. Go parity notes: the handshake
//! deadline mirrors the frontend auth timeout and disarms on the
//! transition into an authenticated state; the periodic backend-active
//! check mirrors `checkBackendActive` and runs only in idle-safe states
//! (KA-003: never concurrent with command I/O); half-close follows Go — a
//! client EOF tears the session down rather than lingering on a half-open
//! pair.

use std::time::Duration;

use session_core::fsm::{SessionEffect, SessionEvent, SessionFsm, SessionState, TransitionError};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, sleep_until, timeout_at};

/// Control-plane commands delivered to one session's loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionControl {
    /// Migrate this session to a new backend at the next safe boundary.
    Redirect,
    /// Close gracefully at the next safe boundary.
    GracefulClose,
    /// Close immediately.
    CloseImmediate,
}

impl SessionControl {
    const fn session_event(self) -> SessionEvent {
        match self {
            Self::Redirect => SessionEvent::ControlRedirect,
            Self::GracefulClose => SessionEvent::ControlGracefulClose,
            Self::CloseImmediate => SessionEvent::ControlCloseImmediate,
        }
    }
}

/// Classified transport events for one session. The SES layers own the
/// classification; the loop never sees packet bytes.
///
/// The loop moves the source into a dedicated pump task that polls each
/// `next_event` future to completion before requesting the next one, so
/// implementations may hold partial read state across awaits without any
/// cancellation hazard.
pub trait SessionEventSource: Send + 'static {
    /// Waits for the next classified event. `None` means the transport is
    /// exhausted (both directions closed at the wire level).
    fn next_event(&mut self) -> impl Future<Output = Option<SessionEvent>> + Send;
}

/// Executes FSM effects. Implementations borrow the session's child set to
/// spawn tracked operations; they can never own a session lock.
pub trait EffectHandler: Send {
    /// Executes one effect in order. Long-running work must be spawned into
    /// `children` instead of blocking the loop.
    fn execute(
        &mut self,
        effect: SessionEffect,
        children: &mut JoinSet<()>,
    ) -> impl Future<Output = ()> + Send;

    /// Backend-liveness probe (Go `checkBackendActive`). Called only in
    /// idle-safe states (KA-003) — never while a command, response, or
    /// `LOCAL INFILE` exchange is in flight. Returning false injects
    /// [`SessionEvent::BackendIoError`].
    fn backend_active(&mut self) -> impl Future<Output = bool> + Send {
        async { true }
    }
}

/// Deadlines and probe cadence for one session loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLoopConfig {
    /// Deadline for completing the handshake phase (armed until the FSM
    /// authenticates; fires [`SessionEvent::HandshakeTimerExpired`]).
    pub handshake_deadline: Duration,
    /// Deadline armed by [`SessionEffect::BeginDrainTimer`]
    /// (fires [`SessionEvent::DrainTimerExpired`]).
    pub drain_deadline: Duration,
    /// Interval for the backend-active probe once authenticated. Zero
    /// disables the probe.
    pub backend_check_interval: Duration,
    /// Absolute budget for the whole terminal cleanup: stopping the pump
    /// (releasing the source/transport), letting children finish
    /// normally, and joining any aborted stragglers all share this one
    /// window.
    pub cleanup_deadline: Duration,
}

impl Default for SessionLoopConfig {
    fn default() -> Self {
        Self {
            handshake_deadline: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(30),
            backend_check_interval: Duration::from_secs(10),
            cleanup_deadline: Duration::from_secs(5),
        }
    }
}

/// Why the loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The FSM reached [`SessionState::Closed`].
    Closed,
    /// The server shutdown signal closed the session.
    ServerShutdown,
    /// The transport was exhausted before the FSM closed.
    TransportExhausted,
}

/// Deadline-bounded cleanup accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// Children aborted at exit because they outlived the drain deadline.
    pub aborted_children: usize,
    /// Whether every child finished (or joined after abort) within the
    /// configured bounds.
    pub within_deadline: bool,
}

/// The loop's final report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Why the loop stopped.
    pub end: SessionEnd,
    /// The FSM state at exit.
    pub final_state: SessionState,
    /// Total effects executed.
    pub effects_executed: u64,
    /// Events rejected by the FSM (protocol violations surfaced by the
    /// transport ordering); each left the machine unchanged.
    pub rejected_events: u64,
    /// Whether the control channel closed while the session kept running
    /// (control-v1 last-good: never a teardown reason by itself).
    pub control_detached: bool,
    /// Cleanup accounting.
    pub cleanup: CleanupReport,
}

/// Capacity of the pump channel between the classifier task and the loop.
/// One slot keeps the classifier in lockstep with the loop: it classifies
/// at most one event ahead, preserving the transport's natural
/// backpressure.
const EVENT_PUMP_CAPACITY: usize = 1;

/// The single owner of one session's mutable state.
pub struct SessionLoop<S, E> {
    fsm: SessionFsm,
    source: Option<S>,
    handler: E,
    control: mpsc::Receiver<SessionControl>,
    shutdown: watch::Receiver<bool>,
    config: SessionLoopConfig,
    children: JoinSet<()>,
    effects_executed: u64,
    rejected_events: u64,
    last_rejection: Option<TransitionError>,
    control_detached: bool,
    aborted_children_total: usize,
    cleanup_within_deadline: bool,
}

enum LoopAction {
    Event(SessionEvent),
    /// The armed one-shot deadline fired.
    Deadline(SessionEvent),
    SourceExhausted,
    ServerShutdown,
    ControlDetached,
    ChildFinished,
    BackendProbe,
}

impl<S: SessionEventSource, E: EffectHandler> SessionLoop<S, E> {
    /// Creates a session loop; the FSM starts at `Accept`.
    #[must_use]
    pub fn new(
        source: S,
        handler: E,
        control: mpsc::Receiver<SessionControl>,
        shutdown: watch::Receiver<bool>,
        config: SessionLoopConfig,
    ) -> Self {
        Self {
            fsm: SessionFsm::new(),
            source: Some(source),
            handler,
            control,
            shutdown,
            config,
            children: JoinSet::new(),
            effects_executed: 0,
            rejected_events: 0,
            last_rejection: None,
            control_detached: false,
            aborted_children_total: 0,
            cleanup_within_deadline: true,
        }
    }

    /// The most recent FSM rejection, for diagnostics.
    #[must_use]
    pub const fn last_rejection(&self) -> Option<TransitionError> {
        self.last_rejection
    }

    /// Runs the session to completion. All child tasks are joined or
    /// aborted, the pump task is stopped, and the transport is dropped
    /// before this returns.
    pub async fn run(mut self) -> SessionSummary {
        // The classifier pump: owns the source, polls every `next_event`
        // future to completion, and hands events over a bounded channel.
        // `events.recv()` below is cancel-safe, so losing a select race
        // can never drop a half-polled classifier future.
        let (event_tx, mut events) = mpsc::channel::<SessionEvent>(EVENT_PUMP_CAPACITY);
        // `new` always fills the slot; `run` consumes `self`.
        let Some(mut source) = self.source.take() else {
            unreachable!("session source taken twice")
        };
        let pump: JoinHandle<()> = tokio::spawn(async move {
            loop {
                // Reserve the slot **before** touching the transport: the
                // classifier reads at most one event ahead of the loop,
                // so transport backpressure is real (an unconsumed event
                // never triggers speculative classification of the next).
                let Ok(permit) = event_tx.reserve().await else {
                    break;
                };
                match source.next_event().await {
                    Some(event) => permit.send(event),
                    None => break,
                }
            }
        });

        let end = self.event_loop(&mut events).await;
        // One absolute budget for the whole terminal sequence.
        let cleanup_by = Instant::now() + self.config.cleanup_deadline;
        // Stop the pump first: the source — and the transport it owns —
        // must release before any teardown child is waited on, so
        // teardown work that needs the transport's file descriptors or
        // locks cannot deadlock against the pump.
        drop(events);
        pump.abort();
        self.cleanup_within_deadline &= timeout_at(cleanup_by, pump).await.is_ok();
        // Terminal accounting: reach Closed through the FSM when possible so
        // teardown effects execute exactly once.
        let end = match end {
            LoopEnd::FsmClosed => SessionEnd::Closed,
            LoopEnd::Shutdown => {
                self.close_via_fsm(SessionEvent::ControlCloseImmediate)
                    .await;
                SessionEnd::ServerShutdown
            }
            LoopEnd::SourceExhausted => {
                self.close_via_fsm(SessionEvent::ClientEof).await;
                SessionEnd::TransportExhausted
            }
        };
        let cleanup = self.cleanup_within(cleanup_by).await;
        SessionSummary {
            end,
            final_state: self.fsm.state(),
            effects_executed: self.effects_executed,
            rejected_events: self.rejected_events,
            control_detached: self.control_detached,
            cleanup,
        }
    }

    async fn event_loop(&mut self, events: &mut mpsc::Receiver<SessionEvent>) -> LoopEnd {
        let handshake_deadline = Instant::now() + self.config.handshake_deadline;
        let mut armed_deadline: Option<(Instant, SessionEvent)> =
            Some((handshake_deadline, SessionEvent::HandshakeTimerExpired));
        let mut next_probe = (!self.config.backend_check_interval.is_zero())
            .then(|| Instant::now() + self.config.backend_check_interval);

        loop {
            if self.fsm.state() == SessionState::Closed {
                return LoopEnd::FsmClosed;
            }
            if self.fsm.state() == SessionState::Closing {
                // The loop is the runtime: teardown effects have executed
                // and their children are tracked, so seal the FSM now;
                // the children drain in the terminal cleanup, under the
                // single absolute budget, after the pump releases the
                // transport.
                self.apply(SessionEvent::TeardownComplete, &mut armed_deadline)
                    .await;
                continue;
            }
            let action = self.next_action(events, armed_deadline, next_probe).await;
            match action {
                LoopAction::ServerShutdown => return LoopEnd::Shutdown,
                LoopAction::SourceExhausted => return LoopEnd::SourceExhausted,
                LoopAction::ControlDetached => {
                    // Control-v1 last-good: losing the control channel never
                    // tears down an established session. Redirect/drain
                    // commands stop arriving; traffic continues.
                    self.control_detached = true;
                }
                LoopAction::ChildFinished => {}
                LoopAction::BackendProbe => {
                    if let Some(probe) = next_probe.as_mut() {
                        *probe = Instant::now() + self.config.backend_check_interval;
                    }
                    if probe_safe(self.fsm.state()) && !self.handler.backend_active().await {
                        self.apply(SessionEvent::BackendIoError, &mut armed_deadline)
                            .await;
                    }
                }
                LoopAction::Deadline(event) => {
                    armed_deadline = None;
                    self.apply(event, &mut armed_deadline).await;
                }
                LoopAction::Event(event) => {
                    self.apply(event, &mut armed_deadline).await;
                }
            }
        }
    }

    async fn next_action(
        &mut self,
        events: &mut mpsc::Receiver<SessionEvent>,
        armed_deadline: Option<(Instant, SessionEvent)>,
        next_probe: Option<Instant>,
    ) -> LoopAction {
        // A shutdown that predates this call (including one set before the
        // loop started) must not be lost to `changed()`'s edge semantics.
        if *self.shutdown.borrow() {
            return LoopAction::ServerShutdown;
        }
        let far_future = Instant::now() + Duration::from_secs(86_400);
        let deadline_at = armed_deadline.map_or(far_future, |(at, _)| at);
        let probe_at = next_probe.unwrap_or(far_future);
        tokio::select! {
            biased;
            changed = self.shutdown.changed() => {
                if changed.is_err() || *self.shutdown.borrow() {
                    LoopAction::ServerShutdown
                } else {
                    LoopAction::ChildFinished
                }
            }
            command = self.control.recv(), if !self.control_detached => match command {
                Some(command) => LoopAction::Event(command.session_event()),
                None => LoopAction::ControlDetached,
            },
            () = sleep_until(deadline_at), if armed_deadline.is_some() => {
                match armed_deadline {
                    Some((_, event)) => LoopAction::Deadline(event),
                    None => LoopAction::ChildFinished,
                }
            }
            () = sleep_until(probe_at), if next_probe.is_some() => LoopAction::BackendProbe,
            joined = self.children.join_next(), if !self.children.is_empty() => {
                let _ = joined;
                LoopAction::ChildFinished
            }
            event = events.recv() => match event {
                Some(event) => LoopAction::Event(event),
                None => LoopAction::SourceExhausted,
            },
        }
    }

    async fn apply(
        &mut self,
        event: SessionEvent,
        armed_deadline: &mut Option<(Instant, SessionEvent)>,
    ) {
        match self.fsm.on_event(event) {
            Ok(effects) => {
                for effect in effects {
                    if effect == SessionEffect::BeginDrainTimer {
                        *armed_deadline = Some((
                            Instant::now() + self.config.drain_deadline,
                            SessionEvent::DrainTimerExpired,
                        ));
                    }
                    self.handler.execute(effect, &mut self.children).await;
                    self.effects_executed += 1;
                }
                // The handshake deadline is judged on the post-transition
                // state: the very transition into an authenticated state
                // (`BackendAuthOk`) disarms it, with no dependency on any
                // later event arriving.
                if let Some((_, pending)) = *armed_deadline
                    && pending == SessionEvent::HandshakeTimerExpired
                    && authenticated_phase(self.fsm.state())
                {
                    *armed_deadline = None;
                }
            }
            Err(rejection) => {
                self.rejected_events += 1;
                self.last_rejection = Some(rejection);
            }
        }
    }

    /// Drives the FSM to `Closed` for an externally decided end: the close
    /// event executes its teardown effects, then `TeardownComplete` seals
    /// the machine. Rejections are tolerated (the FSM may already be
    /// closing or closed).
    async fn close_via_fsm(&mut self, close_event: SessionEvent) {
        let mut deadline = None;
        if self.fsm.state() != SessionState::Closed {
            self.apply(close_event, &mut deadline).await;
        }
        if self.fsm.state() != SessionState::Closed {
            self.apply(SessionEvent::TeardownComplete, &mut deadline)
                .await;
        }
    }

    /// Drains children against the terminal cleanup's **absolute**
    /// deadline: a normal-completion window first — teardown work spawned
    /// by `Close*` effects runs to completion here — then, only for
    /// children that outlived it, abort plus a join. A tenth of the
    /// budget is reserved for that abort join so a stuck child cannot
    /// starve it; both phases share the same absolute deadline, keeping
    /// the whole sequence at one `cleanup_deadline`. Anything beyond the
    /// bound is reported and force-aborted when the set drops.
    async fn cleanup_within(&mut self, deadline: Instant) -> CleanupReport {
        let abort_grace = self.config.cleanup_deadline / 10;
        let drain_by = deadline
            .checked_sub(abort_grace)
            .unwrap_or_else(Instant::now);
        let drained = timeout_at(drain_by, async {
            while self.children.join_next().await.is_some() {}
        })
        .await;
        let aborted_children = self.children.len();
        if drained.is_err() && aborted_children > 0 {
            self.children.abort_all();
            let joined = timeout_at(deadline, async {
                while self.children.join_next().await.is_some() {}
            })
            .await;
            self.cleanup_within_deadline &= joined.is_ok();
        }
        self.aborted_children_total += aborted_children;
        CleanupReport {
            aborted_children: self.aborted_children_total,
            within_deadline: self.cleanup_within_deadline,
        }
    }
}

const fn authenticated_phase(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Ready
            | SessionState::Command
            | SessionState::Response
            | SessionState::LocalInfile
            | SessionState::RedirectPending
            | SessionState::Draining
    )
}

/// KA-003: the backend probe may only run while no command, response, or
/// `LOCAL INFILE` exchange is in flight — it must never race command I/O
/// on the backend connection. `Ready` and `Draining` are the idle states
/// (`Draining` waits at a boundary; a drained command re-enters
/// `Command`). `RedirectPending` is excluded conservatively: the owner is
/// mid-swap.
const fn probe_safe(state: SessionState) -> bool {
    matches!(state, SessionState::Ready | SessionState::Draining)
}

enum LoopEnd {
    FsmClosed,
    Shutdown,
    SourceExhausted,
}
