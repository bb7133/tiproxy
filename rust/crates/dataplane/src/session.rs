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
//! the child-operation set. There is no session mutex anywhere: event
//! sources and effect handlers borrow `&mut` slices of the loop's state for
//! the duration of one call, and child operations live in the session's
//! [`JoinSet`], so nothing detaches and nothing is shared.
//!
//! The loop composes, in biased order: shutdown, control commands, the
//! armed deadline timer, finished child operations, and transport events
//! (already classified into [`SessionEvent`]s by the SES layers via
//! [`SessionEventSource`]). Every accepted event drives
//! [`SessionFsm::on_event`]; every returned effect goes to the injected
//! [`EffectHandler`], which may spawn **tracked** children but cannot own
//! session state.
//!
//! Cleanup is deadline-bounded on every exit path (client/backend/control
//! EOF, cancel, error, or normal close): children are aborted and drained
//! under [`SessionLoopConfig::cleanup_deadline`], and the transport is
//! dropped (closing its file descriptors) before [`SessionSummary`] is
//! returned. Go parity notes: the handshake deadline mirrors the frontend
//! auth timeout, the periodic backend-active check mirrors
//! `checkBackendActive`, and half-close follows Go — a client EOF tears the
//! session down rather than lingering on a half-open pair.

use std::time::Duration;

use session_core::fsm::{SessionEffect, SessionEvent, SessionFsm, SessionState, TransitionError};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout};

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
pub trait SessionEventSource: Send {
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

    /// Periodic backend-liveness probe (Go `checkBackendActive`). Returning
    /// false injects [`SessionEvent::BackendIoError`].
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
    /// Upper bound for aborting and draining children plus dropping the
    /// transport on any exit path.
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
    /// The control channel closed and the FSM cannot make progress; the
    /// session is torn down defensively.
    ControlChannelLost,
}

/// Deadline-bounded cleanup accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// Children aborted at exit (they were still running).
    pub aborted_children: usize,
    /// Whether every child joined within the cleanup deadline.
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
    /// Cleanup accounting.
    pub cleanup: CleanupReport,
}

/// The single owner of one session's mutable state.
pub struct SessionLoop<S, E> {
    fsm: SessionFsm,
    source: S,
    handler: E,
    control: mpsc::Receiver<SessionControl>,
    shutdown: watch::Receiver<bool>,
    config: SessionLoopConfig,
    children: JoinSet<()>,
    effects_executed: u64,
    rejected_events: u64,
    last_rejection: Option<TransitionError>,
    aborted_children_total: usize,
    cleanup_within_deadline: bool,
}

enum LoopAction {
    Event(SessionEvent),
    /// The armed one-shot deadline fired.
    Deadline(SessionEvent),
    SourceExhausted,
    ServerShutdown,
    ControlLost,
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
            source,
            handler,
            control,
            shutdown,
            config,
            children: JoinSet::new(),
            effects_executed: 0,
            rejected_events: 0,
            last_rejection: None,
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
    /// aborted and the transport is dropped before this returns.
    pub async fn run(mut self) -> SessionSummary {
        let end = self.event_loop().await;
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
            LoopEnd::ControlLost => {
                self.close_via_fsm(SessionEvent::ControlCloseImmediate)
                    .await;
                SessionEnd::ControlChannelLost
            }
        };
        let cleanup = self.cleanup().await;
        SessionSummary {
            end,
            final_state: self.fsm.state(),
            effects_executed: self.effects_executed,
            rejected_events: self.rejected_events,
            cleanup,
        }
    }

    async fn event_loop(&mut self) -> LoopEnd {
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
                // The loop is the runtime: teardown effects have executed,
                // so drain children under the deadline and seal the FSM.
                let _ = self.cleanup().await;
                self.apply(SessionEvent::TeardownComplete, &mut armed_deadline)
                    .await;
                continue;
            }
            let action = self.next_action(armed_deadline, next_probe).await;
            match action {
                LoopAction::ServerShutdown => return LoopEnd::Shutdown,
                LoopAction::SourceExhausted => return LoopEnd::SourceExhausted,
                LoopAction::ControlLost => return LoopEnd::ControlLost,
                LoopAction::ChildFinished => {}
                LoopAction::BackendProbe => {
                    if let Some(probe) = next_probe.as_mut() {
                        *probe = Instant::now() + self.config.backend_check_interval;
                    }
                    if authenticated_phase(self.fsm.state()) && !self.handler.backend_active().await
                    {
                        self.apply(SessionEvent::BackendIoError, &mut armed_deadline)
                            .await;
                    }
                }
                LoopAction::Deadline(event) => {
                    armed_deadline = None;
                    self.apply(event, &mut armed_deadline).await;
                }
                LoopAction::Event(event) => {
                    if let Some((_, pending)) = armed_deadline
                        && pending == SessionEvent::HandshakeTimerExpired
                        && authenticated_phase(self.fsm.state())
                    {
                        // Authentication finished: the handshake deadline
                        // disarms and only a drain deadline can re-arm.
                        armed_deadline = None;
                    }
                    self.apply(event, &mut armed_deadline).await;
                }
            }
        }
    }

    async fn next_action(
        &mut self,
        armed_deadline: Option<(Instant, SessionEvent)>,
        next_probe: Option<Instant>,
    ) -> LoopAction {
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
            command = self.control.recv() => match command {
                Some(command) => LoopAction::Event(command.session_event()),
                None => LoopAction::ControlLost,
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
            event = self.source.next_event() => match event {
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

    async fn cleanup(&mut self) -> CleanupReport {
        let aborted_children = self.children.len();
        self.children.abort_all();
        let drained = timeout(self.config.cleanup_deadline, async {
            while self.children.join_next().await.is_some() {}
        })
        .await;
        self.aborted_children_total += aborted_children;
        self.cleanup_within_deadline &= drained.is_ok();
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

enum LoopEnd {
    FsmClosed,
    Shutdown,
    SourceExhausted,
    ControlLost,
}
