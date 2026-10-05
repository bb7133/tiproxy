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

use std::pin::Pin;
use std::time::Duration;

use session_core::fsm::{SessionEffect, SessionEvent, SessionState, TransitionError};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, Sleep, sleep_until, timeout_at};

/// Control-plane commands delivered to one session's loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionControl {
    /// Migrate this session to a new backend at the next safe boundary.
    Redirect,
    /// Close gracefully at the next safe boundary.
    GracefulClose,
    /// Close gracefully using a caller-supplied deadline. The process-local
    /// shutdown coordinator uses this variant so already-admitted sessions
    /// observe the latest accepted dynamic drain timeout.
    GracefulCloseAfter(Duration),
    /// Close immediately.
    CloseImmediate,
}

impl SessionControl {
    const fn session_event(self) -> SessionEvent {
        match self {
            Self::Redirect => SessionEvent::ControlRedirect,
            Self::GracefulClose | Self::GracefulCloseAfter(_) => SessionEvent::ControlGracefulClose,
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

    /// A source that is already a bounded channel of classified events may
    /// hand that channel to the loop so it is read directly, without the
    /// classifier pump task in between. Generic sources (which poll a
    /// transport and need the pump's cancel protection) keep the default.
    ///
    /// Contract for an implementation that returns `Ok`:
    /// - the channel carries only already-classified `SessionEvent`s;
    /// - `recv` on it is cancel-safe (the loop selects over it);
    /// - handing over the receiver does not transfer any other resource:
    ///   whatever the source owns besides the channel must still be released
    ///   by the source's owner (for the engine's `EventRx` there is nothing
    ///   else). When the loop finally drops the receiver, the producer's
    ///   `send` fails; the producer's sender is not dropped by the loop.
    ///
    /// Nothing about FSM admission changes: a `ClientCommand` still waits for
    /// its admission ACK, the FSM enters the in-command state before that ACK
    /// is produced, response/prepare events arise only while in flight, and
    /// the next command stays bound by the existing ACK/event order.
    ///
    /// # Errors
    /// Returns `Err(self)` when the source is not a plain classified channel
    /// and must keep being polled through the pump; the source is handed back
    /// unchanged.
    fn into_event_channel(self) -> Result<mpsc::Receiver<SessionEvent>, Self>
    where
        Self: Sized,
    {
        Err(self)
    }

    /// A source backed by the engine's gated channel hands that channel to the
    /// loop so each event arrives with its admission [`GatePermit`]. This is the
    /// only path on which the fast path may engage; every other source keeps the
    /// default `Err(self)` and is read ungated (pump/`into_event_channel`), which
    /// forces the fast path off.
    ///
    /// # Errors
    /// Returns `Err(self)` when the source is not the engine's gated channel;
    /// the source is handed back unchanged.
    fn into_gated_event_channel(self) -> Result<crate::gate::GatedReceiver<SessionEvent>, Self>
    where
        Self: Sized,
    {
        Err(self)
    }
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
    /// The shared session core (FSM + admission gate). The loop is the FSM's
    /// only writer on the slow path, via [`crate::gate::Gate::apply_slow`]; a
    /// later slice lets the engine commit whitelisted steady transitions under
    /// the same lock.
    core: crate::gate::Gate,
    source: Option<S>,
    handler: E,
    control: crate::gate::GatedReceiver<SessionControl>,
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
    /// A transport event, with its admission permit when it came from the
    /// engine's gated channel (`None` for an ungated pump/generic source, which
    /// keeps the fast path off).
    Event(SessionEvent, Option<crate::gate::GatePermit>),
    Control(SessionControl, crate::gate::GatePermit),
    /// The armed one-shot deadline fired.
    Deadline(SessionEvent),
    SourceExhausted,
    ServerShutdown,
    ControlDetached,
    ChildFinished,
    BackendProbe,
}

/// The loop's event receiver: the engine's gated channel (permits travel with
/// events, enabling the fast path) or an ungated plain channel (direct generic
/// source or the classifier pump; always fast-path-off).
enum LoopEventRx {
    Gated(crate::gate::GatedReceiver<SessionEvent>),
    Plain(mpsc::Receiver<SessionEvent>),
}

impl LoopEventRx {
    /// Cancel-safe receive of the next `(event, permit?)`. The only await is the
    /// inner channel recv, so losing a `select!` race drops nothing.
    async fn recv(&mut self) -> Option<(SessionEvent, Option<crate::gate::GatePermit>)> {
        match self {
            Self::Gated(rx) => rx.recv().await.map(|(event, permit)| (event, Some(permit))),
            Self::Plain(rx) => rx.recv().await.map(|event| (event, None)),
        }
    }
}

/// Parks on the shared shutdown `watch` once and fires `fired` when the
/// signal becomes `true` or its sender is dropped. Ignores changes back to
/// `false`, which the loop treated as a no-op wake.
async fn shutdown_relay(
    mut shutdown: watch::Receiver<bool>,
    core: crate::gate::Gate,
    started: oneshot::Sender<()>,
    fired: oneshot::Sender<()>,
) {
    // First observation, made before the loop is allowed to touch input: a
    // shutdown that already holds (value `true`) or a sender already dropped is
    // sealed here, and `started` acks that the relay has observed the initial
    // state. The loop awaits `started` before its first select, so a
    // pre-existing shutdown is sealed strictly before any event can be
    // dispatched — restoring the synchronous precheck guarantee without the
    // loop reading the watch directly.
    let down_at_start = shutdown
        .has_changed()
        .map_or(true, |_| *shutdown.borrow_and_update());
    if down_at_start {
        core.seal_closed();
    }
    let _ = started.send(());
    if down_at_start {
        let _ = fired.send(());
        return;
    }
    // Otherwise park until the signal flips to `true` or the sender drops.
    loop {
        if shutdown.changed().await.is_err() {
            break;
        }
        if *shutdown.borrow_and_update() {
            break;
        }
    }
    // Seal the core *before* waking the loop, so `open == false` is published
    // under the core lock strictly before the loop can act on the oneshot. This
    // makes the relay the single shutdown-admission linearization point: the
    // engine's fast path (reads `open`) and the loop's gated apply (reads
    // `open`) both refuse once this seal lands, regardless of oneshot latency.
    core.seal_closed();
    let _ = fired.send(());
}

/// Aborts the relay on every exit path of the event loop.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<S: SessionEventSource, E: EffectHandler> SessionLoop<S, E> {
    /// Creates a session loop over the shared `core` (which carries the FSM,
    /// starting at `Accept`). The loop is the FSM's only writer on the slow
    /// path.
    #[must_use]
    pub fn new(
        core: crate::gate::Gate,
        source: S,
        handler: E,
        control: crate::gate::GatedReceiver<SessionControl>,
        shutdown: watch::Receiver<bool>,
        config: SessionLoopConfig,
    ) -> Self {
        Self {
            core,
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
        // `new` always fills the slot; `run` consumes `self`.
        let Some(source) = self.source.take() else {
            unreachable!("session source taken twice")
        };
        // A pre-classified channel source (the engine's `EventRx`) is read
        // directly: the pump would only forward events from one one-slot
        // channel into another, so this removes that task/channel forward on
        // the engine path. Every other source keeps the pump and its cancel
        // protection.
        // Preference order: the engine's gated channel (fast-path eligible),
        // then a plain pre-classified channel, then the classifier pump. Only
        // the gated path carries admission permits; the other two are ungated
        // and keep the fast path off.
        let (mut events, pump): (LoopEventRx, Option<JoinHandle<()>>) =
            match source.into_gated_event_channel() {
                Ok(gated) => (LoopEventRx::Gated(gated), None),
                Err(source) => match source.into_event_channel() {
                    Ok(plain) => (LoopEventRx::Plain(plain), None),
                    Err(mut source) => {
                        let (event_tx, plain) = mpsc::channel::<SessionEvent>(EVENT_PUMP_CAPACITY);
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
                        (LoopEventRx::Plain(plain), Some(pump))
                    }
                },
            };

        let end = self.event_loop(&mut events).await;
        // One absolute budget for the whole terminal sequence.
        let cleanup_by = Instant::now() + self.config.cleanup_deadline;
        // Stop the pump first: the source — and the transport it owns —
        // must release before any teardown child is waited on, so
        // teardown work that needs the transport's file descriptors or
        // locks cannot deadlock against the pump.
        // Dropping the receiver closes the producer's sender either way: for
        // the direct channel the engine's sends now fail exactly as they did
        // once the pump (which owned the receiver) was aborted.
        drop(events);
        if let Some(pump) = pump {
            pump.abort();
            self.cleanup_within_deadline &= timeout_at(cleanup_by, pump).await.is_ok();
        }
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
            final_state: self.core.state_snapshot(),
            effects_executed: self.effects_executed,
            rejected_events: self.rejected_events,
            control_detached: self.control_detached,
            cleanup,
        }
    }

    /// Terminal fence: seals the core closed — so a later slice's engine fast
    /// path refuses to commit once the loop is terminating — then returns the
    /// loop's end reason. Called at every path that leaves the steady loop,
    /// before the FSM is still `Ready` but the session is tearing down.
    fn seal_and_end(&self, end: LoopEnd) -> LoopEnd {
        self.core.seal_closed();
        end
    }

    // One cohesive select/dispatch loop; splitting the arms out would scatter
    // the shared deadline/probe/queued-command state and obscure the ordering.
    #[allow(clippy::too_many_lines)]
    async fn event_loop(&mut self, events: &mut LoopEventRx) -> LoopEnd {
        let handshake_deadline = Instant::now() + self.config.handshake_deadline;
        let mut armed_deadline: Option<(Instant, SessionEvent)> =
            Some((handshake_deadline, SessionEvent::HandshakeTimerExpired));
        let mut next_probe = (!self.config.backend_check_interval.is_zero())
            .then(|| Instant::now() + self.config.backend_check_interval);

        // opt#6: two persistent timers held across loop iterations. Resetting a
        // timer is a wheel operation, but the deadlines only change on rare
        // events (handshake/drain arming, and the probe re-arming every
        // `backend_check_interval`), not per packet. A disabled timer parks at
        // `far_future` and never fires; its branch guard keeps it inert.
        let far_future = Instant::now() + Duration::from_secs(86_400);
        let mut deadline_sleep =
            Box::pin(sleep_until(armed_deadline.map_or(far_future, |(at, _)| at)));
        let mut probe_sleep = Box::pin(sleep_until(next_probe.unwrap_or(far_future)));

        // opt#12: the server shutdown signal is one `watch` shared by every
        // session. Awaiting `changed()` inside the select registered this
        // task on the channel's waiter list and unlinked it again on every
        // iteration, serializing all sessions on that list's mutex. Instead a
        // per-session relay task parks on the shared channel once, seals the
        // core, and fires a private oneshot; the loop polls the oneshot (no
        // shared state).
        //
        // S2b: the relay is the loop's SOLE shutdown-observation path — the
        // loop no longer runs its own `has_changed` precheck. The relay seals
        // the core (under its lock) before firing, so `open == false` is the
        // single admission authority and the engine's fast path cannot commit a
        // command that this loop would have dropped at shutdown.
        //
        // The relay acks via `started` once it has made its first observation
        // (and sealed, if a shutdown already held); the loop awaits that ack
        // before touching any input, so a pre-existing shutdown is sealed
        // strictly before the first select — the loop's `open` fence below then
        // refuses the first event. This restores the synchronous-precheck
        // guarantee the direct `has_changed` read used to provide.
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (relay_tx, mut shutdown_fired) = oneshot::channel::<()>();
        let _relay = AbortOnDrop(tokio::spawn(shutdown_relay(
            self.shutdown.clone(),
            self.core.clone(),
            started_tx,
            relay_tx,
        )));
        // The relay cannot outlive this await without having observed the
        // initial state; a dropped ack (relay aborted) is treated as observed.
        let _ = started_rx.await;

        // The wire engine has at most one unacknowledged command. Its payload
        // stays in the engine; retain only the classified event while a
        // redirect owns the command boundary (Go's processLock).
        let mut queued_command = None;
        loop {
            if self.core.state_snapshot() == SessionState::Closed {
                return self.seal_and_end(LoopEnd::FsmClosed);
            }
            if self.core.state_snapshot() == SessionState::Closing {
                // The loop is the runtime: teardown effects have executed
                // and their children are tracked, so seal the FSM now;
                // the children drain in the terminal cleanup, under the
                // single absolute budget, after the pump releases the
                // transport.
                self.apply(
                    SessionEvent::TeardownComplete,
                    &mut armed_deadline,
                    None,
                    false,
                )
                .await;
                continue;
            }
            // Sync the persistent timers to the current deadlines; reset only
            // when a deadline actually changed (rare), so the steady-state data
            // path touches the timer wheel zero times per packet.
            let deadline_at = armed_deadline.map_or(far_future, |(at, _)| at);
            if deadline_sleep.deadline() != deadline_at {
                deadline_sleep.as_mut().reset(deadline_at);
            }
            let probe_at = next_probe.unwrap_or(far_future);
            if probe_sleep.deadline() != probe_at {
                probe_sleep.as_mut().reset(probe_at);
            }
            let action = self
                .next_action(
                    events,
                    &mut shutdown_fired,
                    &mut deadline_sleep,
                    &mut probe_sleep,
                    armed_deadline,
                    next_probe,
                )
                .await;
            // Shutdown fence: the relay may have sealed the core during the
            // select above (its `seal_closed` is published before the oneshot
            // it also fires). Once sealed, refuse to dispatch *any* action —
            // this closes the seal->fire window where a `gated = false` branch
            // (Deadline / BackendProbe / Control) could otherwise transition
            // before the `ServerShutdown` oneshot is observed. The dequeued
            // action is dropped here (its permit, if any, is returned);
            // terminal close in `run` is reached through this `Shutdown` end and
            // runs ungated. Only the relay seals `open` mid-loop (`seal_and_end`
            // seals and returns in the same step), so `!open` here means
            // shutdown.
            if !self.core.is_open() {
                return LoopEnd::Shutdown;
            }
            match action {
                LoopAction::ServerShutdown => return self.seal_and_end(LoopEnd::Shutdown),
                LoopAction::SourceExhausted => return self.seal_and_end(LoopEnd::SourceExhausted),
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
                    // Admit the probe atomically with the core: only probe when
                    // it is quiescent (open, probe-safe state, `pending == 0`),
                    // and hold the returned operation permit across the await.
                    // While it is held `pending >= 1`, so the engine fast path
                    // falls back and cannot turn `Ready -> Command` mid-probe —
                    // a stale `inactive` result can no longer tear down a command
                    // the fast path committed during the probe. If the core is
                    // not quiescent the probe is skipped this round. The permit
                    // binding stays in scope across the `&&` await and the body,
                    // so it is held for the whole probe and dropped afterwards.
                    if let Some(_probe_permit) = self.core.try_quiescent_operation(probe_safe)
                        && !self.handler.backend_active().await
                    {
                        self.apply(
                            SessionEvent::BackendIoError,
                            &mut armed_deadline,
                            None,
                            false,
                        )
                        .await;
                    }
                }
                LoopAction::Deadline(event) => {
                    armed_deadline = None;
                    self.apply(event, &mut armed_deadline, None, false).await;
                }
                LoopAction::Event(event, permit) => {
                    if self.core.state_snapshot() == SessionState::RedirectPending
                        && matches!(
                            event,
                            SessionEvent::ClientCommand | SessionEvent::ClientCommandQuit
                        )
                        && queued_command.is_none()
                    {
                        // A response can reach the client before the engine
                        // consumes the following StartRedirectHandshake effect.
                        // Rejecting this next command would lose its ACK forever.
                        // The permit rides with the queued command, so the gate
                        // stays non-empty until it is finally applied.
                        queued_command = Some((event, permit));
                    } else {
                        // Ordinary engine event: gated, so a post-seal command
                        // is dropped under the lock (shutdown-admission refusal),
                        // matching the fast path refusing to commit once sealed.
                        self.apply(event, &mut armed_deadline, None, true).await;
                        drop(permit);
                    }
                }
                LoopAction::Control(command, _permit) => {
                    let drain_deadline = match command {
                        SessionControl::GracefulCloseAfter(deadline) => Some(deadline),
                        _ => None,
                    };
                    self.apply(
                        command.session_event(),
                        &mut armed_deadline,
                        drain_deadline,
                        false,
                    )
                    .await;
                    // Permit drops here, after the control's effects are applied
                    // (any effect it spawned already holds its own cmd permit).
                }
            }
            if self.core.state_snapshot() == SessionState::Ready
                && let Some((event, permit)) = queued_command.take()
            {
                // apply() enqueues all terminal redirect effects first, so the
                // backend swap (or failure retaining the old backend) precedes
                // this command's forwarding ACK. Closing instead drops the slot.
                self.apply(event, &mut armed_deadline, None, true).await;
                drop(permit);
            }
        }
    }

    async fn next_action(
        &mut self,
        events: &mut LoopEventRx,
        shutdown_fired: &mut oneshot::Receiver<()>,
        deadline_sleep: &mut Pin<Box<Sleep>>,
        probe_sleep: &mut Pin<Box<Sleep>>,
        armed_deadline: Option<(Instant, SessionEvent)>,
        next_probe: Option<Instant>,
    ) -> LoopAction {
        // S2b: no direct `has_changed` precheck here — the relay is the sole
        // shutdown-observation path (it seals the core and fires `shutdown_fired`
        // below). A shutdown that predates this call reaches us through the
        // oneshot (the relay's first `borrow_and_update` sees it), and a
        // command that races the seal is refused by the gated `apply` under the
        // core lock.
        // opt#6: poll the caller's persistent timers instead of building a
        // fresh `sleep_until` here. A new timer per call armed and (on the
        // untaken branch) dropped a tokio timer-wheel entry on every packet,
        // serializing all sessions on the wheel's global mutex. The caller
        // resets these only when the deadline actually changes.
        tokio::select! {
            biased;
            // The relay fires once the shared signal is `true` or its sender
            // is gone; a relay that vanished (runtime teardown) reads the same.
            _ = &mut *shutdown_fired => LoopAction::ServerShutdown,
            command = self.control.recv(), if !self.control_detached => match command {
                Some((command, permit)) => LoopAction::Control(command, permit),
                None => LoopAction::ControlDetached,
            },
            () = deadline_sleep.as_mut(), if armed_deadline.is_some() => {
                match armed_deadline {
                    Some((_, event)) => LoopAction::Deadline(event),
                    None => LoopAction::ChildFinished,
                }
            }
            () = probe_sleep.as_mut(), if next_probe.is_some() => LoopAction::BackendProbe,
            joined = self.children.join_next(), if !self.children.is_empty() => {
                let _ = joined;
                LoopAction::ChildFinished
            }
            event = events.recv() => match event {
                Some((event, permit)) => LoopAction::Event(event, permit),
                None => LoopAction::SourceExhausted,
            },
        }
    }

    async fn apply(
        &mut self,
        event: SessionEvent,
        armed_deadline: &mut Option<(Instant, SessionEvent)>,
        drain_deadline: Option<Duration>,
        gated: bool,
    ) {
        // The transition runs under the core lock and returns owned effects plus
        // the post-transition state; the effects then execute *outside* the lock
        // (the std mutex guards only pure computation). A gated ordinary event
        // that arrives after the core is sealed closed is dropped here — the
        // shutdown-admission refusal that mirrors the fast path refusing to
        // commit once sealed.
        let (result, post_state) = match self.core.apply_slow(event, gated) {
            crate::gate::SlowOutcome::Applied { result, post_state } => (result, post_state),
            crate::gate::SlowOutcome::DroppedClosed => return,
        };
        match result {
            Ok(effects) => {
                for effect in effects {
                    if effect == SessionEffect::BeginDrainTimer {
                        *armed_deadline = Some((
                            Instant::now() + drain_deadline.unwrap_or(self.config.drain_deadline),
                            SessionEvent::DrainTimerExpired,
                        ));
                    }
                    self.handler.execute(effect, &mut self.children).await;
                    self.effects_executed += 1;
                }
                // The handshake deadline is judged on the post-transition
                // state: the very transition into an authenticated state
                // (`BackendAuthOk`) disarms it, with no dependency on any
                // later event arriving. The post-state captured with the
                // transition is authoritative here (the loop is the only
                // writer of these non-steady transitions).
                if let Some((_, pending)) = *armed_deadline
                    && pending == SessionEvent::HandshakeTimerExpired
                    && authenticated_phase(post_state)
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
        // Reached only from the terminal path in `run`, after the core is
        // sealed closed; the loop is the sole writer here.
        let mut deadline = None;
        // Terminal events are ungated: the core is already sealed closed, so
        // gating would drop them and the FSM could never reach `Closed`.
        if self.core.state_snapshot() != SessionState::Closed {
            self.apply(close_event, &mut deadline, None, false).await;
        }
        if self.core.state_snapshot() != SessionState::Closed {
            self.apply(SessionEvent::TeardownComplete, &mut deadline, None, false)
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

#[cfg(test)]
mod relay_tests {
    use super::shutdown_relay;
    use crate::gate::Gate;
    use tokio::sync::{oneshot, watch};

    /// A shutdown that already holds at startup is sealed and acked before the
    /// loop is released: `started` fires, the core is sealed, and the loop
    /// oneshot fires — all before the relay returns. The seal is published
    /// strictly before the wake, the single shutdown-admission linearization
    /// point.
    #[tokio::test]
    async fn relay_seals_and_acks_a_preexisting_true_signal() {
        let (_tx, rx) = watch::channel(true);
        let core = Gate::new();
        assert!(core.is_open());
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (fired_tx, fired_rx) = oneshot::channel::<()>();
        shutdown_relay(rx, core.clone(), started_tx, fired_tx).await;
        assert!(
            started_rx.await.is_ok(),
            "relay acked its first observation"
        );
        assert!(
            !core.is_open(),
            "a pre-existing shutdown is sealed at startup"
        );
        assert!(fired_rx.await.is_ok(), "relay fired the loop oneshot");
    }

    /// A sender already dropped at startup is a shutdown too, sealed and acked
    /// before the loop runs (so a torn-down runtime never leaves the core
    /// admitting).
    #[tokio::test]
    async fn relay_seals_and_acks_a_preclosed_sender() {
        let (tx, rx) = watch::channel(false);
        drop(tx);
        let core = Gate::new();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (fired_tx, fired_rx) = oneshot::channel::<()>();
        shutdown_relay(rx, core.clone(), started_tx, fired_tx).await;
        assert!(started_rx.await.is_ok());
        assert!(
            !core.is_open(),
            "a pre-closed sender is observed as shutdown"
        );
        assert!(fired_rx.await.is_ok());
    }

    /// When no shutdown holds at startup, the relay acks but leaves the core
    /// open, then seals and fires only once the signal later flips to `true`.
    #[tokio::test]
    async fn relay_acks_open_then_seals_on_a_later_signal() {
        let (tx, rx) = watch::channel(false);
        let core = Gate::new();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let (fired_tx, fired_rx) = oneshot::channel::<()>();
        let relay = tokio::spawn(shutdown_relay(rx, core.clone(), started_tx, fired_tx));
        // The startup ack lands while the core is still open.
        assert!(
            started_rx.await.is_ok(),
            "relay acked its first observation"
        );
        assert!(
            core.is_open(),
            "no shutdown held at startup, so the core stays open"
        );
        // A later shutdown seals and fires.
        assert!(tx.send(true).is_ok(), "receiver still alive");
        assert!(fired_rx.await.is_ok(), "relay fired once shutdown arrived");
        assert!(!core.is_open(), "the later shutdown sealed the core");
        assert!(relay.await.is_ok(), "relay task joins");
    }
}
