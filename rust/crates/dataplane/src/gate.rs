//! Shared session core + fast-path admission gate (v5, slices S1–S2a — no fast
//! path yet).
//!
//! Every message that can change how the *next* client command is handled —
//! engine→loop [`SessionEvent`]s, loop/owner→engine [`EngineCmd`]s, and
//! owner→loop [`SessionControl`]s — is registered in a shared counter before it
//! is enqueued and deregistered only after it (and every effect it spawns) has
//! been fully processed (S1). S2a folds the session FSM into that same locked
//! core, so a later slice can read `pending == 0 && open` together with a
//! speculative transition to decide whether the engine may inline a steady
//! transition. Through S2a the loop is still the FSM's only writer (via
//! [`Gate::apply_slow`]) and there is no behavior change.
//!
//! Registration is a RAII [`GatePermit`] carried alongside the message in the
//! channel (`mpsc::Sender<(T, GatePermit)>`). The permit's `Drop` decrements
//! the counter, so a cancelled send, a closed receiver, or a dropped queued
//! message all return the count automatically. The one hard rule: a
//! `GatePermit` must never be dropped while its [`Gate`] mutex is held (its
//! `Drop` takes that mutex), and the mutex is only ever held for the trivial
//! counter arithmetic — never across an `.await`, channel send, or effect.

use std::sync::{Arc, Mutex};

use session_core::fsm::{
    Effects, SessionEffect, SessionEvent, SessionFsm, SessionState, TransitionError,
};
use tokio::sync::{mpsc, watch};

/// Shared session core: the session FSM together with the admission counters,
/// behind one std `Mutex` so a later slice can evaluate the fast-path predicate
/// (`open && pending == 0` with a speculative transition) atomically. The mutex
/// guards only pure computation — FSM transitions and counter arithmetic —
/// never an `.await`, channel send, or effect execution.
#[derive(Debug)]
struct FsmCore {
    /// The session state machine. In S2a the loop is still its only writer (via
    /// [`Gate::apply_slow`]); a later slice lets the engine commit whitelisted
    /// steady transitions under this same lock.
    fsm: SessionFsm,
    /// Registered-but-not-yet-processed messages across all producers/channels.
    pending: u32,
    /// Loop is running and has not entered terminal handling. Sealed to `false`
    /// under the lock before the loop takes any terminal path or when the
    /// shutdown relay observes shutdown; once false it never reopens. It is the
    /// single admission authority: both [`Gate::apply_slow`] (gated loop events)
    /// and [`Gate::try_commit_steady`] (engine fast path) read it under this
    /// lock, so they linearize on the same seal.
    open: bool,
    /// Count of transitions the engine committed inline on the fast path
    /// (diagnostic; read by tests and metrics).
    fast_transitions: u64,
}

/// Handle to the shared session core (FSM + admission gate) for one session.
#[derive(Clone, Debug)]
pub struct Gate {
    inner: Arc<Mutex<FsmCore>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    /// Creates a core with a fresh FSM (starting at `Accept`), zero in-flight
    /// messages, and `open == true`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FsmCore {
                fsm: SessionFsm::new(),
                pending: 0,
                open: true,
                fast_transitions: 0,
            })),
        }
    }

    /// Reads the current FSM state (a `Copy` value) under the lock and releases
    /// immediately. Never exposes the guard.
    pub(crate) fn state_snapshot(&self) -> SessionState {
        lock(&self.inner).fsm.state()
    }

    /// Applies one event to the FSM on the slow path, under the lock.
    ///
    /// When `gated` is `true` the event is an ordinary data-path event and is
    /// refused ([`SlowOutcome::DroppedClosed`]) if the core is already sealed
    /// closed — this is the admission check that, atomically with the
    /// transition, makes a post-seal `ClientCommand` behave the same whether it
    /// arrives on the slow path or is refused by the fast path. Terminal
    /// teardown events pass `gated = false` so sealing never blocks the FSM
    /// from reaching `Closed`. On [`SlowOutcome::Applied`] the caller executes
    /// the returned owned effects *outside* the lock; no guard escapes.
    pub(crate) fn apply_slow(&self, event: SessionEvent, gated: bool) -> SlowOutcome {
        let mut inner = lock(&self.inner);
        if gated && !inner.open {
            return SlowOutcome::DroppedClosed;
        }
        let result = inner.fsm.on_event(event);
        let post_state = inner.fsm.state();
        SlowOutcome::Applied { result, post_state }
    }

    /// Seals the loop closed under the lock before it takes a terminal path, or
    /// when the shutdown relay observes shutdown. Idempotent; once closed it
    /// never reopens. The admission paths ([`Gate::apply_slow`] gated,
    /// [`Gate::try_commit_steady`]) read `open` under this same lock.
    pub(crate) fn seal_closed(&self) {
        lock(&self.inner).open = false;
    }

    /// Whether the core is still open (loop running, not terminating). The
    /// loop reads this as its per-iteration shutdown fence; the admission paths
    /// ([`Gate::apply_slow`], [`Gate::try_commit_steady`]) also read `open`
    /// inline under the lock.
    pub(crate) fn is_open(&self) -> bool {
        lock(&self.inner).open
    }

    /// Engine fast path: attempt to commit one steady-state transition inline,
    /// skipping the `events`→loop→`cmd` round-trip. Under the single core lock
    /// this checks the whole admission predicate atomically:
    ///
    /// * the core is `open` (not sealed by the relay or a terminal path),
    /// * shutdown is not observed (sender-closed counts as shutdown),
    /// * `pending == 0` (no redirect/drain/control in flight),
    /// * `event` is on the whitelist (only [`SessionEvent::ClientCommand`]),
    /// * and a speculative transition on a *clone* yields exactly the single
    ///   expected steady effect.
    ///
    /// Only then is the clone committed back, an in-flight [`GatePermit`]
    /// registered (so `pending` holds the floor while the caller performs the
    /// forward, exactly as the slow path's effect permit does), and
    /// `fast_transitions` bumped. Otherwise it is [`FastPath::Fallback`] with
    /// zero writes to the core. The returned permit is constructed under the
    /// lock but only dropped by the caller *outside* it.
    pub(crate) fn try_commit_steady(
        &self,
        event: SessionEvent,
        expected_effect: SessionEffect,
        shutdown: &watch::Receiver<bool>,
    ) -> FastPath {
        let mut inner = lock(&self.inner);
        let closed = shutdown.has_changed().map_or(true, |_| *shutdown.borrow());
        if !inner.open
            || closed
            || inner.pending != 0
            || event != SessionEvent::ClientCommand
            || inner.fsm.state() != SessionState::Ready
        {
            return FastPath::Fallback;
        }
        let mut speculative = inner.fsm.clone();
        match speculative.on_event(event) {
            Ok(effects) if effects.len() == 1 && effects[0] == expected_effect => {
                inner.fsm = speculative;
                inner.pending += 1;
                inner.fast_transitions += 1;
                // Registered above; its `Drop` will decrement `pending`. Built
                // under the lock but handed back to the caller, who drops it
                // only after the forward completes and never under this mutex.
                FastPath::Committed(GatePermit {
                    inner: Arc::clone(&self.inner),
                })
            }
            _ => FastPath::Fallback,
        }
    }

    /// Admits a quiescent loop-side operation (currently the backend probe)
    /// atomically with the core: only when the core is `open`, `pending == 0`,
    /// and `state_ok` holds for the current FSM state does it register an
    /// operation [`GatePermit`] and return it. Holding that permit across the
    /// operation's `.await` keeps `pending >= 1`, so the engine fast path falls
    /// back for the duration — the operation cannot race a concurrent inline
    /// commit (e.g. a probe's stale `inactive` result tearing down a command
    /// the fast path committed mid-probe). Returns `None` (skip) otherwise.
    pub(crate) fn try_quiescent_operation<F>(&self, state_ok: F) -> Option<GatePermit>
    where
        F: FnOnce(SessionState) -> bool,
    {
        let mut inner = lock(&self.inner);
        if !inner.open || inner.pending != 0 || !state_ok(inner.fsm.state()) {
            return None;
        }
        inner.pending += 1;
        Some(GatePermit {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Count of inline fast-path commits. Test/diagnostic only.
    #[cfg(test)]
    pub(crate) fn fast_transitions(&self) -> u64 {
        lock(&self.inner).fast_transitions
    }

    /// Registers a standalone "operation" permit not tied to a single message.
    /// Used to bridge a multi-message atomic operation (e.g. the redirect pair
    /// `PrepareRedirect` + `Redirect`): held across both sends so `pending`
    /// cannot transiently reach zero between the first message being consumed
    /// and the second being registered. Dropped on every exit path.
    #[must_use = "hold the operation permit across the whole atomic operation"]
    pub fn operation_permit(&self) -> GatePermit {
        self.register()
    }

    /// Registers one in-flight message, returning its permit. The critical
    /// section only bumps the counter; the caller sends (and later the consumer
    /// drops the permit) outside the lock.
    fn register(&self) -> GatePermit {
        {
            let mut inner = lock(&self.inner);
            inner.pending += 1;
        }
        GatePermit {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Current registered count. Test/diagnostic only.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> u32 {
        lock(&self.inner).pending
    }
}

/// Outcome of a gated slow-path transition ([`Gate::apply_slow`]).
pub(crate) enum SlowOutcome {
    /// The transition ran; `result` carries its effects or rejection and
    /// `post_state` the FSM state afterwards.
    Applied {
        result: Result<Effects, TransitionError>,
        post_state: SessionState,
    },
    /// The core was sealed closed and the event was gated, so it was dropped
    /// with no transition — the shutdown-admission refusal.
    DroppedClosed,
}

/// Result of an engine fast-path attempt ([`Gate::try_commit_steady`]).
#[must_use = "a Committed fast path carries the in-flight permit that must be held across the forward"]
pub(crate) enum FastPath {
    /// The steady transition was committed inline; the caller skips the
    /// `events`+`await_effect` round-trip and holds the permit across the
    /// forward, dropping it only after the command's effect is fully handled.
    Committed(GatePermit),
    /// The predicate did not hold; the caller runs the ordinary slow path.
    Fallback,
}

/// RAII registration for one in-flight message. Decrements the gate counter on
/// `Drop`. Carried with its message through the channel; the consumer drops it
/// only after the message and every effect it spawns are processed.
///
/// Not `Clone`: exactly one permit exists per registered message.
#[derive(Debug)]
#[must_use = "a GatePermit must travel with its message; dropping it early frees the gate slot"]
pub struct GatePermit {
    inner: Arc<Mutex<FsmCore>>,
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        // Takes the gate mutex: must never run while the caller already holds
        // it. Only touches the counter.
        let mut inner = lock(&self.inner);
        inner.pending = inner.pending.saturating_sub(1);
    }
}

/// Sender half that registers every message in the [`Gate`] before enqueueing.
/// `send` mirrors [`mpsc::Sender::send`]'s signature so existing call sites are
/// unchanged; on failure it returns the original message in [`SendError`],
/// preserving tokio's error semantics, and the permit is freed outside the lock
/// as the rejected `(T, GatePermit)` tuple is dropped.
#[derive(Debug)]
pub struct GatedSender<T> {
    tx: mpsc::Sender<(T, GatePermit)>,
    gate: Gate,
}

impl<T> Clone for GatedSender<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            gate: self.gate.clone(),
        }
    }
}

impl<T> GatedSender<T> {
    /// Registers the message, then awaits channel capacity holding the permit
    /// the whole time. On a closed channel the permit rides back on the
    /// rejected tuple and is dropped here (outside the gate lock), and the
    /// original message is returned verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::error::SendError`] with the original message when the
    /// receiver has been dropped, matching [`mpsc::Sender::send`].
    pub async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        let permit = self.gate.register();
        match self.tx.send((msg, permit)).await {
            Ok(()) => Ok(()),
            Err(mpsc::error::SendError((msg, permit))) => {
                drop(permit);
                Err(mpsc::error::SendError(msg))
            }
        }
    }
}

/// Receiver half yielding `(message, permit)`. The caller holds the permit
/// until the message and its derived effects are processed, then drops it —
/// never while holding the gate lock.
#[derive(Debug)]
pub struct GatedReceiver<T> {
    rx: mpsc::Receiver<(T, GatePermit)>,
}

impl<T> GatedReceiver<T> {
    /// Receives the next `(message, permit)`. The caller holds the permit until
    /// the message and its derived effects are processed, then drops it — never
    /// while holding the gate lock.
    pub async fn recv(&mut self) -> Option<(T, GatePermit)> {
        self.rx.recv().await
    }

    /// Non-blocking receive, mirroring [`mpsc::Receiver::try_recv`]. The permit
    /// rides with the message; the caller drops it after processing (not while
    /// holding the gate lock).
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::error::TryRecvError`] when the channel is empty or the
    /// senders are all dropped, matching [`mpsc::Receiver::try_recv`].
    #[must_use = "the returned (message, permit) must be handled; dropping the permit frees the gate slot"]
    pub fn try_recv(&mut self) -> Result<(T, GatePermit), mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }
}

/// Builds a gated channel bound to `gate` with the given capacity.
#[must_use]
pub fn channel<T>(gate: Gate, capacity: usize) -> (GatedSender<T>, GatedReceiver<T>) {
    let (tx, rx) = mpsc::channel(capacity);
    (GatedSender { tx, gate }, GatedReceiver { rx })
}

/// Builds a gated channel with a fresh private [`Gate`] — for standalone/test
/// construction where no session-shared gate is threaded in. The returned
/// sender still routes every message through a permit, so there is no bypass.
#[must_use]
pub fn channel_with_new_gate<T>(capacity: usize) -> (GatedSender<T>, GatedReceiver<T>) {
    channel(Gate::new(), capacity)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn apply_slow_and_state_snapshot_drive_the_fsm_like_a_standalone() -> R {
        // The relocated FSM, driven through the core, must transition and emit
        // effects identically to a standalone `SessionFsm` on the same events.
        let core = Gate::new();
        let mut reference = SessionFsm::new();
        assert_eq!(core.state_snapshot(), reference.state());

        let script = [
            SessionEvent::ConnectionAccepted,
            SessionEvent::ClientHandshakeResponse,
            SessionEvent::BackendGreetingReceived,
            SessionEvent::BackendAuthOk,
            SessionEvent::ClientCommand,
            SessionEvent::BackendResponseTxnDone,
        ];
        for event in script {
            let SlowOutcome::Applied { result, post_state } = core.apply_slow(event, true) else {
                return Err(format!("open core must apply gated {event:?}, not drop it").into());
            };
            let expected = reference.on_event(event);
            assert_eq!(
                result, expected,
                "core effects/rejection match the standalone FSM for {event:?}"
            );
            assert_eq!(
                post_state,
                reference.state(),
                "core post-state matches the standalone FSM for {event:?}"
            );
            assert_eq!(
                core.state_snapshot(),
                reference.state(),
                "a later snapshot still matches for {event:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn gated_apply_is_dropped_once_closed_but_terminal_still_applies() {
        let core = Gate::new();
        core.seal_closed();
        // A gated (ordinary) event is refused after the seal...
        assert!(
            matches!(
                core.apply_slow(SessionEvent::ClientCommand, true),
                SlowOutcome::DroppedClosed
            ),
            "a gated event is dropped once the core is sealed closed"
        );
        // ...but a terminal (ungated) event still drives the FSM.
        assert!(
            matches!(
                core.apply_slow(SessionEvent::ConnectionAccepted, false),
                SlowOutcome::Applied { .. }
            ),
            "an ungated terminal event still applies after the seal"
        );
    }

    #[test]
    fn seal_closed_is_sticky_and_idempotent() {
        let core = Gate::new();
        assert!(core.is_open(), "a fresh core is open");
        core.seal_closed();
        assert!(!core.is_open(), "seal_closed closes the core");
        // The loop may reach several terminal checks; sealing again is a no-op
        // and never reopens.
        core.seal_closed();
        assert!(!core.is_open(), "once closed the core never reopens");
    }

    /// Drives a fresh core through the handshake to `Ready` (the steady state
    /// where the fast path is eligible).
    fn core_in_ready() -> Gate {
        let core = Gate::new();
        for event in [
            SessionEvent::ConnectionAccepted,
            SessionEvent::ClientHandshakeResponse,
            SessionEvent::BackendGreetingReceived,
            SessionEvent::BackendAuthOk,
        ] {
            assert!(
                matches!(core.apply_slow(event, true), SlowOutcome::Applied { .. }),
                "handshake event {event:?} should apply"
            );
        }
        assert_eq!(core.state_snapshot(), SessionState::Ready);
        core
    }

    #[test]
    fn try_commit_steady_commits_and_matches_the_slow_transition() -> R {
        let (_tx, shutdown) = watch::channel(false);
        let core = core_in_ready();

        // Reference: what the slow path would do for the same command.
        let reference = core_in_ready();
        let SlowOutcome::Applied { result, post_state } =
            reference.apply_slow(SessionEvent::ClientCommand, true)
        else {
            return Err("slow path must apply a Ready ClientCommand".into());
        };
        assert_eq!(
            result,
            Ok(vec![SessionEffect::ForwardCommandToBackend]),
            "the slow transition emits exactly the expected steady effect"
        );

        // Fast path: commits the same transition inline, registers one in-flight
        // permit, bumps the fast counter, and lands on the same FSM state.
        let FastPath::Committed(permit) = core.try_commit_steady(
            SessionEvent::ClientCommand,
            SessionEffect::ForwardCommandToBackend,
            &shutdown,
        ) else {
            return Err("a quiescent Ready ClientCommand must commit on the fast path".into());
        };
        assert_eq!(core.fast_transitions(), 1);
        assert_eq!(core.pending(), 1, "the in-flight guard holds the floor");
        assert_eq!(
            core.state_snapshot(),
            post_state,
            "fast commit lands on the same FSM state as the slow transition"
        );
        drop(permit);
        assert_eq!(core.pending(), 0, "dropping the permit frees the floor");
        Ok(())
    }

    #[test]
    fn try_commit_steady_falls_back_without_touching_the_core() {
        let assert_fallback = |core: &Gate, shutdown: &watch::Receiver<bool>, event, label| {
            let state_before = core.state_snapshot();
            let fast_before = core.fast_transitions();
            let pending_before = core.pending();
            assert!(
                matches!(
                    core.try_commit_steady(event, SessionEffect::ForwardCommandToBackend, shutdown),
                    FastPath::Fallback
                ),
                "{label}: must fall back"
            );
            assert_eq!(
                core.state_snapshot(),
                state_before,
                "{label}: FSM untouched"
            );
            assert_eq!(
                core.fast_transitions(),
                fast_before,
                "{label}: no fast count"
            );
            assert_eq!(
                core.pending(),
                pending_before,
                "{label}: no permit registered"
            );
        };

        let (_open_tx, open) = watch::channel(false);

        // Shutdown observed (value true).
        let (_tx, closed) = watch::channel(true);
        assert_fallback(
            &core_in_ready(),
            &closed,
            SessionEvent::ClientCommand,
            "shutdown-true",
        );

        // Shutdown sender dropped (has_changed -> Err -> treated as closed).
        let dropped = {
            let (tx, rx) = watch::channel(false);
            drop(tx);
            rx
        };
        assert_fallback(
            &core_in_ready(),
            &dropped,
            SessionEvent::ClientCommand,
            "sender-closed",
        );

        // Core sealed closed.
        let sealed = core_in_ready();
        sealed.seal_closed();
        assert_fallback(&sealed, &open, SessionEvent::ClientCommand, "sealed");

        // Pending non-zero (an operation permit in flight).
        let busy = core_in_ready();
        let op = busy.operation_permit();
        assert_fallback(&busy, &open, SessionEvent::ClientCommand, "pending!=0");
        drop(op);

        // Non-whitelisted event (Quit).
        assert_fallback(
            &core_in_ready(),
            &open,
            SessionEvent::ClientCommandQuit,
            "quit",
        );

        // FSM not in Ready (fresh core in Accept).
        assert_fallback(
            &Gate::new(),
            &open,
            SessionEvent::ClientCommand,
            "not-ready",
        );
    }

    #[test]
    fn try_commit_steady_rejects_an_effect_mismatch() {
        // Defensive exact-effect guard: even in Ready with a quiescent gate, a
        // commit is refused unless the speculative transition yields exactly the
        // single expected effect. Passing a different expected effect models a
        // caller/FSM drift and must fall back with zero writes.
        let (_tx, shutdown) = watch::channel(false);
        let core = core_in_ready();
        assert!(
            matches!(
                core.try_commit_steady(
                    SessionEvent::ClientCommand,
                    SessionEffect::ForwardResponseToClient,
                    &shutdown,
                ),
                FastPath::Fallback
            ),
            "a non-matching expected effect must fall back"
        );
        assert_eq!(core.fast_transitions(), 0);
        assert_eq!(core.pending(), 0);
        assert_eq!(core.state_snapshot(), SessionState::Ready);
    }

    #[test]
    fn probe_permit_is_quiescent_and_blocks_the_fast_path_across_its_await() {
        let (_tx, shutdown) = watch::channel(false);
        let only_ready = |state| state == SessionState::Ready;

        // Not probe-safe: a fresh core in Accept yields no permit.
        assert!(
            Gate::new().try_quiescent_operation(only_ready).is_none(),
            "a non-probe-safe state is not admitted"
        );

        // Sealed: no probe once terminating.
        let sealed = core_in_ready();
        sealed.seal_closed();
        assert!(
            sealed.try_quiescent_operation(only_ready).is_none(),
            "a sealed core admits no probe"
        );

        // Already busy: pending != 0 yields no permit.
        let busy = core_in_ready();
        let op = busy.operation_permit();
        assert!(
            busy.try_quiescent_operation(only_ready).is_none(),
            "a non-quiescent core (pending != 0) admits no probe"
        );
        drop(op);

        // Quiescent: a permit is granted, and WHILE it is held (modeling the
        // probe's `backend_active().await`) the engine fast path falls back —
        // so no concurrent inline commit can turn Ready -> Command mid-probe.
        let core = core_in_ready();
        let Some(probe_permit) = core.try_quiescent_operation(only_ready) else {
            unreachable!("a quiescent probe-safe core admits the probe");
        };
        assert_eq!(core.pending(), 1, "the probe permit holds the floor");
        assert!(
            matches!(
                core.try_commit_steady(
                    SessionEvent::ClientCommand,
                    SessionEffect::ForwardCommandToBackend,
                    &shutdown,
                ),
                FastPath::Fallback
            ),
            "the fast path falls back while the probe permit is held"
        );
        assert_eq!(
            core.fast_transitions(),
            0,
            "no commit happened during the probe"
        );
        assert_eq!(
            core.state_snapshot(),
            SessionState::Ready,
            "FSM untouched during the probe"
        );
        drop(probe_permit);
        assert_eq!(
            core.pending(),
            0,
            "dropping the probe permit frees the floor"
        );
    }

    #[tokio::test]
    async fn pending_visible_before_apply_and_cleared_after_drop() -> R {
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 4);
        assert_eq!(gate.pending(), 0);
        tx.send(7).await?;
        // Registered and visible before the consumer applies it.
        assert_eq!(
            gate.pending(),
            1,
            "pending visible while message is in flight"
        );
        let (msg, permit) = rx.recv().await.ok_or("recv")?;
        assert_eq!(msg, 7);
        // Still pending until the consumer finishes and drops the permit.
        assert_eq!(gate.pending(), 1, "pending held across apply");
        drop(permit);
        assert_eq!(gate.pending(), 0, "pending cleared after apply");
        Ok(())
    }

    #[tokio::test]
    async fn derived_permit_acquired_before_parent_drop_leaves_no_gap() -> R {
        // Models loop apply: while still holding the parent message's permit,
        // register a derived effect; only then drop the parent. pending never
        // returns to 0 in between.
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 4);
        tx.send(1).await?;
        let (_m, parent) = rx.recv().await.ok_or("recv parent")?;
        assert_eq!(gate.pending(), 1);
        // Derived effect enqueued before the parent permit is dropped.
        tx.send(2).await?;
        assert_eq!(gate.pending(), 2);
        drop(parent);
        assert_eq!(
            gate.pending(),
            1,
            "no pending=0 gap: derived still in flight"
        );
        let (_m2, derived) = rx.recv().await.ok_or("recv derived")?;
        drop(derived);
        assert_eq!(gate.pending(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn operation_permit_holds_the_floor_across_a_consumed_first_message() -> R {
        // Models the redirect pair: an operation permit spans two sends. The
        // first message is consumed and its permit dropped before the second is
        // registered; pending must never reach 0 in that window.
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 4);
        let op = gate.operation_permit();
        assert_eq!(gate.pending(), 1, "operation permit registered");
        // First message of the pair.
        tx.send(1).await?;
        assert_eq!(gate.pending(), 2);
        // Engine consumes and drops the first permit before the second send.
        let (_m, first) = rx.recv().await.ok_or("recv first")?;
        drop(first);
        assert_eq!(gate.pending(), 1, "operation permit still holds the floor");
        // Second message of the pair.
        tx.send(2).await?;
        assert_eq!(gate.pending(), 2);
        // Operation permit released only after the second is registered.
        drop(op);
        assert_eq!(gate.pending(), 1, "second message still in flight");
        let (_m2, second) = rx.recv().await.ok_or("recv second")?;
        drop(second);
        assert_eq!(gate.pending(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn handshake_permits_release_before_the_steady_phase() -> R {
        // Models the engine lifecycle: each handshake effect holds a permit
        // across its I/O then drops it; by the time the steady command phase
        // runs, pending is 0, and it returns to 0 between commands (so a later
        // fast path can engage at a command boundary).
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 4);
        // Handshake: three effects, each permit scoped to its own I/O.
        for effect in [10_u8, 11, 12] {
            tx.send(effect).await?;
            let (_e, permit) = rx.recv().await.ok_or("recv handshake effect")?;
            // ... effect I/O happens here, permit held ...
            drop(permit);
            assert_eq!(gate.pending(), 0, "handshake permit released after its I/O");
        }
        assert_eq!(
            gate.pending(),
            0,
            "no handshake permit leaks into the steady phase"
        );
        // Steady phase: each command's permit drops at the end of its iteration.
        for cmd in [20_u8, 21] {
            tx.send(cmd).await?;
            let (_c, permit) = rx.recv().await.ok_or("recv command")?;
            assert_eq!(gate.pending(), 1, "in-flight during the command");
            drop(permit);
            assert_eq!(gate.pending(), 0, "pending back to 0 between commands");
        }
        Ok(())
    }

    #[tokio::test]
    async fn closed_receiver_returns_original_msg_and_frees_slot() -> R {
        let gate = Gate::new();
        let (tx, rx) = channel::<String>(gate.clone(), 1);
        drop(rx);
        let Err(err) = tx.send("hello".to_owned()).await else {
            return Err("expected closed-channel error".into());
        };
        assert_eq!(err.0, "hello", "original message returned verbatim");
        assert_eq!(gate.pending(), 0, "permit freed on closed-channel failure");
        Ok(())
    }

    #[tokio::test]
    async fn dropped_queued_message_frees_slot() -> R {
        // A message enqueued but never received (receiver dropped with items
        // still buffered) frees its slot when the channel drops it.
        let gate = Gate::new();
        let (tx, rx) = channel::<u8>(gate.clone(), 4);
        tx.send(1).await?;
        tx.send(2).await?;
        assert_eq!(gate.pending(), 2);
        drop(rx);
        drop(tx);
        assert_eq!(
            gate.pending(),
            0,
            "buffered-but-undelivered messages free their slots"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_send_future_frees_slot() -> R {
        // Fill the channel, then cancel a blocked send; its permit must return.
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 1);
        tx.send(1).await?;
        assert_eq!(gate.pending(), 1);
        {
            let blocked = tx.send(2);
            tokio::pin!(blocked);
            // Poll once; it cannot complete (channel full), then drop (cancel).
            let _ = tokio::time::timeout(std::time::Duration::from_millis(20), &mut blocked).await;
        }
        // The cancelled send's permit is freed; only the first message remains.
        let (_m, permit) = rx.recv().await.ok_or("recv")?;
        drop(permit);
        assert_eq!(gate.pending(), 0, "cancelled send frees its slot");
        Ok(())
    }
}
