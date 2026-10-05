//! Fast-path admission gate (v5, slice S1 — plumbing only, no fast path yet).
//!
//! Every message that can change how the *next* client command is handled —
//! engine→loop [`SessionEvent`]s, loop/owner→engine [`EngineCmd`]s, and
//! owner→loop [`SessionControl`]s — is registered in a shared counter before it
//! is enqueued and deregistered only after it (and every effect it spawns) has
//! been fully processed. A later slice reads `pending == 0 && open` to decide
//! whether the engine may inline a steady transition; S1 only installs the
//! counter and routes all three channels through it, with no behavior change.
//!
//! Registration is a RAII [`GatePermit`] carried alongside the message in the
//! channel (`mpsc::Sender<(T, GatePermit)>`). The permit's `Drop` decrements
//! the counter, so a cancelled send, a closed receiver, or a dropped queued
//! message all return the count automatically. The one hard rule: a
//! `GatePermit` must never be dropped while its [`Gate`] mutex is held (its
//! `Drop` takes that mutex), and the mutex is only ever held for the trivial
//! counter arithmetic — never across an `.await`, channel send, or effect.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

/// Shared gate state. The mutex guards only the small counters; no `.await`,
/// send, or effect runs while it is held.
#[derive(Debug)]
struct GateInner {
    /// Registered-but-not-yet-processed messages across all producers/channels.
    pending: u32,
    /// Loop is running and has not entered terminal handling. (S1: always true
    /// and not yet read; the terminal gate consumes it in a later slice.)
    #[allow(dead_code)]
    open: bool,
}

/// Handle to the shared admission gate for one session.
#[derive(Clone, Debug)]
pub struct Gate {
    inner: Arc<Mutex<GateInner>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    /// Creates a gate with zero in-flight messages and `open == true`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(GateInner {
                pending: 0,
                open: true,
            })),
        }
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

    /// Whether the loop is still open. Test/diagnostic only until the terminal
    /// gate consumes it.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn is_open(&self) -> bool {
        lock(&self.inner).open
    }
}

/// RAII registration for one in-flight message. Decrements the gate counter on
/// `Drop`. Carried with its message through the channel; the consumer drops it
/// only after the message and every effect it spawns are processed.
///
/// Not `Clone`: exactly one permit exists per registered message.
#[derive(Debug)]
#[must_use = "a GatePermit must travel with its message; dropping it early frees the gate slot"]
pub struct GatePermit {
    inner: Arc<Mutex<GateInner>>,
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
