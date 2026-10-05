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
    /// Loop is running and has not entered terminal handling. (S1: always true;
    /// the terminal gate is wired in a later slice.)
    open: bool,
}

/// Handle to the shared admission gate for one session.
#[derive(Clone, Debug)]
pub(crate) struct Gate {
    inner: Arc<Mutex<GateInner>>,
}

impl Gate {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(GateInner {
                pending: 0,
                open: true,
            })),
        }
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
pub(crate) struct GatePermit {
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
pub(crate) struct GatedSender<T> {
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
    pub(crate) async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
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
pub(crate) struct GatedReceiver<T> {
    rx: mpsc::Receiver<(T, GatePermit)>,
}

impl<T> GatedReceiver<T> {
    pub(crate) async fn recv(&mut self) -> Option<(T, GatePermit)> {
        self.rx.recv().await
    }
}

/// Builds a gated channel bound to `gate` with the given capacity.
pub(crate) fn channel<T>(gate: Gate, capacity: usize) -> (GatedSender<T>, GatedReceiver<T>) {
    let (tx, rx) = mpsc::channel(capacity);
    (GatedSender { tx, gate }, GatedReceiver { rx })
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_visible_before_apply_and_cleared_after_drop() {
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 4);
        assert_eq!(gate.pending(), 0);
        tx.send(7).await.expect("send");
        // Registered and visible before the consumer applies it.
        assert_eq!(
            gate.pending(),
            1,
            "pending visible while message is in flight"
        );
        let (msg, permit) = rx.recv().await.expect("recv");
        assert_eq!(msg, 7);
        // Still pending until the consumer finishes and drops the permit.
        assert_eq!(gate.pending(), 1, "pending held across apply");
        drop(permit);
        assert_eq!(gate.pending(), 0, "pending cleared after apply");
    }

    #[tokio::test]
    async fn derived_permit_acquired_before_parent_drop_leaves_no_gap() {
        // Models loop apply: while still holding the parent message's permit,
        // register a derived effect; only then drop the parent. pending never
        // returns to 0 in between.
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 4);
        tx.send(1).await.expect("send parent");
        let (_m, parent) = rx.recv().await.expect("recv parent");
        assert_eq!(gate.pending(), 1);
        // Derived effect enqueued before the parent permit is dropped.
        tx.send(2).await.expect("send derived");
        assert_eq!(gate.pending(), 2);
        drop(parent);
        assert_eq!(
            gate.pending(),
            1,
            "no pending=0 gap: derived still in flight"
        );
        let (_m2, derived) = rx.recv().await.expect("recv derived");
        drop(derived);
        assert_eq!(gate.pending(), 0);
    }

    #[tokio::test]
    async fn closed_receiver_returns_original_msg_and_frees_slot() {
        let gate = Gate::new();
        let (tx, rx) = channel::<String>(gate.clone(), 1);
        drop(rx);
        let err = tx.send("hello".to_owned()).await.expect_err("closed");
        assert_eq!(err.0, "hello", "original message returned verbatim");
        assert_eq!(gate.pending(), 0, "permit freed on closed-channel failure");
    }

    #[tokio::test]
    async fn dropped_queued_message_frees_slot() {
        // A message enqueued but never received (receiver dropped with items
        // still buffered) frees its slot when the channel drops it.
        let gate = Gate::new();
        let (tx, rx) = channel::<u8>(gate.clone(), 4);
        tx.send(1).await.expect("send");
        tx.send(2).await.expect("send");
        assert_eq!(gate.pending(), 2);
        drop(rx);
        drop(tx);
        assert_eq!(
            gate.pending(),
            0,
            "buffered-but-undelivered messages free their slots"
        );
    }

    #[tokio::test]
    async fn cancelled_send_future_frees_slot() {
        // Fill the channel, then cancel a blocked send; its permit must return.
        let gate = Gate::new();
        let (tx, mut rx) = channel::<u8>(gate.clone(), 1);
        tx.send(1).await.expect("fill");
        assert_eq!(gate.pending(), 1);
        {
            let blocked = tx.send(2);
            tokio::pin!(blocked);
            // Poll once; it cannot complete (channel full), then drop (cancel).
            let _ = tokio::time::timeout(std::time::Duration::from_millis(20), &mut blocked).await;
        }
        // The cancelled send's permit is freed; only the first message remains.
        let (_m, permit) = rx.recv().await.expect("recv");
        drop(permit);
        // Give any freed permit time to settle (all synchronous here).
        assert_eq!(gate.pending(), 0, "cancelled send frees its slot");
    }
}
