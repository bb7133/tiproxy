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

//! In-process intake and export lifecycle. Network I/O never holds the intake lock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::export::{ObjectStore, encode_window};
use crate::{Batch, Checkpoint, Consumer, Error, Intake, Outbox};

/// The Go meter's upload deadline, including shutdown's final attempt.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const INTERVAL: i64 = 60;

struct State {
    consumer: Consumer<Outbox>,
    accepting: bool,
}

/// Shared intake and one serialized exporter for a single fenced meter owner.
///
/// The sampler may persist batches while an immutable window is uploading.
/// After an export error intake returns `Unhealthy` without changing consumer
/// state. A successful export retry can restore this handle before the next intake,
/// but the native sampler treats any rejected batch as fatal, matching the Go
/// owner. It preserves the WAL for process restart; it does not pause and resume.
/// Stop and join the sampler before signaling the export worker to shut down.
pub struct Meter<S> {
    state: Mutex<State>,
    export_gate: AsyncMutex<()>,
    store: S,
    shared_pool_id: String,
    started: AtomicBool,
    failures: watch::Sender<u64>,
}

impl<S: ObjectStore> Meter<S> {
    /// Composes an already opened consumer/outbox and storage provider.
    #[must_use]
    pub fn new(consumer: Consumer<Outbox>, store: S, shared_pool_id: String) -> Arc<Self> {
        let (failures, _) = watch::channel(0);
        Arc::new(Self {
            state: Mutex::new(State {
                consumer,
                accepting: true,
            }),
            export_gate: AsyncMutex::new(()),
            store,
            shared_pool_id,
            started: AtomicBool::new(false),
            failures,
        })
    }

    /// Durably ingests one batch. Only success authorizes the producer's WAL ACK.
    /// This synchronous disk operation belongs on the sampler/control path.
    ///
    /// # Errors
    /// Rejects stopped/unhealthy owners, malformed batches and persistence failures.
    pub fn apply(&self, batch: &Batch) -> Result<bool, Error> {
        let mut state = self.state()?;
        if !state.accepting || !state.consumer.healthy() {
            return Err(Error::Unhealthy);
        }
        state.consumer.apply(batch)
    }

    /// Current readiness, including asynchronous export failure and owner retirement.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.state()
            .is_ok_and(|state| state.accepting && state.consumer.healthy())
    }

    /// Last staged sequence, for diagnostics only; ACKs still require `apply` success.
    ///
    /// # Errors
    /// Returns unhealthy if the state lock was poisoned.
    pub fn checkpoint(&self) -> Result<Checkpoint, Error> {
        Ok(self.state()?.consumer.checkpoint())
    }

    /// Monotonic export failure count for the process metrics/logging owner.
    #[must_use]
    pub fn export_failures(&self) -> watch::Receiver<u64> {
        self.failures.subscribe()
    }

    /// Serializes exports, retaining pending identity across upload failures/cancellation.
    /// Intake is locked only when sealing or committing the durable window.
    ///
    /// # Errors
    /// Returns encoding, storage, timeout, ownership or persistence errors.
    pub async fn flush(&self, timestamp: i64, timeout: Duration) -> Result<bool, Error> {
        let _export = self.export_gate.lock().await;
        let (self_id, window) = {
            let mut state = self.state()?;
            let outbox = state.consumer.sink_mut();
            let Some(window) = outbox.seal(timestamp)? else {
                return Ok(false);
            };
            (outbox.self_id().to_owned(), window)
        };
        let upload = async {
            let object = encode_window(&self_id, &self.shared_pool_id, &window)?;
            self.store.put_new(&object.key, object.body).await
        };
        let result = match tokio::time::timeout(timeout, upload).await {
            Ok(result) => result,
            Err(_) => Err(Error::Export("upload timeout")),
        };
        let mut state = self.state()?;
        match result {
            Ok(()) => {
                state.consumer.sink_mut().exported(&window)?;
                Ok(true)
            }
            Err(error) => {
                state.consumer.sink_mut().export_failed();
                Err(error)
            }
        }
    }

    /// Runs startup recovery, minute-aligned export and a bounded final flush.
    ///
    /// Exactly one call is allowed. Periodic storage failures remain observable
    /// through `healthy` and `export_failures`; the worker retries pending data.
    /// Shutdown closes intake before its last flush and returns that flush's error.
    /// The process owner must join this future before retiring its owner token.
    ///
    /// # Errors
    /// Returns on duplicate start, invalid wall time or final export failure.
    pub async fn run(&self, shutdown: watch::Receiver<bool>) -> Result<(), Error> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Err(Error::Invalid("meter export worker already started"));
        }
        // Keep polling maintenance while an export awaits the same credential
        // lock. Selecting it only between exports would suspend its lock holder.
        tokio::select! {
            never = self.store.maintain() => match never {},
            result = self.run_exports(shutdown) => result,
        }
    }

    async fn run_exports(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), Error> {
        let current = unix_seconds()?;
        let _ = self.attempt(current / INTERVAL * INTERVAL).await;
        let mut next = current / INTERVAL * INTERVAL + INTERVAL;
        loop {
            if *shutdown.borrow() || shutdown.has_changed().is_err() {
                break;
            }
            let seconds = u64::try_from(next.saturating_sub(unix_seconds()?)).unwrap_or(0);
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                () = tokio::time::sleep(Duration::from_secs(seconds)) => {
                    let _ = self.attempt(next).await;
                    next = next.checked_add(INTERVAL).ok_or(Error::Invalid("export clock overflow"))?;
                }
            }
        }
        self.state()?.accepting = false;
        self.attempt(next).await.map(|_| ())
    }

    async fn attempt(&self, timestamp: i64) -> Result<bool, Error> {
        let result = self.flush(timestamp, WRITE_TIMEOUT).await;
        if result.is_err() {
            self.failures
                .send_modify(|count| *count = count.saturating_add(1));
        }
        result
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.state.lock().map_err(|_| Error::Unhealthy)
    }
}

impl<S: ObjectStore> Intake for Meter<S> {
    fn apply(&self, batch: &Batch) -> Result<bool, Error> {
        Self::apply(self, batch)
    }
}

fn unix_seconds() -> Result<i64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_secs()).ok())
        .filter(|seconds| *seconds >= INTERVAL)
        .ok_or(Error::Invalid(
            "export clock before first minute or out of range",
        ))
}
