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

//! A borrowed, owned worker future: callers cancel and await it before releasing
//! its simulation. It never spawns a detached child or accepts an effect sender.
use super::MigrationSimulation;
use crate::{MigrationProgress, RouteError};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;

struct Running<'a>(&'a AtomicBool);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn stopped(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}
impl MigrationSimulation {
    #[cfg(test)]
    pub(crate) fn worker_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Per-group bounded diagnostics. These values cannot authorize commands.
    #[must_use]
    pub fn progress(&self) -> BTreeMap<u64, MigrationProgress> {
        self.router.migration_progress()
    }

    /// Latest structured refusal per retained group, bounded to one record
    /// every ten seconds. Reading it grants no session/effect authority.
    #[must_use]
    pub fn keyspace_records(&self) -> BTreeMap<u64, crate::KeyspaceRefusal> {
        self.router.keyspace_records()
    }

    /// Runs the sole owned 10ms worker in this borrowed simulation. Signal true
    /// or drop the stop sender, then await this future before releasing the
    /// owner. Source notifications update failover clocks without issuing a
    /// migration round; the ticker drops missed ticks and delays its first tick.
    /// # Errors
    /// Returns `WorkerRunning` for a duplicate worker, or an unavailable/retired
    /// source error. Temporary missing backend rounds are retried on publication.
    pub async fn run_worker(
        &self,
        redirects_enabled: bool,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), RouteError> {
        self.running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RouteError::WorkerRunning)?;
        let _running = Running(&self.running);
        let (mut config, mut backend, mut lifecycle) = self.router.migration_updates();
        let mut ticker = ticker();
        // Register observers before the first capture, so no publication edge
        // is lost between initialization and the select loop.
        self.refresh_worker_state()?;
        #[cfg(test)]
        self.initialized.store(true, Ordering::Release);
        loop {
            if stopped(&stop) || lifecycle.borrow().phase != control_plane::LifecyclePhase::Ready {
                return Ok(());
            }
            let tick = tokio::select! {
                biased;
                _ = stop.changed() => false,
                changed = lifecycle.changed() => { if changed.is_err() { return Ok(()); } false },
                changed = config.changed() => { changed.map_err(|_| RouteError::ControlUnavailable)?; false },
                changed = backend.changed() => { changed.map_err(|_| RouteError::ControlUnavailable)?; false },
                _ = ticker.tick() => true,
            };
            if stopped(&stop) || lifecycle.borrow().phase != control_plane::LifecyclePhase::Ready {
                return Ok(());
            }
            let candidate = match self.router.capture() {
                Ok(candidate) => candidate,
                Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => continue,
                Err(error) => return Err(error),
            };
            let now = tokio::time::Instant::now().into_std();
            let result = if tick {
                self.router.migration_round(
                    &candidate,
                    &self.sender,
                    redirects_enabled,
                    &stop,
                    &crate::scheduler::RoundClock::default(),
                )
            } else {
                self.router.refresh_failover(&candidate, now)
            };
            match result {
                Ok(()) | Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => (),
                Err(error) => return Err(error),
            }
        }
    }
    fn refresh_worker_state(&self) -> Result<(), RouteError> {
        match self.router.capture() {
            Ok(candidate) => match self
                .router
                .refresh_failover(&candidate, tokio::time::Instant::now().into_std())
            {
                Ok(()) | Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => Ok(()),
                Err(error) => Err(error),
            },
            Err(RouteError::StaleCandidate | RouteError::ControlUnavailable) => Ok(()),
            Err(error) => Err(error),
        }
    }
    #[cfg(test)]
    pub(crate) fn round_at(
        &self,
        candidate: &crate::Candidate,
        redirects_enabled: bool,
        stop: &watch::Receiver<bool>,
        balance_now: std::time::Instant,
        close_now: std::time::Instant,
        wall: i64,
    ) -> Result<(), RouteError> {
        self.router.migration_round(
            candidate,
            &self.sender,
            redirects_enabled,
            stop,
            &crate::scheduler::RoundClock {
                fixed: Some((balance_now, close_now, wall)),
            },
        )
    }
}

fn ticker() -> tokio::time::Interval {
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + crate::scheduler::TICK,
        crate::scheduler::TICK,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn worker_ticker_delays_first_tick_and_skips_missed_ticks() {
        let start = tokio::time::Instant::now();
        let mut tick = ticker();
        tick.tick().await;
        assert_eq!(
            tokio::time::Instant::now() - start,
            crate::scheduler::TICK,
            "WORKER_FIRST_TICK"
        );
        tokio::time::advance(std::time::Duration::from_millis(55)).await;
        tick.tick().await;
        assert!(
            {
                let mut future = Box::pin(tick.tick());
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(future.as_mut().poll(cx).is_pending())
                })
                .await
            },
            "WORKER_MISSED_SKIP"
        );
        tokio::time::advance(std::time::Duration::from_millis(5)).await;
        tick.tick().await;
        assert_eq!(
            tokio::time::Instant::now() - start,
            std::time::Duration::from_millis(70)
        );
    }
}
