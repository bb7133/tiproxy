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

//! Tick budgets and bounded, payload-free simulation commands.
use crate::{ForceClose, Redirect};
use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
pub(crate) const TICK: Duration = Duration::from_millis(10);
/// An admitted local simulation operation. Neither variant performs I/O.
#[derive(Clone, Debug)]
pub enum MigrationCommand {
    /// Score transferred; physical completion is a later event.
    Redirect(Redirect),
    /// Closing admitted; accounting stays until an observed close.
    ForceClose(ForceClose),
}
impl From<Redirect> for MigrationCommand {
    fn from(value: Redirect) -> Self {
        Self::Redirect(value)
    }
}
impl From<ForceClose> for MigrationCommand {
    fn from(value: ForceClose) -> Self {
        Self::ForceClose(value)
    }
}
#[cfg(test)]
type CommandSink = Box<dyn Fn(&MigrationCommand) -> bool + Send + Sync>;
pub(crate) struct CommandQueue {
    capacity: usize,
    #[cfg(test)]
    api_sink: Option<CommandSink>,
    entries: Mutex<VecDeque<MigrationCommand>>,
}
impl CommandQueue {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            #[cfg(test)]
            api_sink: None,
            entries: Mutex::new(VecDeque::new()),
        }
    }
    // Test-client acceptance at the command boundary, never internal selection.
    #[cfg(test)]
    pub(crate) fn with_api_sink(capacity: usize, sink: CommandSink) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
            api_sink: Some(sink),
        }
    }
    pub(crate) fn try_send(&self, command: impl Into<MigrationCommand>) -> Result<(), ()> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity {
            return Err(());
        }
        let command = command.into();
        #[cfg(test)]
        if self.api_sink.as_ref().is_some_and(|sink| !sink(&command)) {
            return Err(());
        }
        entries.push_back(command);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn observation(&self) -> Vec<String> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|c| match c {
                MigrationCommand::Redirect(r) => format!("r{}", r.to().connection_id),
                MigrationCommand::ForceClose(c) => format!("c{}", c.assignment().connection_id),
            })
            .collect()
    }
    pub(crate) fn take(&self) -> Option<MigrationCommand> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }
    #[cfg(test)]
    pub(crate) fn take_redirect(&self) -> Option<Redirect> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(entries.front(), Some(MigrationCommand::Redirect(_))) {
            return None;
        }
        match entries.pop_front() {
            Some(MigrationCommand::Redirect(redirect)) => Some(redirect),
            _ => unreachable!("checked queue front under lock"),
        }
    }
}
/// Bounded per-group observations; these counters grant no issuance authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MigrationProgress {
    /// Accepted redirects, not attempts or results.
    pub redirects: u64,
    /// Accepted close commands, not observed closed sessions.
    pub closes: u64,
    /// Pair and issuance-backstop keyspace refusals.
    pub keyspace_refusals: u64,
    /// Refusal evidence records limited to once per group per ten seconds.
    pub keyspace_records: u64,
}
/// The latest rate-limited keyspace refusal record for a retained group.
/// Its bounded diagnostic fields never authorize a redirect or expose payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyspaceRefusal {
    /// Current physical source backend identifier.
    pub from: String,
    /// Refused destination backend identifier.
    pub to: String,
    /// Source's current routing keyspace.
    pub from_keyspace: String,
    /// Destination's current routing keyspace.
    pub to_keyspace: String,
    /// Pair factor, absent for the manual issuance backstop.
    pub reason: Option<crate::Factor>,
    /// Source population represented by this refusal.
    pub physical_connections: u64,
    /// Accumulated refused pairs/backstop calls when the record was emitted.
    pub refusals: u64,
}

#[derive(Default)]
pub(crate) struct GroupSchedule {
    pub(crate) last_accepted: Option<Instant>,
    last_keyspace_record: Option<Instant>,
    pub(crate) last_refusal: Option<KeyspaceRefusal>,
    pub(crate) progress: MigrationProgress,
}
impl GroupSchedule {
    // Explicit extreme-rate difference: clamp zero to 1ns and bound each round
    // by source physical population; ordinary rates truncate like Go.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub(crate) fn budget(&self, rate: f64, now: Instant, physical: usize) -> usize {
        if rate.is_nan() || rate <= 0.0 {
            return 0;
        }
        let interval = Duration::from_nanos(((1_000_000_000.0 / rate) as u64).max(1));
        if interval < TICK * 2 {
            usize::try_from((TICK.as_nanos() - 1) / interval.as_nanos() + 1)
                .unwrap_or(usize::MAX)
                .min(physical)
        } else if self
            .last_accepted
            .is_none_or(|last| now.saturating_duration_since(last) >= interval)
        {
            physical.min(1)
        } else {
            0
        }
    }
    pub(crate) fn accepted(&mut self, now: Instant) {
        self.last_accepted = Some(now);
        self.progress.redirects = self.progress.redirects.saturating_add(1);
    }
    pub(crate) fn refuse_keyspace(&mut self, now: Instant, mut record: KeyspaceRefusal) {
        self.progress.keyspace_refusals = self.progress.keyspace_refusals.saturating_add(1);
        if self
            .last_keyspace_record
            .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(10))
        {
            self.last_keyspace_record = Some(now);
            record.refusals = self.progress.keyspace_refusals;
            self.last_refusal = Some(record);
            self.progress.keyspace_records = self.progress.keyspace_records.saturating_add(1);
        }
    }
}

// Production reads a fresh monotonic clock for each group and again for close.
// Deterministic injection is compiled only into unit/evidence tests.
#[derive(Default)]
pub(crate) struct RoundClock {
    #[cfg(test)]
    pub(crate) fixed: Option<(Instant, Instant, i64)>,
}
// The receiver carries the test-only clock values; production reads fresh time.
#[cfg_attr(not(test), allow(clippy::unused_self))]
impl RoundClock {
    pub(crate) fn balance_now(&self) -> Instant {
        #[cfg(test)]
        if let Some((balance, _, _)) = self.fixed {
            return balance;
        }
        tokio::time::Instant::now().into_std()
    }
    pub(crate) fn close_now(&self) -> Instant {
        #[cfg(test)]
        if let Some((_, close, _)) = self.fixed {
            return close;
        }
        tokio::time::Instant::now().into_std()
    }
    pub(crate) fn wall(&self) -> Result<i64, crate::RouteError> {
        #[cfg(test)]
        if let Some((_, _, wall)) = self.fixed {
            return Ok(wall);
        }
        crate::selector::now_nanos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_extreme_rates_bound_scan_and_reject_invalid_rates() {
        let schedule = GroupSchedule::default();
        let now = Instant::now();
        for rate in [1e20, f64::INFINITY] {
            assert_eq!(schedule.budget(rate, now, 6), 6, "WORKER_EXTREME_BOUND");
        }
        for rate in [0.0, -1.0, f64::NAN] {
            assert_eq!(schedule.budget(rate, now, 6), 0);
        }
        assert_eq!(schedule.budget(1e20, now, 0), 0);
    }
}
