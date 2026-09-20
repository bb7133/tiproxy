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

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use control_plane::ownership::OwnerToken;
use serde::{Deserialize, Serialize};

use crate::persistence::StateFile;
use crate::types::{valid_checkpoint, valid_producer};
use crate::{Batch, Checkpoint, Delta, DurableSink, Error, SourceBaseline, SourceKey};

type TotalKey = (String, String, bool);

#[derive(Clone, Deserialize, Serialize)]
struct PersistedSource {
    key: SourceKey,
    baseline: SourceBaseline,
}

#[derive(Clone, Deserialize, Serialize)]
struct State {
    version: u32,
    producer_id: String,
    last_applied: u64,
    process_generation: u64,
    sources: Vec<PersistedSource>,
    totals: Vec<Delta>,
    pending: Vec<Delta>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            producer_id: String::new(),
            last_applied: 0,
            process_generation: 0,
            sources: Vec::new(),
            totals: Vec::new(),
            pending: Vec::new(),
        }
    }
}

/// Durable absolute-counter consumer. Own this with its sink in one module task.
///
/// The consumer checkpoints before sink ingestion; the sink commits its aggregate
/// and sequence together. A crash on either side of ingestion is recovered by
/// retrying the same producer-qualified batch, never by resetting a checkpoint.
pub struct Consumer<S> {
    file: StateFile,
    state: State,
    healthy: bool,
    sink: S,
}

impl<S: DurableSink> Consumer<S> {
    /// Opens compatible Go consumer state and checks it against the durable sink.
    ///
    /// # Errors
    /// Rejects corrupt state, missing/mismatched sink checkpoints or retired ownership.
    pub fn open(path: impl Into<PathBuf>, owner: OwnerToken, sink: S) -> Result<Self, Error> {
        if !sink.healthy() {
            return Err(Error::Unhealthy);
        }
        let file = StateFile::new(path.into(), owner)?;
        let state = if let Some(state) = file.load::<State>()? {
            validate_state(&state)?;
            state
        } else {
            let state = State::default();
            file.persist(&state)?;
            state
        };
        let value = Self {
            file,
            state,
            healthy: true,
            sink,
        };
        value.validate_sink()?;
        Ok(value)
    }

    /// Whether both durable stages are available for producer acknowledgments.
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.healthy && self.file.check_owner().is_ok() && self.sink.healthy()
    }

    /// Last durably staged sequence; callers ACK only after successful `apply`.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            producer_id: self.state.producer_id.clone(),
            sequence: self.state.last_applied,
        }
    }

    /// Saturating diagnostic totals, ordered by keyspace, backend, and peer class.
    #[must_use]
    pub fn totals(&self) -> &[Delta] {
        &self.state.totals
    }

    /// The owned sink, for inspecting its exporter/checkpoint state.
    #[must_use]
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    /// Mutable access from the same module owner, for sealing/exporting windows.
    pub const fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Applies one sample batch; `false` means an already applied sequence.
    ///
    /// # Errors
    /// Gaps, attribution changes, counter regression, overflow, and durable failures
    /// reject the batch. An I/O/sink failure permanently fences this instance.
    pub fn apply(&mut self, batch: &Batch) -> Result<bool, Error> {
        self.file.check_owner()?;
        if !valid_producer(&batch.producer_id)
            || batch.snapshots.is_empty()
            || batch.snapshots.len() > 1024
        {
            return Err(Error::Invalid("producer or snapshot bound"));
        }
        if !self.healthy {
            return Err(Error::Unhealthy);
        }
        if let Err(error) = self.validate_sink() {
            self.healthy = false;
            return Err(error);
        }
        if !self.state.producer_id.is_empty() && self.state.producer_id != batch.producer_id {
            return Err(Error::Invalid("producer mismatch"));
        }
        if self.state.producer_id == batch.producer_id && batch.sequence <= self.state.last_applied
        {
            if batch.sequence == self.state.last_applied {
                self.drain_pending()?;
            }
            return Ok(false);
        }
        if self.state.last_applied.checked_add(1) != Some(batch.sequence) {
            return Err(Error::Invalid("sequence gap"));
        }
        let state = self.stage(batch)?;
        if let Err(error) = self.file.persist(&state) {
            self.healthy = false;
            return Err(error);
        }
        self.state = state;
        self.drain_pending()?;
        Ok(true)
    }

    fn stage(&self, batch: &Batch) -> Result<State, Error> {
        let generation = batch.snapshots[0].key.process_generation;
        if generation < self.state.process_generation
            || batch
                .snapshots
                .iter()
                .any(|s| s.key.process_generation != generation)
        {
            return Err(Error::Invalid("process generation regressed or mixed"));
        }
        let mut sources: BTreeMap<_, _> = self
            .state
            .sources
            .iter()
            .filter(|s| s.key.process_generation >= generation)
            .map(|s| (s.key, s.baseline.clone()))
            .collect();
        let mut totals = total_map(&self.state.totals)?;
        let mut pending = total_map(&self.state.pending)?;
        let mut seen = BTreeSet::new();
        for snapshot in &batch.snapshots {
            let key = snapshot.key;
            let current = &snapshot.baseline;
            validate_source(key, current, generation)?;
            if !seen.insert(key) {
                return Err(Error::Invalid("duplicate source"));
            }
            let previous = sources.get(&key);
            if let Some(previous) = previous
                && (previous.backend_id != current.backend_id
                    || previous.cluster_name != current.cluster_name
                    || previous.keyspace != current.keyspace
                    || previous.local != current.local
                    || previous.public_endpoint != current.public_endpoint)
            {
                return Err(Error::Invalid("source attribution mutated"));
            }
            let inbound = counter_delta(
                previous.map(|p| (p.inbound_bytes, p.inbound_wrap_epoch)),
                current.inbound_bytes,
                current.inbound_wrap_epoch,
            )?;
            let outbound = counter_delta(
                previous.map(|p| (p.outbound_bytes, p.outbound_wrap_epoch)),
                current.outbound_bytes,
                current.outbound_wrap_epoch,
            )?;
            let cross = if current.local {
                0
            } else {
                inbound
                    .checked_add(outbound)
                    .ok_or(Error::Invalid("cross-location overflow"))?
            };
            let total_key = (
                current.keyspace.clone(),
                current.backend_id.clone(),
                current.public_endpoint,
            );
            let total = totals.entry(total_key.clone()).or_default();
            total.0 = total.0.saturating_add(inbound);
            total.1 = total.1.saturating_add(cross);
            let pending = pending.entry(total_key).or_default();
            pending.0 = pending
                .0
                .checked_add(inbound)
                .ok_or(Error::Invalid("response aggregate overflow"))?;
            pending.1 = pending
                .1
                .checked_add(cross)
                .ok_or(Error::Invalid("cross-location aggregate overflow"))?;
            if snapshot.final_sample {
                sources.remove(&key);
            } else {
                sources.insert(key, current.clone());
            }
        }
        Ok(State {
            version: 1,
            producer_id: batch.producer_id.clone(),
            last_applied: batch.sequence,
            process_generation: generation,
            sources: sources
                .into_iter()
                .map(|(key, baseline)| PersistedSource { key, baseline })
                .collect(),
            totals: total_vec(totals),
            pending: total_vec(pending),
        })
    }

    fn drain_pending(&mut self) -> Result<(), Error> {
        if self.state.pending.is_empty() {
            return Ok(());
        }
        let result = (|| {
            self.sink.apply(
                &self.state.producer_id,
                self.state.last_applied,
                &self.state.pending,
            )?;
            if !self.sink.healthy() {
                return Err(Error::Unhealthy);
            }
            let mut next = self.state.clone();
            next.pending.clear();
            self.file.persist(&next)?;
            self.state = next;
            Ok(())
        })();
        if result.is_err() {
            self.healthy = false;
        }
        result
    }

    fn validate_sink(&self) -> Result<(), Error> {
        let Some(sink) = self.sink.checkpoint() else {
            return Ok(());
        };
        if !valid_checkpoint(&sink.producer_id, sink.sequence) {
            return Err(Error::Invalid("sink checkpoint inconsistent"));
        }
        if self.state.producer_id.is_empty() {
            return if sink.sequence == 0 {
                Ok(())
            } else {
                Err(Error::Invalid("sink ahead of fresh consumer"))
            };
        }
        if !sink.producer_id.is_empty() && sink.producer_id != self.state.producer_id {
            return Err(Error::Invalid("sink producer mismatch"));
        }
        if self.state.pending.is_empty() {
            if sink.producer_id != self.state.producer_id
                || sink.sequence != self.state.last_applied
            {
                return Err(Error::Invalid("sink checkpoint mismatch"));
            }
        } else if sink.sequence != self.state.last_applied
            && Some(sink.sequence) != self.state.last_applied.checked_sub(1)
        {
            return Err(Error::Invalid("sink outside pending window"));
        }
        Ok(())
    }
}

fn counter_delta(previous: Option<(u64, u64)>, current: u64, epoch: u64) -> Result<u64, Error> {
    let invalid = || Error::Invalid("counter regressed or wrap jumped");
    let Some((value, previous_epoch)) = previous else {
        return if epoch == 0 {
            Ok(current)
        } else {
            Err(invalid())
        };
    };
    if epoch == previous_epoch {
        return current.checked_sub(value).ok_or_else(invalid);
    }
    if previous_epoch.checked_add(1) != Some(epoch) || value == 0 {
        return Err(invalid());
    }
    (u64::MAX - value + 1)
        .checked_add(current)
        .ok_or_else(invalid)
}

fn validate_source(
    key: SourceKey,
    baseline: &SourceBaseline,
    generation: u64,
) -> Result<(), Error> {
    if key.connection_id == 0
        || key.process_generation == 0
        || key.backend_generation == 0
        || key.process_generation > generation
        || baseline.backend_id.is_empty()
        || baseline.keyspace.is_empty()
        || baseline.backend_id.len() > 256
        || baseline.cluster_name.len() > 256
        || baseline.keyspace.len() > 256
    {
        return Err(Error::Invalid("unknown or over-bound source attribution"));
    }
    Ok(())
}

fn validate_state(state: &State) -> Result<(), Error> {
    if state.version != 1
        || !valid_checkpoint(&state.producer_id, state.last_applied)
        || state.producer_id.is_empty() != (state.process_generation == 0)
        || (state.producer_id.is_empty()
            && (!state.sources.is_empty() || !state.totals.is_empty() || !state.pending.is_empty()))
    {
        return Err(Error::Invalid("consumer state lineage"));
    }
    let mut seen = BTreeSet::new();
    for source in &state.sources {
        validate_source(source.key, &source.baseline, state.process_generation)?;
        if !seen.insert(source.key) {
            return Err(Error::Invalid("duplicate persisted source"));
        }
    }
    total_map(&state.totals)?;
    total_map(&state.pending)?;
    Ok(())
}

fn total_map(values: &[Delta]) -> Result<BTreeMap<TotalKey, (u64, u64)>, Error> {
    let mut output = BTreeMap::new();
    for value in values {
        if value.keyspace.is_empty()
            || value.backend_id.is_empty()
            || value.keyspace.len() > 256
            || value.backend_id.len() > 256
        {
            return Err(Error::Invalid("unknown total attribution"));
        }
        if output
            .insert(
                (
                    value.keyspace.clone(),
                    value.backend_id.clone(),
                    value.public_endpoint,
                ),
                (value.response_bytes, value.cross_location_bytes),
            )
            .is_some()
        {
            return Err(Error::Invalid("duplicate total attribution"));
        }
    }
    Ok(output)
}

fn total_vec(values: BTreeMap<TotalKey, (u64, u64)>) -> Vec<Delta> {
    values
        .into_iter()
        .map(
            |((keyspace, backend_id, public_endpoint), (response_bytes, cross_location_bytes))| {
                Delta {
                    keyspace,
                    backend_id,
                    public_endpoint,
                    response_bytes,
                    cross_location_bytes,
                }
            },
        )
        .collect()
}
