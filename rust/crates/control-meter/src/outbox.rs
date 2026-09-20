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

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;

use control_plane::ownership::OwnerToken;
use serde::{Deserialize, Serialize};

use crate::persistence::StateFile;
use crate::types::{valid_checkpoint, valid_producer};
use crate::{Checkpoint, Delta, DurableSink, Error};

/// A tenant aggregate in the Go-compatible outbox format.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExportRecord {
    /// Tenant/keyspace identifier (the historical field name is `cluster_id`).
    pub cluster_id: String,
    /// Bytes received from the backend for public endpoints.
    pub public_response_bytes: u64,
    /// Bytes received from the backend for private endpoints.
    pub private_response_bytes: u64,
    /// Bidirectional bytes crossing locations.
    pub cross_az_bytes: u64,
}

/// Immutable durable export window, reused unchanged until storage accepts it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExportWindow {
    /// Minute-level Unix timestamp.
    pub timestamp: i64,
    /// Sorted per-tenant aggregates.
    pub data: Vec<ExportRecord>,
}

#[derive(Clone, Deserialize, Serialize)]
struct State {
    version: u32,
    self_id: String,
    producer_id: String,
    last_batch_sequence: u64,
    data: Vec<ExportRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<ExportWindow>,
}

/// Durable aggregate and pending export owner, compatible with the Go outbox.
pub struct Outbox {
    file: StateFile,
    state: State,
    persistence_healthy: bool,
    writer_healthy: bool,
}

impl Outbox {
    /// Opens a Go-compatible outbox, retaining its stable export identity.
    ///
    /// # Errors
    /// Rejects corrupt state, retired ownership, or inaccessible persistence.
    pub fn open(path: impl Into<PathBuf>, owner: OwnerToken) -> Result<Self, Error> {
        let file = StateFile::new(path.into(), owner)?;
        let state = if let Some(state) = file.load::<State>()? {
            validate_state(&state)?;
            state
        } else {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| Error::Invalid("export identity entropy unavailable"))?;
            // Go uses a UUID with underscores so the SDK's filename delimiter
            // remains unambiguous. Preserve the same shape for fresh Rust state.
            random[6] = (random[6] & 0x0f) | 0x40;
            random[8] = (random[8] & 0x3f) | 0x80;
            let mut self_id = String::with_capacity(36);
            for (index, byte) in random.iter().enumerate() {
                if [4, 6, 8, 10].contains(&index) {
                    self_id.push('_');
                }
                let _ = write!(self_id, "{byte:02x}");
            }
            let state = State {
                version: 1,
                self_id,
                producer_id: String::new(),
                last_batch_sequence: 0,
                data: Vec::new(),
                pending: None,
            };
            file.persist(&state)?;
            state
        };
        Ok(Self {
            file,
            state,
            persistence_healthy: true,
            writer_healthy: true,
        })
    }

    /// Stable identity used in object keys, retained through restarts.
    #[must_use]
    pub fn self_id(&self) -> &str {
        &self.state.self_id
    }

    /// Active traffic, distinct from the immutable pending export window.
    #[must_use]
    pub fn active(&self) -> &[ExportRecord] {
        &self.state.data
    }

    /// Existing sealed window, if any.
    #[must_use]
    pub const fn pending(&self) -> Option<&ExportWindow> {
        self.state.pending.as_ref()
    }

    /// Seals active traffic, or returns the unchanged previous window for retry.
    ///
    /// # Errors
    /// Rejects invalid timestamps or persistence/owner failures.
    pub fn seal(&mut self, timestamp: i64) -> Result<Option<ExportWindow>, Error> {
        self.file.check_owner()?;
        if !self.persistence_healthy {
            return Err(Error::Unhealthy);
        }
        if let Some(window) = &self.state.pending {
            return Ok(Some(window.clone()));
        }
        if self.state.data.is_empty() {
            return Ok(None);
        }
        if timestamp <= 0 || timestamp % 60 != 0 {
            return Err(Error::Invalid("export timestamp must be a positive minute"));
        }
        let mut next = self.state.clone();
        next.pending = Some(ExportWindow {
            timestamp,
            data: std::mem::take(&mut next.data),
        });
        self.commit(next)?;
        Ok(self.state.pending.clone())
    }

    /// Records a failed object-store attempt without modifying the sealed window.
    pub fn export_failed(&mut self) {
        self.writer_healthy = false;
    }

    /// Clears exactly the successfully exported window, after durable storage ACK.
    ///
    /// # Errors
    /// A stale/different window or persistence failure must not clear pending data.
    pub fn exported(&mut self, window: &ExportWindow) -> Result<(), Error> {
        self.file.check_owner()?;
        if !self.persistence_healthy {
            return Err(Error::Unhealthy);
        }
        if self.state.pending.as_ref() != Some(window) {
            return Err(Error::Invalid("export window mismatch"));
        }
        let mut next = self.state.clone();
        next.pending = None;
        self.commit(next)?;
        self.writer_healthy = true;
        Ok(())
    }

    fn commit(&mut self, next: State) -> Result<(), Error> {
        if let Err(error) = self.file.persist(&next) {
            self.persistence_healthy = false;
            return Err(error);
        }
        self.state = next;
        Ok(())
    }
}

impl DurableSink for Outbox {
    fn healthy(&self) -> bool {
        self.persistence_healthy && self.writer_healthy && self.file.check_owner().is_ok()
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            producer_id: self.state.producer_id.clone(),
            sequence: self.state.last_batch_sequence,
        }
    }

    fn apply(&mut self, producer: &str, sequence: u64, deltas: &[Delta]) -> Result<(), Error> {
        self.file.check_owner()?;
        if !self.persistence_healthy {
            return Err(Error::Unhealthy);
        }
        if !valid_producer(producer) || sequence == 0 {
            return Err(Error::Invalid("producer or sequence"));
        }
        if !self.state.producer_id.is_empty() && self.state.producer_id != producer {
            return Err(Error::Invalid("outbox producer mismatch"));
        }
        if self.state.producer_id == producer && sequence <= self.state.last_batch_sequence {
            return Ok(());
        }
        if self.state.last_batch_sequence.checked_add(1) != Some(sequence) {
            return Err(Error::Invalid("outbox sequence gap"));
        }
        let mut data = record_map(&self.state.data)?;
        for delta in deltas {
            if delta.keyspace.is_empty() || delta.backend_id.is_empty() {
                return Err(Error::Invalid("unknown delta attribution"));
            }
            let record = data
                .entry(delta.keyspace.clone())
                .or_insert_with(|| ExportRecord {
                    cluster_id: delta.keyspace.clone(),
                    public_response_bytes: 0,
                    private_response_bytes: 0,
                    cross_az_bytes: 0,
                });
            record.cross_az_bytes = record
                .cross_az_bytes
                .checked_add(delta.cross_location_bytes)
                .ok_or(Error::Invalid("cross-AZ aggregate overflow"))?;
            let response = if delta.public_endpoint {
                &mut record.public_response_bytes
            } else {
                &mut record.private_response_bytes
            };
            *response = response
                .checked_add(delta.response_bytes)
                .ok_or(Error::Invalid("response aggregate overflow"))?;
        }
        let mut next = self.state.clone();
        producer.clone_into(&mut next.producer_id);
        next.last_batch_sequence = sequence;
        next.data = data.into_values().collect();
        self.commit(next)
    }
}

fn record_map(records: &[ExportRecord]) -> Result<BTreeMap<String, ExportRecord>, Error> {
    let mut data = BTreeMap::new();
    for record in records {
        if record.cluster_id.is_empty()
            || data
                .insert(record.cluster_id.clone(), record.clone())
                .is_some()
        {
            return Err(Error::Invalid("empty or duplicate outbox cluster"));
        }
    }
    Ok(data)
}

fn validate_state(state: &State) -> Result<(), Error> {
    if state.version != 1
        || state.self_id.is_empty()
        || !valid_checkpoint(&state.producer_id, state.last_batch_sequence)
    {
        return Err(Error::Invalid("outbox state lineage"));
    }
    record_map(&state.data)?;
    if let Some(window) = &state.pending {
        if window.timestamp <= 0 || window.data.is_empty() {
            return Err(Error::Invalid("pending export window"));
        }
        record_map(&window.data)?;
    }
    Ok(())
}
