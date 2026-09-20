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

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed failures; none of these outcomes authorize a producer ACK.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid sequence, attribution, counter, or persisted state.
    #[error("invalid metering state: {0}")]
    Invalid(&'static str),
    /// The control owner has retired.
    #[error("metering owner retired")]
    Retired,
    /// Persistence or export previously failed and must recover before use.
    #[error("metering persistence or exporter is unhealthy")]
    Unhealthy,
    /// Durable file I/O failed.
    #[error("metering persistence: {0}")]
    Io(#[from] std::io::Error),
    /// Durable state was not valid JSON.
    #[error("metering state encoding: {0}")]
    Json(#[from] serde_json::Error),
}

/// Producer identity and monotonically increasing durable batch sequence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checkpoint {
    /// Stable 32-character lowercase hexadecimal producer identity.
    pub producer_id: String,
    /// Last accepted sequence, zero only for a fresh state.
    pub sequence: u64,
}

/// One physical backend incarnation owned by a SQL connection.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
pub struct SourceKey {
    /// Process-local SQL connection identifier.
    #[serde(rename = "ConnectionID")]
    pub connection_id: u64,
    /// Producer process generation.
    pub process_generation: u64,
    /// Backend incarnation, advanced on migration.
    pub backend_generation: u64,
}

/// Immutable attribution and the last accepted absolute counters for a source.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SourceBaseline {
    /// Backend address/identity.
    #[serde(rename = "BackendID")]
    pub backend_id: String,
    /// Configured backend cluster name; may be empty.
    pub cluster_name: String,
    /// Metering tenant/keyspace identity.
    pub keyspace: String,
    /// Whether backend traffic stays in the local location.
    pub local: bool,
    /// Whether the original TCP peer is a public endpoint.
    pub public_endpoint: bool,
    /// Absolute bytes received from the backend (response bytes).
    pub inbound_bytes: u64,
    /// Absolute bytes sent to the backend.
    pub outbound_bytes: u64,
    /// Number of wraps of the inbound counter.
    pub inbound_wrap_epoch: u64,
    /// Number of wraps of the outbound counter.
    pub outbound_wrap_epoch: u64,
}

/// Current absolute counters and optional final marker for one source.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    /// Source incarnation.
    pub key: SourceKey,
    /// Attribution and absolute counters.
    pub baseline: SourceBaseline,
    /// This source will publish no further samples.
    pub final_sample: bool,
}

/// A producer-qualified, ordered sample batch.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Batch {
    /// Stable producer identity.
    pub producer_id: String,
    /// Consecutive sequence starting at one.
    pub sequence: u64,
    /// At most 1,024 samples, all from the same process generation.
    pub snapshots: Vec<Snapshot>,
}

/// Source-attributed bytes derived from absolute samples.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Delta {
    /// Tenant/keyspace used by the Go sink as its cluster identifier.
    pub keyspace: String,
    /// Backend attribution.
    pub backend_id: String,
    /// Original TCP peer classification.
    pub public_endpoint: bool,
    /// Bytes received from the backend.
    pub response_bytes: u64,
    /// Sum of inbound/outbound bytes when the backend is remote.
    pub cross_location_bytes: u64,
}

/// Atomic deduplication checkpoint and durable aggregate ingestion seam.
pub trait DurableSink {
    /// Whether persistence and exporting currently permit acknowledgments.
    fn healthy(&self) -> bool;
    /// Last durably ingested batch.
    fn checkpoint(&self) -> Checkpoint;
    /// Persists a consecutive batch and its checkpoint in one atomic write.
    ///
    /// # Errors
    /// Returns an error for invalid attribution, overflow, gaps, or persistence failure.
    fn apply(&mut self, producer: &str, sequence: u64, deltas: &[Delta]) -> Result<(), Error>;
}

pub(crate) fn valid_producer(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_checkpoint(producer: &str, sequence: u64) -> bool {
    (producer.is_empty() && sequence == 0) || (valid_producer(producer) && sequence > 0)
}
