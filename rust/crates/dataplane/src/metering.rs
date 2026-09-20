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

//! Crash-safe producer identity and sealed-batch WAL for DPL-06 metering.
//!
//! The file is a versioned, checksummed protobuf payload written through a
//! sibling temporary file, `fsync`, atomic rename, then parent-directory
//! `fsync`. It contains no SQL payload or credentials: only the stable
//! producer id, process generation, next sequence, and sealed unacknowledged
//! metering batches. A corrupt, unsafe-permission, or unwritable WAL is a
//! fail-closed startup/runtime error.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use control_proto::v1::{MeteringBatch, MeteringSourceSnapshot};
use prost::Message;
use proxy_io::counted::ByteCounters;
use tokio::sync::watch;

use crate::control_commands::{
    MAX_DELTAS_PER_BATCH, MAX_METERING_KEY_BYTES, MAX_UNACKED_METERING_BATCHES, MeteringError,
};
use crate::control_dispatch::{ControlDispatchHandle, MeteringSnapshotRecordError};

const WAL_MAGIC: &[u8; 8] = b"TPMWAL01";
const WAL_VERSION: u32 = 1;
const HEADER_BYTES: usize = 24;

#[derive(Clone, PartialEq, Message)]
struct WalPayload {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(string, tag = "2")]
    producer_id: String,
    #[prost(uint64, tag = "3")]
    process_generation: u64,
    #[prost(uint64, tag = "4")]
    next_sequence: u64,
    #[prost(message, repeated, tag = "5")]
    unacked: Vec<MeteringBatch>,
}

/// Validated producer state loaded from the WAL.
#[derive(Debug, Clone)]
pub struct LoadedMeteringWal {
    /// Stable UUID-like 128-bit producer identity (lowercase hex).
    pub producer_id: String,
    /// Generation incremented and persisted once per Rust process start.
    pub process_generation: u64,
    /// Next batch sequence; always nonzero.
    pub next_sequence: u64,
    /// Sealed batches retained verbatim until an explicit durable ACK.
    pub unacked: Vec<MeteringBatch>,
}

/// A bound WAL path. Mutation is synchronous by design and happens only on
/// the control-dispatch/sampler path, never on the SQL packet hot path.
#[derive(Debug)]
pub struct MeteringWal {
    path: PathBuf,
}

/// Fail-closed WAL error.
#[derive(Debug, thiserror::Error)]
pub enum MeteringWalError {
    /// File or directory I/O failed.
    #[error("metering WAL I/O at {path}: {source}")]
    Io {
        /// WAL path involved.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Existing content or metadata violates the WAL contract.
    #[error("metering WAL is corrupt or unsafe at {path}: {detail}")]
    Corrupt {
        /// WAL path involved.
        path: PathBuf,
        /// Static diagnostic safe for logs.
        detail: &'static str,
    },
    /// The process-generation counter is exhausted.
    #[error("metering WAL process generation is exhausted at {path}")]
    ProcessGenerationExhausted {
        /// WAL path involved.
        path: PathBuf,
    },
}

impl MeteringWal {
    /// Opens or creates a WAL, increments its process generation, and persists
    /// that increment before returning. Existing state is validated strictly;
    /// there is no "start fresh" fallback.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for corruption, unsafe permissions,
    /// entropy failure, generation exhaustion, or any durable-write failure.
    pub fn open(path: impl Into<PathBuf>) -> Result<(Self, LoadedMeteringWal), MeteringWalError> {
        let path = path.into();
        let wal = Self { path };
        let existing = wal.path.exists();
        let mut payload = if existing {
            wal.read_payload()?
        } else {
            WalPayload {
                version: WAL_VERSION,
                producer_id: new_producer_id(&wal.path)?,
                process_generation: 0,
                next_sequence: 1,
                unacked: Vec::new(),
            }
        };
        validate_payload(&wal.path, &payload)?;
        if existing && payload.process_generation == 0 {
            return Err(wal.corrupt("existing process generation is zero"));
        }
        payload.process_generation =
            payload.process_generation.checked_add(1).ok_or_else(|| {
                MeteringWalError::ProcessGenerationExhausted {
                    path: wal.path.clone(),
                }
            })?;
        wal.write_payload(&payload)?;
        Ok((
            wal,
            LoadedMeteringWal {
                producer_id: payload.producer_id,
                process_generation: payload.process_generation,
                next_sequence: payload.next_sequence,
                unacked: payload.unacked,
            },
        ))
    }

    /// Atomically replaces the durable sequence/unacked state.
    ///
    /// # Errors
    ///
    /// Returns on any encode or filesystem durability failure.
    pub fn persist(
        &self,
        producer_id: &str,
        process_generation: u64,
        next_sequence: u64,
        unacked: &[MeteringBatch],
    ) -> Result<(), MeteringWalError> {
        let payload = WalPayload {
            version: WAL_VERSION,
            producer_id: producer_id.to_owned(),
            process_generation,
            next_sequence,
            unacked: unacked.to_vec(),
        };
        validate_payload(&self.path, &payload)?;
        self.write_payload(&payload)
    }

    fn read_payload(&self) -> Result<WalPayload, MeteringWalError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|source| self.io(source))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(self.corrupt("path is not a regular file"));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(self.corrupt("permissions must be 0600 or stricter"));
        }
        let mut bytes = Vec::new();
        File::open(&self.path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|source| self.io(source))?;
        if bytes.len() < HEADER_BYTES || &bytes[..8] != WAL_MAGIC {
            return Err(self.corrupt("bad header"));
        }
        let length = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| self.corrupt("bad length"))?,
        );
        let checksum = u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| self.corrupt("bad checksum"))?,
        );
        let payload = &bytes[HEADER_BYTES..];
        if usize::try_from(length).ok() != Some(payload.len()) || checksum64(payload) != checksum {
            return Err(self.corrupt("length or checksum mismatch"));
        }
        WalPayload::decode(payload).map_err(|_| self.corrupt("protobuf decode failed"))
    }

    fn write_payload(&self, payload: &WalPayload) -> Result<(), MeteringWalError> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| self.io(source))?;
        let encoded = payload.encode_to_vec();
        let length = u64::try_from(encoded.len()).map_err(|_| self.corrupt("payload too large"))?;
        let temporary = temporary_path(&self.path);
        let write_result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(WAL_MAGIC)?;
            file.write_all(&length.to_le_bytes())?;
            file.write_all(&checksum64(&encoded).to_le_bytes())?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if let Err(source) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(self.io(source));
        }
        Ok(())
    }

    fn io(&self, source: std::io::Error) -> MeteringWalError {
        MeteringWalError::Io {
            path: self.path.clone(),
            source,
        }
    }

    fn corrupt(&self, detail: &'static str) -> MeteringWalError {
        MeteringWalError::Corrupt {
            path: self.path.clone(),
            detail,
        }
    }
}

fn validate_payload(path: &Path, payload: &WalPayload) -> Result<(), MeteringWalError> {
    let corrupt = |detail| MeteringWalError::Corrupt {
        path: path.to_path_buf(),
        detail,
    };
    if payload.version != WAL_VERSION {
        return Err(corrupt("unsupported version"));
    }
    if payload.producer_id.len() != 32
        || !payload
            .producer_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(corrupt("invalid producer id"));
    }
    if payload.next_sequence == 0 {
        return Err(corrupt("next sequence is zero"));
    }
    if payload.unacked.len() > MAX_UNACKED_METERING_BATCHES {
        return Err(corrupt("unacked batch bound exceeded"));
    }
    let first = payload
        .next_sequence
        .checked_sub(u64::try_from(payload.unacked.len()).map_err(|_| corrupt("too many batches"))?)
        .ok_or_else(|| corrupt("unacked sequence range underflows"))?;
    for (index, batch) in payload.unacked.iter().enumerate() {
        let expected = first
            .checked_add(u64::try_from(index).map_err(|_| corrupt("too many batches"))?)
            .ok_or_else(|| corrupt("unacked sequence range overflows"))?;
        if batch.sequence != expected || batch.producer_id != payload.producer_id {
            return Err(corrupt("unacked producer or sequence mismatch"));
        }
        if !batch.deltas.is_empty()
            || batch.snapshots.is_empty()
            || batch.snapshots.len() > MAX_DELTAS_PER_BATCH
        {
            return Err(corrupt("unacked absolute batch shape is invalid"));
        }
        let mut sources = BTreeSet::new();
        for snapshot in &batch.snapshots {
            if snapshot.connection_id == 0
                || snapshot.process_generation == 0
                || snapshot.process_generation > payload.process_generation
                || snapshot.backend_generation == 0
                || snapshot.backend_id.is_empty()
                || snapshot.keyspace.is_empty()
                || snapshot.backend_id.len() > MAX_METERING_KEY_BYTES
                || snapshot.cluster_name.len() > MAX_METERING_KEY_BYTES
                || snapshot.keyspace.len() > MAX_METERING_KEY_BYTES
                || !sources.insert((
                    snapshot.connection_id,
                    snapshot.process_generation,
                    snapshot.backend_generation,
                ))
            {
                return Err(corrupt("unacked source identity is invalid"));
            }
        }
    }
    Ok(())
}

fn new_producer_id(path: &Path) -> Result<String, MeteringWalError> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| MeteringWalError::Corrupt {
        path: path.to_path_buf(),
        detail: "producer entropy unavailable",
    })?;
    let mut result = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").map_err(|_| MeteringWalError::Corrupt {
            path: path.to_path_buf(),
            detail: "producer id formatting failed",
        })?;
    }
    Ok(result)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(value)
}

fn checksum64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Immutable identity assigned only after a backend is successfully attached.
#[derive(Debug, Clone)]
pub struct MeteringAttribution {
    /// Connection id allocated by admission.
    pub connection_id: u64,
    /// Successful backend generation (initial is 1; redirect increments).
    pub backend_generation: u64,
    /// Stable router backend id.
    pub backend_id: String,
    /// Router cluster label. Empty is a legal legacy/unscoped value.
    pub cluster_name: String,
    /// Router keyspace label.
    pub keyspace: String,
    /// Whether the backend is in the proxy's local zone.
    pub local: bool,
    /// Classification of the direct upstream/LB peer at accept time.
    pub public_endpoint: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SourceKey {
    connection_id: u64,
    backend_generation: u64,
}

struct SourceState {
    attribution: MeteringAttribution,
    counters: Arc<ByteCounters>,
    previous_inbound: u64,
    previous_outbound: u64,
    inbound_wrap_epoch: u64,
    outbound_wrap_epoch: u64,
    final_values: Option<(u64, u64)>,
}

/// Process-wide source registry. SQL tasks only register/finalize sources and
/// load two atomics at a successful swap boundary; periodic sampling and all
/// WAL/control I/O stay in a background task.
#[derive(Clone)]
pub struct MeteringSourceRegistry {
    process_generation: u64,
    sources: Arc<Mutex<BTreeMap<SourceKey, SourceState>>>,
    retired_totals: Arc<Mutex<BTreeMap<u64, (u64, u64)>>>,
    closed_connections: Arc<Mutex<BTreeSet<u64>>>,
    failed: Arc<AtomicBool>,
}

/// Registry/sampler failure. Every variant is fail closed.
#[derive(Debug, thiserror::Error)]
pub enum MeteringSamplerError {
    /// Registry ownership was poisoned.
    #[error("metering source registry is poisoned")]
    RegistryPoisoned,
    /// A source identity was missing, duplicated, or finalized twice.
    #[error("metering source identity invariant failed")]
    SourceInvariant,
    /// A router assignment lacked a billable backend/keyspace identity.
    #[error("metering source attribution is unknown")]
    UnknownAttribution,
    /// The process or backend generation cannot advance safely.
    #[error("metering source generation is exhausted")]
    GenerationExhausted,
    /// The durable ledger rejected the snapshot handoff.
    #[error("metering durable dispatch rejected snapshots: {0:?}")]
    DispatchRejected(MeteringError),
    /// The durable dispatch owner disappeared before accepting the handoff.
    #[error("metering durable dispatch owner unavailable")]
    DispatchUnavailable,
    /// The process-local durable consumer rejected a batch; WAL remains replayable.
    #[error("native metering consumer rejected snapshots: {0}")]
    NativeConsumer(#[from] control_meter::Error),
}

struct PreparedSample {
    snapshots: Vec<MeteringSourceSnapshot>,
    finals: Vec<SourceKey>,
}

impl MeteringSourceRegistry {
    /// Creates a registry for the WAL-persisted nonzero process generation.
    ///
    /// # Errors
    ///
    /// Rejects zero, which cannot disambiguate a process restart.
    pub fn new(process_generation: u64) -> Result<Self, MeteringSamplerError> {
        if process_generation == 0 {
            return Err(MeteringSamplerError::SourceInvariant);
        }
        Ok(Self {
            process_generation,
            sources: Arc::new(Mutex::new(BTreeMap::new())),
            retired_totals: Arc::new(Mutex::new(BTreeMap::new())),
            closed_connections: Arc::new(Mutex::new(BTreeSet::new())),
            failed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Marks an invariant/durability dependency failure observed on a SQL
    /// task. The sampler converts it into process-wide fail-closed shutdown on
    /// its next bounded tick instead of allowing unrelated sessions to keep
    /// serving unmetered.
    pub fn fail_closed(&self) {
        self.failed.store(true, Ordering::Release);
    }

    /// Returns the number of source generations still owned by the sampler.
    /// This is a diagnostic/testing surface; final sources remain counted
    /// until their snapshot has transferred durably to the WAL.
    ///
    /// # Errors
    ///
    /// Returns when registry ownership was poisoned.
    pub fn active_source_count(&self) -> Result<usize, MeteringSamplerError> {
        self.sources
            .lock()
            .map(|sources| sources.len())
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)
    }

    /// Registers a successfully attached backend source backed by the exact
    /// raw counters used from dial through handshake/auth/restore.
    ///
    /// # Errors
    ///
    /// Rejects unknown attribution or a duplicate source key.
    pub fn register(
        &self,
        attribution: MeteringAttribution,
        counters: Arc<ByteCounters>,
    ) -> Result<(), MeteringSamplerError> {
        if attribution.connection_id == 0
            || attribution.backend_generation == 0
            || attribution.backend_id.is_empty()
            || attribution.keyspace.is_empty()
        {
            return Err(MeteringSamplerError::UnknownAttribution);
        }
        let key = SourceKey {
            connection_id: attribution.connection_id,
            backend_generation: attribution.backend_generation,
        };
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        if sources.contains_key(&key) {
            return Err(MeteringSamplerError::SourceInvariant);
        }
        sources.insert(
            key,
            SourceState {
                attribution,
                counters,
                previous_inbound: 0,
                previous_outbound: 0,
                inbound_wrap_epoch: 0,
                outbound_wrap_epoch: 0,
                final_values: None,
            },
        );
        Ok(())
    }

    /// Marks a source final with the exact two raw values already loaded at
    /// the swap/close boundary. The same values can therefore feed CLOSED
    /// aggregation without a second atomic load.
    ///
    /// # Errors
    ///
    /// Rejects an unknown or already-final source.
    pub fn finalize(
        &self,
        connection_id: u64,
        backend_generation: u64,
        inbound: u64,
        outbound: u64,
    ) -> Result<(), MeteringSamplerError> {
        let key = SourceKey {
            connection_id,
            backend_generation,
        };
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        let source = sources
            .get_mut(&key)
            .ok_or(MeteringSamplerError::SourceInvariant)?;
        if source.final_values.replace((inbound, outbound)).is_some() {
            return Err(MeteringSamplerError::SourceInvariant);
        }
        Ok(())
    }

    /// Finalizes every still-live source for an externally aborted engine and
    /// returns aggregate backend totals, including already sampled redirect
    /// legs. Each live source counter is loaded exactly once here.
    ///
    /// # Errors
    ///
    /// Returns on poisoned state, missing source, or aggregate overflow.
    pub fn finalize_connection(
        &self,
        connection_id: u64,
    ) -> Result<Option<(u64, u64)>, MeteringSamplerError> {
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        let retired = self
            .retired_totals
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        let mut totals = retired.get(&connection_id).copied().unwrap_or_default();
        let mut found = retired.contains_key(&connection_id);
        for source in sources
            .iter_mut()
            .filter(|(key, _)| key.connection_id == connection_id)
            .map(|(_, source)| source)
        {
            found = true;
            let values = source
                .final_values
                .unwrap_or_else(|| (source.counters.inbound(), source.counters.outbound()));
            source.final_values = Some(values);
            totals.0 = totals
                .0
                .checked_add(values.0)
                .ok_or(MeteringSamplerError::GenerationExhausted)?;
            totals.1 = totals
                .1
                .checked_add(values.1)
                .ok_or(MeteringSamplerError::GenerationExhausted)?;
        }
        Ok(found.then_some(totals))
    }

    /// Releases CLOSED-only fallback totals after the owner has emitted the
    /// terminal lifecycle record. Source snapshots remain independently owned
    /// by the sampler until their durable handoff commits.
    pub fn forget_connection(&self, connection_id: u64) {
        let Ok(sources) = self.sources.lock() else {
            self.fail_closed();
            return;
        };
        let Ok(mut retired) = self.retired_totals.lock() else {
            self.fail_closed();
            return;
        };
        let still_sampling = sources.keys().any(|key| key.connection_id == connection_id);
        retired.remove(&connection_id);
        let Ok(mut closed) = self.closed_connections.lock() else {
            self.fail_closed();
            return;
        };
        if still_sampling {
            closed.insert(connection_id);
        } else {
            closed.remove(&connection_id);
        }
    }

    fn prepare(&self) -> Result<PreparedSample, MeteringSamplerError> {
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        let mut snapshots = Vec::with_capacity(sources.len());
        let mut finals = Vec::new();
        for (key, source) in sources.iter_mut() {
            let (inbound, outbound) = source
                .final_values
                .unwrap_or_else(|| (source.counters.inbound(), source.counters.outbound()));
            if inbound < source.previous_inbound {
                source.inbound_wrap_epoch = source
                    .inbound_wrap_epoch
                    .checked_add(1)
                    .ok_or(MeteringSamplerError::GenerationExhausted)?;
            }
            if outbound < source.previous_outbound {
                source.outbound_wrap_epoch = source
                    .outbound_wrap_epoch
                    .checked_add(1)
                    .ok_or(MeteringSamplerError::GenerationExhausted)?;
            }
            source.previous_inbound = inbound;
            source.previous_outbound = outbound;
            let attribution = &source.attribution;
            let is_final = source.final_values.is_some();
            snapshots.push(MeteringSourceSnapshot {
                connection_id: attribution.connection_id,
                process_generation: self.process_generation,
                backend_generation: attribution.backend_generation,
                backend_id: attribution.backend_id.clone(),
                cluster_name: attribution.cluster_name.clone(),
                keyspace: attribution.keyspace.clone(),
                local: attribution.local,
                public_endpoint: attribution.public_endpoint,
                backend_inbound_bytes: inbound,
                backend_outbound_bytes: outbound,
                inbound_wrap_epoch: source.inbound_wrap_epoch,
                outbound_wrap_epoch: source.outbound_wrap_epoch,
                r#final: is_final,
            });
            if is_final {
                finals.push(*key);
            }
        }
        Ok(PreparedSample { snapshots, finals })
    }

    fn commit(&self, sample: &PreparedSample) -> Result<(), MeteringSamplerError> {
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        let mut retired = self
            .retired_totals
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        let mut closed = self
            .closed_connections
            .lock()
            .map_err(|_| MeteringSamplerError::RegistryPoisoned)?;
        for key in &sample.finals {
            let removed = sources
                .remove(key)
                .ok_or(MeteringSamplerError::SourceInvariant)?;
            let values = removed
                .final_values
                .ok_or(MeteringSamplerError::SourceInvariant)?;
            if !closed.contains(&key.connection_id) {
                let totals = retired.entry(key.connection_id).or_default();
                totals.0 = totals
                    .0
                    .checked_add(values.0)
                    .ok_or(MeteringSamplerError::GenerationExhausted)?;
                totals.1 = totals
                    .1
                    .checked_add(values.1)
                    .ok_or(MeteringSamplerError::GenerationExhausted)?;
            }
        }
        for connection_id in sample.finals.iter().map(|key| key.connection_id) {
            if !sources.keys().any(|key| key.connection_id == connection_id)
                && closed.remove(&connection_id)
            {
                retired.remove(&connection_id);
            }
        }
        Ok(())
    }
}

/// Classifies the direct accepted TCP peer against the frozen public CIDRs.
/// The PROXY-v2 inner client is deliberately excluded: Go's `ProxyAddr()`
/// semantics classify the upstream/LB hop visible to the listener.
#[must_use]
pub fn is_public_endpoint(ip: std::net::IpAddr, cidrs: &[String]) -> bool {
    cidrs.iter().any(|cidr| cidr_contains(ip, cidr))
}

fn cidr_contains(ip: std::net::IpAddr, cidr: &str) -> bool {
    let (address, prefix) = cidr
        .split_once('/')
        .map_or((cidr, None), |(address, prefix)| {
            (address, prefix.parse::<u8>().ok())
        });
    let Ok(network) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, network) {
        (std::net::IpAddr::V4(value), std::net::IpAddr::V4(network)) => {
            let bits = prefix.unwrap_or(32);
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(value) & mask == u32::from(network) & mask
        }
        (std::net::IpAddr::V6(value), std::net::IpAddr::V6(network)) => {
            let bits = prefix.unwrap_or(128);
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(value) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

/// Samples all live/final sources at the fixed cadence and transfers each
/// sample to the WAL-backed dispatch owner. On shutdown it performs one final
/// sample after the composition has joined every session, so the batch carries
/// their exact final counters/markers. Any rejected durable handoff terminates
/// fail closed.
///
/// # Errors
///
/// Returns on registry invariant or durable-dispatch failure.
pub async fn run_metering_sampler(
    registry: MeteringSourceRegistry,
    dispatch: ControlDispatchHandle,
    mut shutdown: watch::Receiver<bool>,
    cadence: Duration,
) -> Result<(), MeteringSamplerError> {
    let mut interval = tokio::time::interval(cadence);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let stopping = tokio::select! {
            _ = interval.tick() => false,
            changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        };
        if registry.failed.load(Ordering::Acquire) {
            return Err(MeteringSamplerError::SourceInvariant);
        }
        let sample = registry.prepare()?;
        for snapshots in sample.snapshots.chunks(MAX_DELTAS_PER_BATCH) {
            let snapshots = snapshots.to_vec();
            let finals = snapshots
                .iter()
                .filter(|snapshot| snapshot.r#final)
                .map(|snapshot| SourceKey {
                    connection_id: snapshot.connection_id,
                    backend_generation: snapshot.backend_generation,
                })
                .collect();
            dispatch
                .record_metering_snapshots(snapshots)
                .await
                .map_err(|error| match error {
                    MeteringSnapshotRecordError::Rejected { error, .. } => {
                        MeteringSamplerError::DispatchRejected(error)
                    }
                    MeteringSnapshotRecordError::DispatchUnavailable { .. } => {
                        MeteringSamplerError::DispatchUnavailable
                    }
                })?;
            // Commit each chunk independently after its own durable handoff.
            // A later chunk may fail without replaying an already-final source
            // as a new sequence, and active-source absolute baselines still
            // converge on the next successful sample.
            registry.commit(&PreparedSample {
                snapshots: Vec::new(),
                finals,
            })?;
        }
        if stopping {
            return Ok(());
        }
    }
}

/// Samples directly into the native consumer, without a Go control session.
///
/// The supplied ledger is exclusively owned by this sampler. Replay completes
/// before new samples; every trim follows a successful producer-qualified apply.
/// Disk work runs on the blocking pool. Stop/join sessions, then this sampler,
/// then the meter export worker, and only then retire the process owner.
/// The WAL keeps its existing codec for Go-to-native migration and rollback;
/// protocol types are translated here and never enter the control-meter crate.
///
/// # Errors
/// Returns on source, WAL, native-consumer or blocking-task failure. Failed batches
/// stay in the durable WAL; neither an unavailable consumer nor a failed ACK resets it.
pub async fn run_native_metering_sampler<S: control_meter::Intake + 'static>(
    registry: MeteringSourceRegistry,
    mut ledger: crate::control_commands::MeteringLedger,
    meter: Arc<S>,
    mut shutdown: watch::Receiver<bool>,
    cadence: Duration,
) -> Result<(), MeteringSamplerError> {
    if cadence.is_zero() || registry.process_generation != ledger.process_generation() {
        return Err(MeteringSamplerError::SourceInvariant);
    }
    let mut interval = tokio::time::interval(cadence);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let stopping = if *shutdown.borrow() || shutdown.has_changed().is_err() {
            true
        } else {
            tokio::select! {
                _ = interval.tick() => false,
                changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
            }
        };
        let sources = registry.clone();
        let sink = Arc::clone(&meter);
        let (returned, result) = tokio::task::spawn_blocking(move || {
            let result = native_sample(&sources, &mut ledger, sink.as_ref());
            (ledger, result)
        })
        .await
        .map_err(|_| MeteringSamplerError::DispatchUnavailable)?;
        ledger = returned;
        result?;
        if stopping {
            return Ok(());
        }
    }
}

fn native_sample<S: control_meter::Intake>(
    registry: &MeteringSourceRegistry,
    ledger: &mut crate::control_commands::MeteringLedger,
    meter: &S,
) -> Result<(), MeteringSamplerError> {
    if registry.failed.load(Ordering::Acquire) {
        return Err(MeteringSamplerError::SourceInvariant);
    }
    for batch in ledger.replay() {
        native_deliver(ledger, meter, batch)?;
    }
    let sample = registry.prepare()?;
    for snapshots in sample.snapshots.chunks(MAX_DELTAS_PER_BATCH) {
        let finals = snapshots
            .iter()
            .filter(|source| source.r#final)
            .map(|source| SourceKey {
                connection_id: source.connection_id,
                backend_generation: source.backend_generation,
            })
            .collect();
        let batch = ledger
            .record_snapshots(snapshots.to_vec())
            .map_err(MeteringSamplerError::DispatchRejected)?
            .ok_or(MeteringSamplerError::SourceInvariant)?;
        // As on the bridge path, source retirement follows WAL ownership. If
        // consumer ingestion fails, replay that exact sequence rather than
        // publishing the same final source as a new, double-counted batch.
        registry.commit(&PreparedSample {
            snapshots: Vec::new(),
            finals,
        })?;
        native_deliver(ledger, meter, batch)?;
    }
    Ok(())
}

fn native_deliver<S: control_meter::Intake>(
    ledger: &mut crate::control_commands::MeteringLedger,
    meter: &S,
    batch: MeteringBatch,
) -> Result<(), MeteringSamplerError> {
    let native = control_meter::Batch {
        producer_id: batch.producer_id,
        sequence: batch.sequence,
        snapshots: batch
            .snapshots
            .into_iter()
            .map(|source| control_meter::Snapshot {
                key: control_meter::SourceKey {
                    connection_id: source.connection_id,
                    process_generation: source.process_generation,
                    backend_generation: source.backend_generation,
                },
                baseline: control_meter::SourceBaseline {
                    backend_id: source.backend_id,
                    cluster_name: source.cluster_name,
                    keyspace: source.keyspace,
                    local: source.local,
                    public_endpoint: source.public_endpoint,
                    inbound_bytes: source.backend_inbound_bytes,
                    outbound_bytes: source.backend_outbound_bytes,
                    inbound_wrap_epoch: source.inbound_wrap_epoch,
                    outbound_wrap_epoch: source.outbound_wrap_epoch,
                },
                final_sample: source.r#final,
            })
            .collect(),
    };
    meter.apply(&native)?;
    if !ledger
        .acknowledge(&native.producer_id, native.sequence)
        .map_err(MeteringSamplerError::DispatchRejected)?
    {
        return Err(MeteringSamplerError::SourceInvariant);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use control_proto::v1::{MeteringBatch, MeteringSourceSnapshot};
    use proxy_io::counted::ByteCounters;

    use super::{
        MeteringAttribution, MeteringSamplerError, MeteringSourceRegistry, MeteringWal,
        is_public_endpoint,
    };
    use crate::control_commands::{MeteringError, MeteringLedger};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_directory() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "tiproxy-metering-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).expect("create test directory");
        directory
    }

    struct NativeFixture {
        dir: PathBuf,
        owners: control_plane::ownership::OwnershipRegistry,
        lease: Option<control_plane::ownership::OwnerLease>,
    }

    impl NativeFixture {
        fn new() -> Self {
            let owners = control_plane::ownership::OwnershipRegistry::new();
            let lease = owners
                .claim(
                    control_plane::ownership::OwnerScope::Process,
                    "native-meter",
                )
                .expect("owner");
            Self {
                dir: test_directory(),
                owners,
                lease: Some(lease),
            }
        }
        fn meter(&self) -> Arc<control_meter::runtime::Meter<control_meter::LocalStore>> {
            let owner = self.lease.as_ref().expect("lease").token();
            let outbox = control_meter::Outbox::open(self.dir.join("outbox.json"), owner.clone())
                .expect("outbox");
            let consumer =
                control_meter::Consumer::open(self.dir.join("consumer.json"), owner, outbox)
                    .expect("consumer");
            let store = control_meter::LocalStore::new(&self.dir.join("objects"), "", true, "0755")
                .expect("local store");
            control_meter::runtime::Meter::new(consumer, store, String::new())
        }
        fn outbox(&self) -> control_meter::Outbox {
            control_meter::Outbox::open(
                self.dir.join("outbox.json"),
                self.lease.as_ref().expect("lease").token(),
            )
            .expect("outbox")
        }
    }
    impl Drop for NativeFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn native_final_source(registry: &MeteringSourceRegistry) {
        registry
            .register(
                MeteringAttribution {
                    connection_id: 1,
                    backend_generation: 1,
                    backend_id: "backend-a".into(),
                    cluster_name: "cluster".into(),
                    keyspace: "ks".into(),
                    local: false,
                    public_endpoint: true,
                },
                Arc::new(ByteCounters::default()),
            )
            .expect("register");
        registry.finalize(1, 1, 10, 20).expect("finalize");
    }

    #[tokio::test]
    async fn native_sampler_delivers_final_batch_without_control_bridge() {
        let f = NativeFixture::new();
        let path = f.dir.join("producer.wal");
        let ledger = MeteringLedger::open_persistent(path.clone()).expect("ledger");
        let registry = MeteringSourceRegistry::new(ledger.process_generation()).expect("registry");
        native_final_source(&registry);
        let (_, shutdown) = tokio::sync::watch::channel(true);
        super::run_native_metering_sampler(
            registry.clone(),
            ledger,
            f.meter(),
            shutdown,
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("native final sample");
        assert_eq!(registry.active_source_count().expect("count"), 0);
        let restored = MeteringLedger::open_persistent(path).expect("reopen ledger");
        assert_eq!(restored.unacked_len(), 0);
        assert_eq!(restored.last_sequence(), 1);
        let outbox = f.outbox();
        assert_eq!(outbox.active()[0].public_response_bytes, 10);
        assert_eq!(outbox.active()[0].cross_az_bytes, 30);
    }

    #[tokio::test]
    async fn native_disabled_sampler_acks_final_without_creating_outbox() {
        let f = NativeFixture::new();
        let path = f.dir.join("producer.wal");
        let ledger = MeteringLedger::open_persistent(path.clone()).expect("ledger");
        let registry = MeteringSourceRegistry::new(ledger.process_generation()).expect("registry");
        native_final_source(&registry);
        let meter = control_meter::service::Service::open(
            &control_config::MeteringConfig::default(),
            f.dir.join("consumer.json"),
            f.dir.join("outbox.json"),
            f.lease.as_ref().expect("lease").token(),
        )
        .await
        .expect("disabled service");
        let (_, shutdown) = tokio::sync::watch::channel(true);
        super::run_native_metering_sampler(
            registry.clone(),
            ledger,
            Arc::clone(&meter),
            shutdown.clone(),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("native disabled final sample");
        assert_eq!(registry.active_source_count().expect("count"), 0);
        let restored = MeteringLedger::open_persistent(path).expect("reopen ledger");
        assert_eq!(restored.unacked_len(), 0);
        assert_eq!(restored.last_sequence(), 1);
        assert_eq!(meter.checkpoint().expect("checkpoint").sequence, 1);
        assert!(!f.dir.join("outbox.json").exists());
        meter.run(shutdown).await.expect("disabled shutdown");
        assert!(!meter.healthy());
    }

    #[test]
    fn native_consumer_failure_keeps_wal_and_replays_final_only_once() {
        let mut f = NativeFixture::new();
        let mut ledger =
            MeteringLedger::open_persistent(f.dir.join("producer.wal")).expect("ledger");
        let registry = MeteringSourceRegistry::new(ledger.process_generation()).expect("registry");
        native_final_source(&registry);
        let old = f.meter();
        drop(f.lease.take());
        assert!(super::native_sample(&registry, &mut ledger, old.as_ref()).is_err());
        assert_eq!(
            ledger.unacked_len(),
            1,
            "no consumer success means no WAL ACK"
        );
        assert_eq!(
            registry.active_source_count().expect("count"),
            0,
            "final moved durably to WAL"
        );
        f.lease = Some(
            f.owners
                .claim(
                    control_plane::ownership::OwnerScope::Process,
                    "native-meter",
                )
                .expect("replacement owner"),
        );
        super::native_sample(&registry, &mut ledger, f.meter().as_ref()).expect("replay");
        assert_eq!(
            ledger.last_sequence(),
            1,
            "final must not become a new sequence"
        );
        assert_eq!(ledger.unacked_len(), 0);
        assert_eq!(f.outbox().active()[0].public_response_bytes, 10);
    }

    #[test]
    fn native_ack_persistence_failure_replays_without_double_billing() {
        let f = NativeFixture::new();
        let wal_dir = f.dir.join("wal-state");
        let path = wal_dir.join("producer.wal");
        let mut ledger = MeteringLedger::open_persistent(path.clone()).expect("ledger");
        let batch = ledger
            .record_snapshots(vec![MeteringSourceSnapshot {
                connection_id: 1,
                process_generation: ledger.process_generation(),
                backend_generation: 1,
                backend_id: "backend-a".into(),
                keyspace: "ks".into(),
                backend_inbound_bytes: 10,
                backend_outbound_bytes: 20,
                r#final: true,
                ..Default::default()
            }])
            .expect("record")
            .expect("batch");
        let disk = fs::read(&path).expect("wal bytes");
        fs::remove_file(&path).expect("remove wal");
        fs::remove_dir(&wal_dir).expect("remove parent");
        fs::write(&wal_dir, b"block ACK persistence").expect("block parent");
        let meter = f.meter();
        assert!(super::native_deliver(&mut ledger, meter.as_ref(), batch).is_err());
        assert_eq!(ledger.unacked_len(), 1);
        assert_eq!(
            f.outbox().active()[0].private_response_bytes,
            10,
            "consumer committed before ACK failed"
        );
        fs::remove_file(&wal_dir).expect("unblock parent");
        fs::create_dir(&wal_dir).expect("restore parent");
        fs::write(&path, disk).expect("restore WAL");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure WAL");
        drop(ledger);
        let mut ledger = MeteringLedger::open_persistent(path).expect("restart");
        let registry =
            MeteringSourceRegistry::new(ledger.process_generation()).expect("new registry");
        super::native_sample(&registry, &mut ledger, meter.as_ref()).expect("deduplicated replay");
        assert_eq!(ledger.unacked_len(), 0);
        assert_eq!(ledger.last_sequence(), 1);
        assert_eq!(f.outbox().active()[0].private_response_bytes, 10);
    }

    #[test]
    fn wal_persists_identity_generation_and_unacked_batches() {
        let directory = test_directory();
        let path = directory.join("metering.wal");
        let (wal, first) = MeteringWal::open(path.clone()).expect("create WAL");
        assert_eq!(first.process_generation, 1);
        assert_eq!(first.next_sequence, 1);
        let batch = MeteringBatch {
            sequence: 1,
            producer_id: first.producer_id.clone(),
            snapshots: vec![MeteringSourceSnapshot {
                connection_id: 1,
                process_generation: first.process_generation,
                backend_generation: 1,
                backend_id: "backend-a".to_owned(),
                keyspace: "keyspace-a".to_owned(),
                ..Default::default()
            }],
            ..Default::default()
        };
        wal.persist(
            &first.producer_id,
            first.process_generation,
            2,
            std::slice::from_ref(&batch),
        )
        .expect("persist batch");
        let (_, second) = MeteringWal::open(path.clone()).expect("reopen WAL");
        assert_eq!(second.producer_id, first.producer_id);
        assert_eq!(second.process_generation, 2);
        assert_eq!(second.next_sequence, 2);
        assert_eq!(second.unacked, vec![batch]);
        assert_eq!(
            fs::metadata(&path)
                .expect("WAL metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn wal_corruption_and_unsafe_permissions_fail_closed() {
        let directory = test_directory();
        let path = directory.join("metering.wal");
        let _ = MeteringWal::open(path.clone()).expect("create WAL");
        let mut bytes = fs::read(&path).expect("read WAL");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, bytes).expect("corrupt WAL");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
        assert!(MeteringWal::open(path.clone()).is_err());

        fs::remove_file(&path).expect("remove corrupt WAL");
        let _ = MeteringWal::open(path.clone()).expect("recreate WAL");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("make unsafe");
        assert!(MeteringWal::open(path).is_err());
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn explicit_ack_durably_trims_replay_across_restart() {
        let directory = test_directory();
        let path = directory.join("metering.wal");
        let mut first = MeteringLedger::open_persistent(path.clone()).expect("open ledger");
        let producer = first.producer_id().to_owned();
        let process_generation = first.process_generation();
        let batch = first
            .record_snapshots(vec![MeteringSourceSnapshot {
                connection_id: 1,
                process_generation,
                backend_generation: 1,
                backend_id: "backend-a".to_owned(),
                keyspace: "keyspace-a".to_owned(),
                ..Default::default()
            }])
            .expect("record snapshot")
            .expect("sealed batch");
        assert_eq!(batch.sequence, 1);
        drop(first);

        let mut second = MeteringLedger::open_persistent(path.clone()).expect("reopen ledger");
        assert_eq!(second.producer_id(), producer);
        assert_eq!(second.replay(), vec![batch]);
        assert!(second.acknowledge(&producer, 1).expect("acknowledge"));
        drop(second);

        let third = MeteringLedger::open_persistent(path).expect("reopen trimmed ledger");
        assert!(third.replay().is_empty());
        assert_eq!(third.last_sequence(), 1);
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn absolute_ledger_rejects_duplicate_sources_transactionally() {
        let directory = test_directory();
        let path = directory.join("metering.wal");
        let mut ledger = MeteringLedger::open_persistent(path).expect("open ledger");
        let snapshot = MeteringSourceSnapshot {
            connection_id: 1,
            process_generation: ledger.process_generation(),
            backend_generation: 1,
            backend_id: "backend-a".to_owned(),
            keyspace: "keyspace-a".to_owned(),
            ..Default::default()
        };
        assert!(matches!(
            ledger.record_snapshots(vec![snapshot.clone(), snapshot]),
            Err(MeteringError::UnknownAttribution)
        ));
        assert!(ledger.replay().is_empty());
        assert_eq!(ledger.last_sequence(), 0);
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn unknown_keyspace_is_session_scoped_not_global_failure() {
        let registry = MeteringSourceRegistry::new(9).expect("registry");
        let result = registry.register(
            MeteringAttribution {
                connection_id: 7,
                backend_generation: 1,
                backend_id: "backend-a".to_owned(),
                cluster_name: "cluster-a".to_owned(),
                keyspace: String::new(),
                local: false,
                public_endpoint: true,
            },
            Arc::new(ByteCounters::default()),
        );
        assert!(matches!(
            result,
            Err(MeteringSamplerError::UnknownAttribution)
        ));
        assert!(!registry.failed.load(Ordering::Acquire));
    }

    #[test]
    fn source_registry_preserves_retired_totals_for_force_close() {
        let registry = MeteringSourceRegistry::new(9).expect("registry");
        registry
            .register(
                MeteringAttribution {
                    connection_id: 7,
                    backend_generation: 1,
                    backend_id: "backend-a".to_owned(),
                    cluster_name: "cluster-a".to_owned(),
                    keyspace: "keyspace-a".to_owned(),
                    local: false,
                    public_endpoint: true,
                },
                Arc::new(ByteCounters::default()),
            )
            .expect("register first source");
        registry
            .finalize(7, 1, 10, 20)
            .expect("finalize first source");
        let sample = registry.prepare().expect("prepare first final");
        registry.commit(&sample).expect("commit first final");

        registry
            .register(
                MeteringAttribution {
                    connection_id: 7,
                    backend_generation: 2,
                    backend_id: "backend-b".to_owned(),
                    cluster_name: "cluster-a".to_owned(),
                    keyspace: "keyspace-a".to_owned(),
                    local: true,
                    public_endpoint: true,
                },
                Arc::new(ByteCounters::default()),
            )
            .expect("register second source");
        assert_eq!(
            registry.finalize_connection(7).expect("force finalize"),
            Some((10, 20))
        );
        let sample = registry.prepare().expect("prepare second final");
        assert_eq!(sample.snapshots.len(), 1);
        assert!(sample.snapshots[0].r#final);
        registry.commit(&sample).expect("commit second final");
        registry.forget_connection(7);
        assert_eq!(
            registry.finalize_connection(7).expect("already removed"),
            None
        );
    }

    #[test]
    fn source_registry_does_not_retain_totals_after_closed_before_commit() {
        let registry = MeteringSourceRegistry::new(9).expect("registry");
        registry
            .register(
                MeteringAttribution {
                    connection_id: 8,
                    backend_generation: 1,
                    backend_id: "backend-a".to_owned(),
                    cluster_name: "cluster-a".to_owned(),
                    keyspace: "keyspace-a".to_owned(),
                    local: false,
                    public_endpoint: true,
                },
                Arc::new(ByteCounters::default()),
            )
            .expect("register source");
        registry.finalize(8, 1, 10, 20).expect("finalize source");
        let sample = registry.prepare().expect("prepare final");

        registry.forget_connection(8);
        registry.commit(&sample).expect("commit after CLOSED");

        assert_eq!(
            registry.finalize_connection(8).expect("no retained totals"),
            None
        );
        assert!(
            registry
                .closed_connections
                .lock()
                .expect("closed registry")
                .is_empty(),
            "the close-before-commit marker is released once all sources commit"
        );
    }

    #[test]
    fn public_endpoint_uses_direct_peer_cidrs() {
        let cidrs = vec!["10.0.0.0/8".to_owned(), "2001:db8::/32".to_owned()];
        assert!(is_public_endpoint(
            "10.4.5.6".parse().expect("IPv4"),
            &cidrs
        ));
        assert!(is_public_endpoint(
            "2001:db8::7".parse().expect("IPv6"),
            &cidrs
        ));
        assert!(!is_public_endpoint(
            "192.168.1.1".parse().expect("IPv4"),
            &cidrs
        ));
        assert!(!is_public_endpoint(
            "10.4.5.6".parse().expect("IPv4"),
            &["bad".to_owned()]
        ));
    }
}
