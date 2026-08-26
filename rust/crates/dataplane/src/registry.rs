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

//! Stable frontend connection IDs and RAII-owned registry membership.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::admission::AdmissionPermit;

/// Stable Rust-owned frontend connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Reconstructs an identifier received from the control protocol.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidConnectionId`] for the reserved zero
    /// value. Every ID allocated by this registry is nonzero.
    pub const fn from_control(value: u64) -> Result<Self, RegistryError> {
        if value == 0 {
            Err(RegistryError::InvalidConnectionId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the wire/control-plane numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Metadata that may be exposed to control, reconciliation, metrics, and logs.
/// It deliberately contains no packet or authentication payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMetadata {
    /// Stable connection ID.
    pub connection_id: ConnectionId,
    /// Snapshot generation captured for this new connection.
    pub snapshot_generation: u64,
    /// Logical configured listener name.
    pub listener_name: Arc<str>,
    /// OS-reported address of the listener that accepted this connection.
    pub listener_address: SocketAddr,
    /// Socket peer address before optional PROXY-v2 replacement.
    pub peer_address: SocketAddr,
    /// Read-plus-write connection-buffer reservation.
    pub reserved_buffer_bytes: u64,
}

/// Point-in-time registry view sorted by stable connection ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRegistrySnapshot {
    /// Live connection metadata in ascending ID order.
    pub connections: Vec<ConnectionMetadata>,
    /// Total connections successfully registered over this process lifetime.
    pub registered_total: u64,
}

#[derive(Debug, Default)]
struct RegistryState {
    connections: BTreeMap<ConnectionId, ConnectionMetadata>,
}

#[derive(Debug)]
struct RegistryInner {
    next_id: AtomicU64,
    registered_total: AtomicU64,
    state: Mutex<RegistryState>,
}

/// Single process-wide owner of live frontend connection identities.
#[derive(Debug, Clone)]
pub struct ConnectionRegistry {
    inner: Arc<RegistryInner>,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    /// Creates an empty registry whose first ID is one, matching Go.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                next_id: AtomicU64::new(1),
                registered_total: AtomicU64::new(0),
                state: Mutex::new(RegistryState::default()),
            }),
        }
    }

    pub(crate) fn register(
        &self,
        permit: AdmissionPermit,
        snapshot_generation: u64,
        listener_name: Arc<str>,
        listener_address: SocketAddr,
        peer_address: SocketAddr,
    ) -> Result<ConnectionLease, RegistryError> {
        let connection_id = self.allocate_id()?;
        let metadata = ConnectionMetadata {
            connection_id,
            snapshot_generation,
            listener_name,
            listener_address,
            peer_address,
            reserved_buffer_bytes: permit.reserved_buffer_bytes(),
        };
        lock(&self.inner.state)
            .connections
            .insert(connection_id, metadata.clone());
        self.inner.registered_total.fetch_add(1, Ordering::Relaxed);
        Ok(ConnectionLease {
            inner: Arc::clone(&self.inner),
            metadata,
            _permit: permit,
        })
    }

    fn allocate_id(&self) -> Result<ConnectionId, RegistryError> {
        self.inner
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(ConnectionId)
            .map_err(|_| RegistryError::ConnectionIdExhausted)
    }

    /// Returns the number of live registered connections.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.inner.state).connections.len()
    }

    /// Returns whether there are no live registered connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns one live metadata record, if present.
    #[must_use]
    pub fn get(&self, connection_id: ConnectionId) -> Option<ConnectionMetadata> {
        lock(&self.inner.state)
            .connections
            .get(&connection_id)
            .cloned()
    }

    /// Returns a sorted, payload-free reconciliation view.
    #[must_use]
    pub fn snapshot(&self) -> ConnectionRegistrySnapshot {
        ConnectionRegistrySnapshot {
            connections: lock(&self.inner.state)
                .connections
                .values()
                .cloned()
                .collect(),
            registered_total: self.inner.registered_total.load(Ordering::Relaxed),
        }
    }
}

/// Stable-ID allocation failed before registry insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The control protocol's reserved zero value is not a connection ID.
    #[error("frontend connection ID must be nonzero")]
    InvalidConnectionId,
    /// Every nonzero `u64` process-lifetime ID has been allocated.
    #[error("frontend connection ID space is exhausted")]
    ConnectionIdExhausted,
}

/// Registry membership paired with the underlying admission permit.
/// Dropping it removes metadata before releasing admission gauges.
pub(crate) struct ConnectionLease {
    inner: Arc<RegistryInner>,
    metadata: ConnectionMetadata,
    _permit: AdmissionPermit,
}

impl ConnectionLease {
    pub(crate) const fn metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        lock(&self.inner.state)
            .connections
            .remove(&self.metadata.connection_id);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmissionController, AdmissionPolicy, MemoryProbe, MemorySample};

    #[derive(Debug)]
    struct NoPressure;

    impl MemoryProbe for NoPressure {
        fn sample(&self) -> Result<MemorySample, crate::MemoryProbeError> {
            Ok(MemorySample::now(1, 100))
        }
    }

    fn permit(controller: &AdmissionController) -> AdmissionPermit {
        let policy = AdmissionPolicy::new(0, 0.0, 4096)
            .unwrap_or_else(|error| unreachable!("policy: {error}"));
        controller
            .try_acquire(policy)
            .unwrap_or_else(|error| unreachable!("admit: {error}"))
    }

    #[test]
    fn ids_are_stable_monotonic_and_membership_is_raii() {
        let admission = AdmissionController::new(Arc::new(NoPressure));
        let registry = ConnectionRegistry::new();
        let listener = SocketAddr::from(([127, 0, 0, 1], 6000));
        let peer = SocketAddr::from(([127, 0, 0, 1], 50_000));
        let first = registry
            .register(permit(&admission), 7, Arc::from("sql-0"), listener, peer)
            .unwrap_or_else(|error| unreachable!("register: {error}"));
        let second = registry
            .register(permit(&admission), 8, Arc::from("sql-1"), listener, peer)
            .unwrap_or_else(|error| unreachable!("register: {error}"));
        assert_eq!(first.metadata().connection_id.get(), 1);
        assert_eq!(second.metadata().connection_id.get(), 2);
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.snapshot().registered_total, 2);
        drop(first);
        assert_eq!(registry.len(), 1);
        assert_eq!(admission.metrics().active_connections, 1);
        drop(second);
        assert!(registry.is_empty());
        assert_eq!(admission.metrics().active_connections, 0);
    }

    #[test]
    fn control_ids_and_allocation_failure_are_typed_and_leak_free() {
        assert!(matches!(
            ConnectionId::from_control(0),
            Err(RegistryError::InvalidConnectionId)
        ));
        assert_eq!(
            ConnectionId::from_control(42)
                .unwrap_or_else(|error| unreachable!("control id: {error}"))
                .get(),
            42
        );

        let admission = AdmissionController::new(Arc::new(NoPressure));
        let registry = ConnectionRegistry::new();
        registry.inner.next_id.store(u64::MAX, Ordering::Release);
        let listener = SocketAddr::from(([127, 0, 0, 1], 6000));
        let peer = SocketAddr::from(([127, 0, 0, 1], 50_000));
        let result = registry.register(permit(&admission), 7, Arc::from("sql-0"), listener, peer);
        assert!(matches!(result, Err(RegistryError::ConnectionIdExhausted)));
        assert!(registry.is_empty());
        assert_eq!(registry.snapshot().registered_total, 0);
        assert_eq!(admission.metrics().active_connections, 0);
        assert_eq!(admission.metrics().connection_buffer_bytes, 0);
    }
}
