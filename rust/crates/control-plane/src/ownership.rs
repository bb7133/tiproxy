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

//! In-process ownership fencing for control responsibilities.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use thiserror::Error;

/// Maximum byte length for owner, namespace, and cluster identifiers.
pub const MAX_OWNER_ID_BYTES: usize = 256;

/// A process-wide or scoped control responsibility.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum OwnerScope {
    /// The one process-local control runtime.
    Process,
    /// A future stateful responsibility scoped by namespace and cluster.
    NamespaceCluster {
        /// Namespace identity.
        namespace: Arc<str>,
        /// Backend-cluster identity.
        cluster: Arc<str>,
    },
}

impl OwnerScope {
    /// Builds a namespace/cluster scope with bounded non-empty identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerError::InvalidIdentifier`] for empty or over-bound
    /// identifiers.
    pub fn namespace_cluster(
        namespace: impl Into<String>,
        cluster: impl Into<String>,
    ) -> Result<Self, OwnerError> {
        let namespace = validate_identifier("namespace", namespace.into())?;
        let cluster = validate_identifier("cluster", cluster.into())?;
        Ok(Self::NamespaceCluster { namespace, cluster })
    }

    /// Returns a stable, payload-free scope label for observations.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Process => "process".to_owned(),
            Self::NamespaceCluster { namespace, cluster } => {
                format!("namespace:{namespace}/cluster:{cluster}")
            }
        }
    }
}

/// Ownership acquisition failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnerError {
    /// An identifier was empty or exceeded its bound.
    #[error("invalid {kind} identifier {value:?}")]
    InvalidIdentifier {
        /// Identifier role.
        kind: &'static str,
        /// Rejected value.
        value: String,
    },
    /// Exactly one owner may hold a scope.
    #[error("scope {scope:?} is already owned by {owner_id} generation {generation}")]
    AlreadyOwned {
        /// Rejected scope.
        scope: OwnerScope,
        /// Current owner identity.
        owner_id: Arc<str>,
        /// Current owner generation.
        generation: u64,
    },
    /// Owner generations never wrap and reuse a stale generation.
    #[error("owner generation space is exhausted")]
    GenerationExhausted,
}

#[derive(Clone)]
struct ActiveOwner {
    owner_id: Arc<str>,
    generation: u64,
}

struct RegistryInner {
    owners: Mutex<HashMap<OwnerScope, ActiveOwner>>,
    next_generation: AtomicU64,
}

/// The registry enforcing one live owner for every scope.
#[derive(Clone)]
pub struct OwnershipRegistry {
    inner: Arc<RegistryInner>,
}

impl OwnershipRegistry {
    /// Creates an empty ownership registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                owners: Mutex::new(HashMap::new()),
                next_generation: AtomicU64::new(1),
            }),
        }
    }

    /// Claims one scope until the returned lease is dropped or released.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid owner identity, an already owned scope,
    /// or exhausted generation space.
    pub fn claim(
        &self,
        scope: OwnerScope,
        owner_id: impl Into<String>,
    ) -> Result<OwnerLease, OwnerError> {
        let owner_id = validate_identifier("owner", owner_id.into())?;
        let mut owners = self
            .inner
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(active) = owners.get(&scope) {
            return Err(OwnerError::AlreadyOwned {
                scope,
                owner_id: Arc::clone(&active.owner_id),
                generation: active.generation,
            });
        }
        let generation = self
            .inner
            .next_generation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| OwnerError::GenerationExhausted)?;
        owners.insert(
            scope.clone(),
            ActiveOwner {
                owner_id: Arc::clone(&owner_id),
                generation,
            },
        );
        drop(owners);
        let state = Arc::new(LeaseState {
            registry: Arc::downgrade(&self.inner),
            scope,
            owner_id,
            generation,
            active: AtomicBool::new(true),
        });
        Ok(OwnerLease { state })
    }
}

impl Default for OwnershipRegistry {
    fn default() -> Self {
        Self::new()
    }
}

struct LeaseState {
    registry: Weak<RegistryInner>,
    scope: OwnerScope,
    owner_id: Arc<str>,
    generation: u64,
    active: AtomicBool,
}

impl LeaseState {
    fn release(&self) {
        if !self.active.swap(false, Ordering::AcqRel) {
            return;
        }
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut owners = registry
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owners.get(&self.scope).is_some_and(|active| {
            active.generation == self.generation && active.owner_id == self.owner_id
        }) {
            owners.remove(&self.scope);
        }
    }
}

/// The unique lease that owns one scope.
pub struct OwnerLease {
    state: Arc<LeaseState>,
}

impl OwnerLease {
    /// Returns a non-owning token for future module contexts.
    #[must_use]
    pub fn token(&self) -> OwnerToken {
        OwnerToken {
            state: Arc::downgrade(&self.state),
        }
    }

    /// Returns the owner identity.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.state.owner_id
    }

    /// Returns the monotonically increasing owner generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.state.generation
    }

    /// Returns the owned scope.
    #[must_use]
    pub fn scope(&self) -> &OwnerScope {
        &self.state.scope
    }

    /// Releases the scope before dropping the lease.
    pub fn release(&self) {
        self.state.release();
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        self.state.release();
    }
}

/// A cloneable, non-owning generation fence carried by in-process modules.
#[derive(Clone)]
pub struct OwnerToken {
    state: Weak<LeaseState>,
}

impl OwnerToken {
    /// Returns whether the originating lease still owns its exact generation.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.state
            .upgrade()
            .is_some_and(|state| state.active.load(Ordering::Acquire))
    }

    /// Returns the owner generation while the lease is alive.
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        self.state.upgrade().map(|state| state.generation)
    }
}

fn validate_identifier(kind: &'static str, value: String) -> Result<Arc<str>, OwnerError> {
    if value.is_empty() || value.len() > MAX_OWNER_ID_BYTES {
        return Err(OwnerError::InvalidIdentifier { kind, value });
    }
    Ok(Arc::from(value))
}
