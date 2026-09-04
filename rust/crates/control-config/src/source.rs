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

//! Atomic last-good config/namespace snapshots and canonical decoding.

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str;
use std::sync::{Arc, RwLock};

use thiserror::Error;
use tokio::sync::watch;

use crate::model::{
    ConfigError, EffectiveConfig, LogOnlineConfig, NamespaceConfig, ProxyOnlineConfig,
    SourceRevision, TopologyConfig,
};

/// Historical persistent root for dynamic configuration and namespaces.
pub const CONFIG_PREFIX: &str = "/config/";
/// Historical dynamic proxy key.
pub const PROXY_CONFIG_KEY: &str = "/config/proxy";
/// Historical dynamic log key.
pub const LOG_CONFIG_KEY: &str = "/config/log";
/// Historical namespace key prefix.
pub const NAMESPACE_CONFIG_PREFIX: &str = "/config/ns/";
const MAX_PERSISTENT_ENTRIES: usize = 4_096;
const MAX_PERSISTENT_KEY_BYTES: usize = 2_048;
const MAX_PERSISTENT_VALUE_BYTES: usize = 64 * 1_024;

/// Parsing, validation, checksum, or generation failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// TOML input must be UTF-8.
    #[error("configuration TOML is not UTF-8")]
    NonUtf8Toml,
    /// A TOML candidate could not be decoded.
    #[error("configuration TOML decode failed")]
    TomlDecode(#[source] toml::de::Error),
    /// A canonical TOML view could not be encoded.
    #[error("canonical configuration TOML encode failed")]
    TomlEncode(#[source] toml::ser::Error),
    /// A legacy JSON value could not be decoded.
    #[error("legacy {kind} JSON decode failed")]
    JsonDecode {
        /// Stable persisted value kind.
        kind: &'static str,
        /// Decoder failure retained for local diagnostics.
        #[source]
        source: serde_json::Error,
    },
    /// A complete effective candidate failed validation.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A namespace key and value violate the persistent contract.
    #[error("invalid namespace entry: {class}")]
    Namespace {
        /// Stable error class without the persisted payload.
        class: &'static str,
    },
    /// No generation remains after `u64::MAX`.
    #[error("config/namespace generation exhausted")]
    GenerationExhausted,
    /// A persisted key or value exceeded the bounded compatibility surface.
    #[error("invalid persistent entry: {class}")]
    PersistentEntry {
        /// Stable payload-free rejection class.
        class: &'static str,
    },
    /// A process composition validator rejected an otherwise valid domain
    /// candidate (for example, unreadable TLS material).
    #[error("configuration candidate rejected: {class}")]
    CandidateRejected {
        /// Stable payload-free rejection class.
        class: &'static str,
    },
}

/// An opaque, type-erased artifact a [`CandidateValidator`] prepares once and
/// that the store carries atomically with the snapshot it publishes.
///
/// `control-config` never inspects the contents; a consumer downcasts it to its
/// own concrete type. It has no serialization surface and a redacted `Debug`,
/// so no validated material (such as PEM bytes or endpoints) can leak through
/// it. `Clone` clones only the `Arc`; equality is intentionally not derived —
/// compare identity with [`PreparedArtifact::is_same_handle`].
#[derive(Clone)]
pub struct PreparedArtifact(Arc<dyn Any + Send + Sync>);

impl PreparedArtifact {
    /// Wraps an already-constructed prepared value.
    #[must_use]
    pub fn new(inner: Arc<dyn Any + Send + Sync>) -> Self {
        Self(inner)
    }

    /// An empty artifact, for validators that prepare nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self(Arc::new(()))
    }

    /// Downcasts to the concrete prepared type, or `None` on a type mismatch.
    #[must_use]
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }

    /// Whether two artifacts are the exact same `Arc` handle.
    #[must_use]
    pub fn is_same_handle(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for PreparedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Process-composition validation performed before a generation is
/// published. The core store owns syntax/domain validation; this hook covers
/// serving concerns such as loading TLS material without adding protocol
/// dependencies to `control-config`. It prepares an opaque
/// [`PreparedArtifact`] that the store then carries atomically with the
/// published snapshot, so a consumer never re-reads that material.
pub trait CandidateValidator: Send + Sync {
    /// Validates a complete effective candidate and ordered namespace view, and
    /// prepares the artifact to publish with the snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded payload-free class when the candidate cannot become
    /// a process generation.
    fn validate(
        &self,
        effective: &EffectiveConfig,
        namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str>;
}

impl<F> CandidateValidator for F
where
    F: Fn(&EffectiveConfig, &[NamespaceConfig]) -> Result<PreparedArtifact, &'static str>
        + Send
        + Sync,
{
    fn validate(
        &self,
        effective: &EffectiveConfig,
        namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str> {
        self(effective, namespaces)
    }
}

#[derive(Debug)]
struct AcceptCandidate;

impl CandidateValidator for AcceptCandidate {
    fn validate(
        &self,
        _effective: &EffectiveConfig,
        _namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, &'static str> {
        Ok(PreparedArtifact::empty())
    }
}

/// Complete legacy-compatible overlay read from `/config` at one etcd revision.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PersistentConfigSnapshot {
    /// Optional `/config/proxy` dynamic subset.
    pub proxy: Option<ProxyOnlineConfig>,
    /// Optional `/config/log` dynamic subset.
    pub log: Option<LogOnlineConfig>,
    /// Name-sorted `/config/ns/<name>` values.
    pub namespaces: Vec<NamespaceConfig>,
}

/// Immutable config/namespace state published to process-local consumers.
#[derive(Clone, Debug)]
pub struct ConfigNamespaceSnapshot {
    generation: u64,
    source_revision: SourceRevision,
    config_checksum: u32,
    namespace_checksum: u32,
    effective: Arc<EffectiveConfig>,
    namespaces: Arc<[NamespaceConfig]>,
    prepared: PreparedArtifact,
}

impl PartialEq for ConfigNamespaceSnapshot {
    fn eq(&self, other: &Self) -> bool {
        // The prepared artifact is intentionally excluded: it is an opaque,
        // per-generation handle, not part of the config identity, and the
        // no-op-suppression comparison must not depend on it.
        self.generation == other.generation
            && self.source_revision == other.source_revision
            && self.config_checksum == other.config_checksum
            && self.namespace_checksum == other.namespace_checksum
            && self.effective == other.effective
            && self.namespaces == other.namespaces
    }
}

impl ConfigNamespaceSnapshot {
    /// Returns the contiguous accepted generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns accepted file/etcd source revisions.
    #[must_use]
    pub const fn source_revision(&self) -> SourceRevision {
        self.source_revision
    }

    /// Returns CRC32-IEEE over canonical effective TOML.
    #[must_use]
    pub const fn config_checksum(&self) -> u32 {
        self.config_checksum
    }

    /// Returns CRC32-IEEE over canonical ordered namespace JSON.
    #[must_use]
    pub const fn namespace_checksum(&self) -> u32 {
        self.namespace_checksum
    }

    /// Returns the immutable full effective configuration.
    #[must_use]
    pub const fn effective(&self) -> &Arc<EffectiveConfig> {
        &self.effective
    }

    /// Returns the immutable name-sorted namespace array.
    #[must_use]
    pub fn namespaces(&self) -> &[NamespaceConfig] {
        &self.namespaces
    }

    /// Returns the opaque artifact the validator prepared for this generation.
    ///
    /// A consumer downcasts it to its own concrete prepared type; the store
    /// never inspects it.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedArtifact {
        &self.prepared
    }

    /// Returns the normalized CP-TOPO projection.
    ///
    /// # Errors
    ///
    /// Returns a stable address projection error when self identity cannot be
    /// formed from the accepted full configuration.
    pub fn topology(&self) -> Result<TopologyConfig, ConfigError> {
        self.effective.topology()
    }
}

/// Race-free pull/watch contract for CP-TOPO and later CP-ROUTE.
pub trait ConfigNamespaceSource: Send + Sync {
    /// Returns the committed last-good snapshot.
    fn current(&self) -> Arc<ConfigNamespaceSnapshot>;

    /// Subscribes to future committed generations.
    fn subscribe(&self) -> watch::Receiver<Arc<ConfigNamespaceSnapshot>>;
}

struct StoreState {
    current: Arc<ConfigNamespaceSnapshot>,
    observed_source_revision: SourceRevision,
    file_base: EffectiveConfig,
    file_revision: u64,
    persistent: PersistentConfigSnapshot,
}

/// Atomic last-good config/namespace owner.
#[derive(Clone)]
pub struct ConfigNamespaceStore {
    state: Arc<RwLock<StoreState>>,
    updates: watch::Sender<Arc<ConfigNamespaceSnapshot>>,
    validator: Arc<dyn CandidateValidator>,
}

impl ConfigNamespaceStore {
    /// Builds and publishes the real generation-one view before returning.
    ///
    /// # Errors
    ///
    /// Returns an error when the initial config or namespace set cannot be
    /// validated and canonically encoded.
    pub fn new(
        effective: EffectiveConfig,
        namespaces: Vec<NamespaceConfig>,
        source_revision: SourceRevision,
        current_dir: &Path,
    ) -> Result<Self, StoreError> {
        Self::new_with_validator(
            effective,
            namespaces,
            source_revision,
            current_dir,
            Arc::new(AcceptCandidate),
        )
    }

    /// Builds generation one with a process-composition validator that is
    /// reused for every later candidate.
    ///
    /// # Errors
    ///
    /// Returns a domain, canonicalization, or composition validation error.
    pub fn new_with_validator(
        effective: EffectiveConfig,
        namespaces: Vec<NamespaceConfig>,
        source_revision: SourceRevision,
        current_dir: &Path,
        validator: Arc<dyn CandidateValidator>,
    ) -> Result<Self, StoreError> {
        let effective = effective.validated(current_dir)?;
        let prepared = validator
            .validate(&effective, &namespaces)
            .map_err(|class| StoreError::CandidateRejected { class })?;
        let snapshot = Arc::new(build_snapshot(
            1,
            effective.clone(),
            namespaces.clone(),
            source_revision,
            prepared,
        )?);
        let (updates, _) = watch::channel(Arc::clone(&snapshot));
        Ok(Self {
            state: Arc::new(RwLock::new(StoreState {
                current: snapshot,
                observed_source_revision: source_revision,
                file_base: effective,
                file_revision: source_revision.file_revision,
                persistent: PersistentConfigSnapshot {
                    proxy: None,
                    log: None,
                    namespaces,
                },
            })),
            updates,
            validator,
        })
    }

    /// Parses a partial TOML document over Go-compatible defaults and creates
    /// a generation-one store.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid TOML, validation, or canonical encoding.
    pub fn from_toml(
        data: &[u8],
        advertise_override: Option<&str>,
        current_dir: &Path,
    ) -> Result<Self, StoreError> {
        Self::from_toml_with_validator(
            data,
            advertise_override,
            current_dir,
            Arc::new(AcceptCandidate),
        )
    }

    /// Creates generation one from TOML and installs a process-composition
    /// validator for this and every later candidate.
    ///
    /// # Errors
    ///
    /// Returns a TOML, domain, canonicalization, or composition validation
    /// error.
    pub fn from_toml_with_validator(
        data: &[u8],
        advertise_override: Option<&str>,
        current_dir: &Path,
        validator: Arc<dyn CandidateValidator>,
    ) -> Result<Self, StoreError> {
        let effective = apply_toml_patch(&EffectiveConfig::default(), data)?
            .with_advertise_override(advertise_override);
        Self::new_with_validator(
            effective,
            Vec::new(),
            SourceRevision {
                file_revision: 1,
                etcd_revision: 0,
            },
            current_dir,
            validator,
        )
    }

    /// Atomically applies one complete effective candidate.
    ///
    /// The source cursor is always advanced monotonically for recovery. A
    /// rejected candidate or an effective no-op does not publish or advance
    /// the accepted generation.
    ///
    /// # Errors
    ///
    /// Returns a validation, namespace, checksum, restart-required, or
    /// generation-exhaustion error while retaining last-good.
    pub fn apply(
        &self,
        effective: EffectiveConfig,
        namespaces: Vec<NamespaceConfig>,
        source_revision: SourceRevision,
        current_dir: &Path,
    ) -> Result<Option<Arc<ConfigNamespaceSnapshot>>, StoreError> {
        self.observe_source_revision(source_revision);
        let effective = effective.validated(current_dir)?;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        effective.check_reload_from(state.current.effective())?;
        let prepared = self.validate_candidate(&effective, &namespaces)?;
        let persistent = PersistentConfigSnapshot {
            proxy: None,
            log: None,
            namespaces: namespaces.clone(),
        };
        let published = publish_candidate(
            &mut state,
            &self.updates,
            effective.clone(),
            namespaces,
            source_revision,
            prepared,
        )?;
        state.file_base = effective;
        state.file_revision = source_revision.file_revision;
        state.persistent = persistent;
        Ok(published)
    }

    /// Applies a partial local TOML candidate over the current last-good view.
    ///
    /// # Errors
    ///
    /// Returns a decode, validation, or restart-required error while retaining
    /// last-good.
    pub fn apply_toml(
        &self,
        data: &[u8],
        advertise_override: Option<&str>,
        file_revision: u64,
        current_dir: &Path,
    ) -> Result<Option<Arc<ConfigNamespaceSnapshot>>, StoreError> {
        self.observe_source_revision(SourceRevision {
            file_revision,
            etcd_revision: 0,
        });
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file_base = apply_toml_patch(&state.file_base, data)?
            .with_advertise_override(advertise_override)
            .validated(current_dir)?;
        let effective = compose_effective(&file_base, &state.persistent).validated(current_dir)?;
        effective.check_reload_from(state.current.effective())?;
        let prepared = self.validate_candidate(&effective, &state.persistent.namespaces)?;
        let etcd_revision = state.current.source_revision.etcd_revision;
        let published = publish_if_changed(
            &mut state,
            &self.updates,
            effective,
            SourceRevision {
                file_revision,
                etcd_revision,
            },
            prepared,
        )?;
        state.file_base = file_base;
        state.file_revision = file_revision;
        Ok(published)
    }

    /// Applies one complete persistent `/config` overlay atomically over the
    /// last accepted local-file base.
    ///
    /// Missing proxy/log values reveal the corresponding file-base values;
    /// namespace values replace the complete prior namespace set. A rejected
    /// candidate retains both the accepted overlay and the published view.
    ///
    /// # Errors
    ///
    /// Returns validation, restart-required, checksum, or generation errors.
    pub fn apply_persistent(
        &self,
        persistent: PersistentConfigSnapshot,
        etcd_revision: i64,
        current_dir: &Path,
    ) -> Result<Option<Arc<ConfigNamespaceSnapshot>>, StoreError> {
        self.observe_source_revision(SourceRevision {
            file_revision: 0,
            etcd_revision,
        });
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if etcd_revision < state.current.source_revision.etcd_revision {
            return Ok(None);
        }
        let effective = compose_effective(&state.file_base, &persistent).validated(current_dir)?;
        effective.check_reload_from(state.current.effective())?;
        let source_revision = SourceRevision {
            file_revision: state.file_revision,
            etcd_revision,
        };
        let namespaces = persistent.namespaces.clone();
        let prepared = self.validate_candidate(&effective, &namespaces)?;
        let published = publish_candidate(
            &mut state,
            &self.updates,
            effective,
            namespaces,
            source_revision,
            prepared,
        )?;
        state.persistent = persistent;
        Ok(published)
    }

    /// Revalidates the current effective view and publishes a new generation
    /// for changed external material such as certificate, key, or CA file
    /// contents.
    ///
    /// Configuration and namespace checksums deliberately remain unchanged:
    /// they cover the canonical source model, while the generation also
    /// identifies the immutable process-serving material loaded from it.
    ///
    /// # Errors
    ///
    /// Returns a composition-validation or generation-exhaustion error while
    /// retaining the previous last-good generation.
    pub fn refresh_external_material(&self) -> Result<Arc<ConfigNamespaceSnapshot>, StoreError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let effective = Arc::clone(state.current.effective());
        let namespaces = Arc::clone(&state.current.namespaces);
        let prepared = self.validate_candidate(&effective, &namespaces)?;
        let next_generation = state
            .current
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let candidate = Arc::new(build_snapshot(
            next_generation,
            effective.as_ref().clone(),
            namespaces.to_vec(),
            state.current.source_revision,
            prepared,
        )?);
        state.current = Arc::clone(&candidate);
        self.updates.send_replace(Arc::clone(&candidate));
        Ok(candidate)
    }

    /// Records an observed etcd cursor before parsing a candidate, so a
    /// rejected revision is never replayed forever during recovery.
    pub fn observe_etcd_revision(&self, etcd_revision: i64) {
        self.observe_source_revision(SourceRevision {
            file_revision: 0,
            etcd_revision,
        });
    }

    /// Returns the dynamic proxy/log defaults from the last accepted file
    /// layer, before any persistent overlay is applied.
    #[must_use]
    pub fn persistent_defaults(&self) -> (ProxyOnlineConfig, LogOnlineConfig) {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            state.file_base.proxy_online().clone(),
            state.file_base.log_online().clone(),
        )
    }

    /// Validates a prospective owner-fenced proxy write against the complete
    /// current file base and persistent namespace view without publishing it.
    pub(crate) fn validate_proxy_mutation(
        &self,
        proxy: ProxyOnlineConfig,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent.proxy = Some(proxy);
        self.validate_persistent_view(persistent, current_dir)
    }

    /// Validates a prospective owner-fenced log write without publishing it.
    pub(crate) fn validate_log_mutation(
        &self,
        log: LogOnlineConfig,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent.log = Some(log);
        self.validate_persistent_view(persistent, current_dir)
    }

    /// Validates a prospective namespace upsert against the complete ordered
    /// namespace view without publishing it.
    pub(crate) fn validate_namespace_mutation(
        &self,
        namespace: NamespaceConfig,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent
            .namespaces
            .retain(|current| current.namespace != namespace.namespace);
        persistent.namespaces.push(namespace);
        self.validate_persistent_view(persistent, current_dir)
    }

    /// Validates a prospective namespace deletion without publishing it.
    pub(crate) fn validate_namespace_deletion(
        &self,
        name: &str,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent
            .namespaces
            .retain(|namespace| namespace.namespace != name);
        self.validate_persistent_view(persistent, current_dir)
    }

    /// Applies an owner-fenced proxy mutation at its linearized etcd revision.
    pub(crate) fn apply_committed_proxy_mutation(
        &self,
        proxy: ProxyOnlineConfig,
        etcd_revision: i64,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent.proxy = Some(proxy);
        self.apply_persistent(persistent, etcd_revision, current_dir)
            .map(|_| ())
    }

    /// Applies an owner-fenced log mutation at its linearized etcd revision.
    pub(crate) fn apply_committed_log_mutation(
        &self,
        log: LogOnlineConfig,
        etcd_revision: i64,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent.log = Some(log);
        self.apply_persistent(persistent, etcd_revision, current_dir)
            .map(|_| ())
    }

    /// Applies an owner-fenced namespace upsert at its etcd revision.
    pub(crate) fn apply_committed_namespace_mutation(
        &self,
        namespace: NamespaceConfig,
        etcd_revision: i64,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent
            .namespaces
            .retain(|current| current.namespace != namespace.namespace);
        persistent.namespaces.push(namespace);
        self.apply_persistent(persistent, etcd_revision, current_dir)
            .map(|_| ())
    }

    /// Applies an owner-fenced namespace deletion at its etcd revision.
    pub(crate) fn apply_committed_namespace_deletion(
        &self,
        name: &str,
        etcd_revision: i64,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let mut persistent = self.persistent_view();
        persistent
            .namespaces
            .retain(|namespace| namespace.namespace != name);
        self.apply_persistent(persistent, etcd_revision, current_dir)
            .map(|_| ())
    }

    /// Returns the highest observed source cursor, including rejected/no-op
    /// candidates, for watch recovery diagnostics.
    #[must_use]
    pub fn observed_source_revision(&self) -> SourceRevision {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observed_source_revision
    }

    fn observe_source_revision(&self, source_revision: SourceRevision) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.observed_source_revision =
            max_revision(state.observed_source_revision, source_revision);
    }

    fn validate_candidate(
        &self,
        effective: &EffectiveConfig,
        namespaces: &[NamespaceConfig],
    ) -> Result<PreparedArtifact, StoreError> {
        self.validator
            .validate(effective, namespaces)
            .map_err(|class| StoreError::CandidateRejected { class })
    }

    fn persistent_view(&self) -> PersistentConfigSnapshot {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .persistent
            .clone()
    }

    fn validate_persistent_view(
        &self,
        persistent: PersistentConfigSnapshot,
        current_dir: &Path,
    ) -> Result<(), StoreError> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let effective = compose_effective(&state.file_base, &persistent).validated(current_dir)?;
        effective.check_reload_from(state.current.effective())?;
        let prepared = self.validate_candidate(&effective, &persistent.namespaces)?;
        let generation = state
            .current
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        build_snapshot(
            generation,
            effective,
            persistent.namespaces,
            state.current.source_revision,
            prepared,
        )
        .map(|_| ())
    }
}

impl ConfigNamespaceSource for ConfigNamespaceStore {
    fn current(&self) -> Arc<ConfigNamespaceSnapshot> {
        Arc::clone(
            &self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .current,
        )
    }

    fn subscribe(&self) -> watch::Receiver<Arc<ConfigNamespaceSnapshot>> {
        self.updates.subscribe()
    }
}

/// Decodes the exact historical `/config/proxy` JSON shape.
///
/// # Errors
///
/// Returns a stable JSON decode failure.
pub fn decode_proxy_online(data: &[u8]) -> Result<ProxyOnlineConfig, StoreError> {
    serde_json::from_slice(data).map_err(|source| StoreError::JsonDecode {
        kind: "proxy",
        source,
    })
}

/// Decodes the exact historical `/config/log` JSON shape.
///
/// # Errors
///
/// Returns a stable JSON decode failure.
pub fn decode_log_online(data: &[u8]) -> Result<LogOnlineConfig, StoreError> {
    serde_json::from_slice(data).map_err(|source| StoreError::JsonDecode {
        kind: "log",
        source,
    })
}

/// Decodes and validates one historical `/config/ns/<name>` JSON value.
///
/// # Errors
///
/// Returns a stable error for invalid JSON, empty name, or key/value mismatch.
pub fn decode_namespace(key_name: &str, data: &[u8]) -> Result<NamespaceConfig, StoreError> {
    let namespace: NamespaceConfig =
        serde_json::from_slice(data).map_err(|source| StoreError::JsonDecode {
            kind: "namespace",
            source,
        })?;
    if key_name.is_empty() || namespace.namespace.is_empty() {
        return Err(StoreError::Namespace {
            class: "empty_name",
        });
    }
    if key_name != namespace.namespace {
        return Err(StoreError::Namespace {
            class: "key_value_name_mismatch",
        });
    }
    Ok(namespace)
}

/// Decodes one bounded, complete linearizable `/config/` range read.
///
/// Unknown keys are retained outside this owner's compatibility surface and
/// ignored. Known keys are decoded atomically; one malformed known value
/// rejects the complete candidate.
///
/// # Errors
///
/// Returns a stable bound, UTF-8, JSON, namespace, or duplicate-key failure.
pub fn decode_persistent_entries<I, K, V>(
    entries: I,
) -> Result<PersistentConfigSnapshot, StoreError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let mut raw = BTreeMap::new();
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index >= MAX_PERSISTENT_ENTRIES {
            return Err(StoreError::PersistentEntry {
                class: "too_many_entries",
            });
        }
        let key = key.as_ref();
        let value = value.as_ref();
        if key.is_empty() || key.len() > MAX_PERSISTENT_KEY_BYTES || key.contains(&0) {
            return Err(StoreError::PersistentEntry {
                class: "invalid_key",
            });
        }
        if value.len() > MAX_PERSISTENT_VALUE_BYTES {
            return Err(StoreError::PersistentEntry {
                class: "value_too_large",
            });
        }
        let key = str::from_utf8(key).map_err(|_| StoreError::PersistentEntry {
            class: "non_utf8_key",
        })?;
        if raw.insert(key.to_owned(), value.to_vec()).is_some() {
            return Err(StoreError::PersistentEntry {
                class: "duplicate_key",
            });
        }
    }

    let proxy = raw
        .get(PROXY_CONFIG_KEY)
        .map(|value| decode_proxy_online(value))
        .transpose()?;
    let log = raw
        .get(LOG_CONFIG_KEY)
        .map(|value| decode_log_online(value))
        .transpose()?;
    let mut namespaces = Vec::new();
    for (key, value) in raw.range(NAMESPACE_CONFIG_PREFIX.to_owned()..) {
        let Some(name) = key.strip_prefix(NAMESPACE_CONFIG_PREFIX) else {
            break;
        };
        if name.is_empty() {
            return Err(StoreError::Namespace {
                class: "empty_name",
            });
        }
        namespaces.push(decode_namespace(name, value)?);
    }
    Ok(PersistentConfigSnapshot {
        proxy,
        log,
        namespaces,
    })
}

fn apply_toml_patch(base: &EffectiveConfig, data: &[u8]) -> Result<EffectiveConfig, StoreError> {
    let text = str::from_utf8(data).map_err(|_| StoreError::NonUtf8Toml)?;
    let mut base_value = toml::Value::try_from(base.clone()).map_err(StoreError::TomlEncode)?;
    let patch_value = toml::from_str(text).map_err(StoreError::TomlDecode)?;
    merge_toml(&mut base_value, patch_value);
    base_value.try_into().map_err(StoreError::TomlDecode)
}

fn merge_toml(base: &mut toml::Value, patch: toml::Value) {
    match (base, patch) {
        (toml::Value::Table(base), toml::Value::Table(patch)) => {
            for (key, value) in patch {
                if let Some(base_value) = base.get_mut(&key) {
                    merge_toml(base_value, value);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, patch) => *base = patch,
    }
}

fn compose_effective(
    file_base: &EffectiveConfig,
    persistent: &PersistentConfigSnapshot,
) -> EffectiveConfig {
    let mut effective = file_base.clone();
    if let Some(proxy) = &persistent.proxy {
        effective.apply_proxy_online(proxy.clone());
    }
    if let Some(log) = &persistent.log {
        effective.apply_log_online(log.clone());
    }
    effective
}

fn publish_if_changed(
    state: &mut StoreState,
    updates: &watch::Sender<Arc<ConfigNamespaceSnapshot>>,
    effective: EffectiveConfig,
    source_revision: SourceRevision,
    prepared: PreparedArtifact,
) -> Result<Option<Arc<ConfigNamespaceSnapshot>>, StoreError> {
    let namespaces = state.persistent.namespaces.clone();
    publish_candidate(
        state,
        updates,
        effective,
        namespaces,
        source_revision,
        prepared,
    )
}

fn publish_candidate(
    state: &mut StoreState,
    updates: &watch::Sender<Arc<ConfigNamespaceSnapshot>>,
    effective: EffectiveConfig,
    namespaces: Vec<NamespaceConfig>,
    source_revision: SourceRevision,
    prepared: PreparedArtifact,
) -> Result<Option<Arc<ConfigNamespaceSnapshot>>, StoreError> {
    let next_generation = state
        .current
        .generation
        .checked_add(1)
        .ok_or(StoreError::GenerationExhausted)?;
    let candidate = build_snapshot(
        next_generation,
        effective,
        namespaces,
        source_revision,
        prepared,
    )?;
    if state.current.effective.as_ref() == candidate.effective.as_ref()
        && state.current.namespaces.as_ref() == candidate.namespaces.as_ref()
    {
        return Ok(None);
    }
    let candidate = Arc::new(candidate);
    state.current = Arc::clone(&candidate);
    updates.send_replace(Arc::clone(&candidate));
    Ok(Some(candidate))
}

fn build_snapshot(
    generation: u64,
    effective: EffectiveConfig,
    mut namespaces: Vec<NamespaceConfig>,
    source_revision: SourceRevision,
    prepared: PreparedArtifact,
) -> Result<ConfigNamespaceSnapshot, StoreError> {
    namespaces.sort_by(|left, right| left.namespace.cmp(&right.namespace));
    let mut names = std::collections::BTreeSet::new();
    if namespaces.iter().any(|namespace| {
        namespace.namespace.is_empty() || !names.insert(namespace.namespace.as_str())
    }) {
        return Err(StoreError::Namespace {
            class: "empty_or_duplicate_name",
        });
    }
    let config_data = encode_canonical_config(&effective)?;
    let namespace_data =
        serde_json::to_vec(&namespaces).map_err(|source| StoreError::JsonDecode {
            kind: "namespace_checksum",
            source,
        })?;
    Ok(ConfigNamespaceSnapshot {
        generation,
        source_revision,
        config_checksum: crc32fast::hash(config_data.as_bytes()),
        namespace_checksum: crc32fast::hash(&namespace_data),
        effective: Arc::new(effective),
        namespaces: Arc::from(namespaces),
        prepared,
    })
}

/// Encodes one effective configuration into the checksum representation used
/// by the legacy Go config manager.
///
/// # Errors
///
/// Returns a TOML encoding error if the complete validated model cannot be
/// represented.
pub fn encode_canonical_config(effective: &EffectiveConfig) -> Result<String, StoreError> {
    Ok(effective.encode_go_toml())
}

const fn max_revision(left: SourceRevision, right: SourceRevision) -> SourceRevision {
    SourceRevision {
        file_revision: if left.file_revision > right.file_revision {
            left.file_revision
        } else {
            right.file_revision
        },
        etcd_revision: if left.etcd_revision > right.etcd_revision {
            left.etcd_revision
        } else {
            right.etcd_revision
        },
    }
}
