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

//! Versioned, process-local configuration views.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use thiserror::Error;
use tokio::sync::watch;

/// Maximum number of TLS allow-list roots accepted by the process foundation.
pub const MAX_TLS_ROOTS: usize = 64;

/// Maximum length of the bounded Prometheus namespace.
pub const MAX_METRICS_NAMESPACE_BYTES: usize = 64;

/// A control-plane configuration validation or lineage failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Configuration generations start at one.
    #[error("control config generation must be positive")]
    ZeroGeneration,
    /// A replacement must be the immediate successor of the last-good view.
    #[error("control config generation {actual} does not follow {current}")]
    NonSuccessorGeneration {
        /// The currently committed generation.
        current: u64,
        /// The rejected candidate generation.
        actual: u64,
    },
    /// `u64::MAX` cannot have an immediate successor.
    #[error("control config generation {current} is exhausted")]
    GenerationExhausted {
        /// The terminal committed generation.
        current: u64,
    },
    /// TLS roots are absolute process-security boundaries.
    #[error("TLS root must be absolute: {0:?}")]
    RelativeTlsRoot(PathBuf),
    /// The TLS root list is deliberately bounded.
    #[error("TLS root count {actual} exceeds {maximum}")]
    TooManyTlsRoots {
        /// The rejected root count.
        actual: usize,
        /// The accepted upper bound.
        maximum: usize,
    },
    /// Metrics namespaces use a conservative, bounded Prometheus-safe shape.
    #[error("invalid metrics namespace {0:?}")]
    InvalidMetricsNamespace(String),
}

/// Dynamic log filtering owned by the in-process runtime foundation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogLevel {
    /// Emit only errors.
    Error,
    /// Emit warnings and errors.
    Warn,
    /// Emit normal lifecycle events.
    #[default]
    Info,
    /// Emit debug diagnostics.
    Debug,
    /// Emit trace diagnostics.
    Trace,
}

impl LogLevel {
    /// Returns the stable lower-case spelling used by structured events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Bounded process metrics policy shared by later control modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricsPolicy {
    namespace: Arc<str>,
}

impl MetricsPolicy {
    /// Builds a Prometheus-safe namespace.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidMetricsNamespace`] for an empty,
    /// over-bound, or non-`[a-z][a-z0-9_]*` namespace.
    pub fn new(namespace: impl Into<String>) -> Result<Self, ConfigError> {
        let namespace = namespace.into();
        let mut chars = namespace.chars();
        let valid = namespace.len() <= MAX_METRICS_NAMESPACE_BYTES
            && chars.next().is_some_and(|first| first.is_ascii_lowercase())
            && chars.all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            });
        if !valid {
            return Err(ConfigError::InvalidMetricsNamespace(namespace));
        }
        Ok(Self {
            namespace: Arc::from(namespace),
        })
    }

    /// Returns the namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl Default for MetricsPolicy {
    fn default() -> Self {
        Self {
            namespace: Arc::from("tiproxy"),
        }
    }
}

/// Immutable TLS-root view. Existing users retain their `Arc`; new users see
/// the next committed generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsPolicy {
    roots: Arc<[PathBuf]>,
}

impl TlsPolicy {
    /// Validates, sorts, and de-duplicates TLS allow-list roots.
    ///
    /// # Errors
    ///
    /// Returns an error for relative paths or an over-bound root set.
    pub fn new(mut roots: Vec<PathBuf>) -> Result<Self, ConfigError> {
        if roots.len() > MAX_TLS_ROOTS {
            return Err(ConfigError::TooManyTlsRoots {
                actual: roots.len(),
                maximum: MAX_TLS_ROOTS,
            });
        }
        if let Some(relative) = roots.iter().find(|root| !root.is_absolute()) {
            return Err(ConfigError::RelativeTlsRoot(relative.clone()));
        }
        roots.sort();
        roots.dedup();
        Ok(Self {
            roots: Arc::from(roots),
        })
    }

    /// Returns the sorted, de-duplicated roots.
    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            roots: Arc::from([]),
        }
    }
}

/// One fully validated, atomically installed process configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlConfig {
    generation: u64,
    drain_grace: Duration,
    health_port: u16,
    tls: Arc<TlsPolicy>,
    log_level: LogLevel,
    metrics: MetricsPolicy,
}

impl ControlConfig {
    /// Builds a validated configuration view.
    ///
    /// # Errors
    ///
    /// Returns an error when `generation` is zero.
    pub fn new(
        generation: u64,
        drain_grace: Duration,
        health_port: u16,
        tls: TlsPolicy,
        log_level: LogLevel,
        metrics: MetricsPolicy,
    ) -> Result<Self, ConfigError> {
        if generation == 0 {
            return Err(ConfigError::ZeroGeneration);
        }
        Ok(Self {
            generation,
            drain_grace,
            health_port,
            tls: Arc::new(tls),
            log_level,
            metrics,
        })
    }

    /// Returns the monotonically increasing configuration generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the graceful-drain deadline.
    #[must_use]
    pub const fn drain_grace(&self) -> Duration {
        self.drain_grace
    }

    /// Returns the optional health endpoint port (`0` disables it).
    #[must_use]
    pub const fn health_port(&self) -> u16 {
        self.health_port
    }

    /// Returns the immutable TLS view for new consumers.
    #[must_use]
    pub fn tls(&self) -> Arc<TlsPolicy> {
        Arc::clone(&self.tls)
    }

    /// Returns the dynamic log level.
    #[must_use]
    pub const fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Returns the bounded metrics policy.
    #[must_use]
    pub const fn metrics(&self) -> &MetricsPolicy {
        &self.metrics
    }
}

/// The process-local configuration contract consumed by Rust control modules.
pub trait ConfigSource: Send + Sync {
    /// Returns the committed last-good view.
    fn current(&self) -> Arc<ControlConfig>;

    /// Subscribes to future committed generations.
    fn subscribe(&self) -> watch::Receiver<Arc<ControlConfig>>;
}

/// The TLS-specific subset used by connection factories.
pub trait TlsSource: Send + Sync {
    /// Returns the TLS view used for a newly created connection or client.
    fn current_tls(&self) -> Arc<TlsPolicy>;
}

/// Atomic last-good configuration store.
#[derive(Clone)]
pub struct ConfigStore {
    current: Arc<RwLock<Arc<ControlConfig>>>,
    updates: watch::Sender<Arc<ControlConfig>>,
}

impl ConfigStore {
    /// Creates a store with an already validated initial view.
    #[must_use]
    pub fn new(initial: ControlConfig) -> Self {
        let initial = Arc::new(initial);
        let (updates, _) = watch::channel(Arc::clone(&initial));
        Self {
            current: Arc::new(RwLock::new(initial)),
            updates,
        }
    }

    /// Atomically commits the immediate successor of the last-good view.
    ///
    /// Validation happens before the writer lock is acquired. A rejected
    /// lineage leaves both the current view and subscribers untouched.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::NonSuccessorGeneration`] for stale, duplicate,
    /// or skipped generations, and [`ConfigError::GenerationExhausted`] once
    /// the committed generation reaches `u64::MAX`.
    pub fn apply(&self, candidate: ControlConfig) -> Result<Arc<ControlConfig>, ConfigError> {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expected =
            current
                .generation()
                .checked_add(1)
                .ok_or(ConfigError::GenerationExhausted {
                    current: current.generation(),
                })?;
        if candidate.generation() != expected {
            return Err(ConfigError::NonSuccessorGeneration {
                current: current.generation(),
                actual: candidate.generation(),
            });
        }
        let candidate = Arc::new(candidate);
        *current = Arc::clone(&candidate);
        self.updates.send_replace(Arc::clone(&candidate));
        Ok(candidate)
    }
}

impl ConfigSource for ConfigStore {
    fn current(&self) -> Arc<ControlConfig> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn subscribe(&self) -> watch::Receiver<Arc<ControlConfig>> {
        self.updates.subscribe()
    }
}

impl TlsSource for ConfigStore {
    fn current_tls(&self) -> Arc<TlsPolicy> {
        self.current().tls()
    }
}
