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

//! Restart-pinned storage factory and enabled/disabled native metering lifecycle.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use control_config::{LocalFsMeteringConfig, MeteringConfig};
use control_plane::ownership::OwnerToken;
use tokio::sync::watch;

use crate::cloud_store::CloudStore;
use crate::export::{MaintenanceFuture, ObjectStore, UploadFuture};
use crate::runtime::Meter;
use crate::{Batch, Checkpoint, Consumer, DisabledSink, Error, Intake, LocalStore, Outbox};

enum Store {
    Local(LocalStore),
    Cloud(Box<CloudStore>),
}

impl Store {
    async fn new(config: &MeteringConfig) -> Result<Self, Error> {
        match config.provider_type.as_str() {
            "localfs" => {
                // An absent section differs from an explicitly empty section.
                let local = config.localfs.clone().unwrap_or(LocalFsMeteringConfig {
                    create_dirs: true,
                    ..Default::default()
                });
                let prefix = config.prefix.clone();
                tokio::task::spawn_blocking(move || {
                    LocalStore::new(
                        Path::new(&local.base_path),
                        &prefix,
                        local.create_dirs,
                        &local.permissions,
                    )
                    .map(Self::Local)
                })
                .await
                .map_err(|_| Error::Export("storage factory worker failed"))?
            }
            "s3" | "oss" | "cos" | "azure" => CloudStore::new(config)
                .await
                .map(|store| Self::Cloud(Box::new(store))),
            _ => Err(Error::Invalid("unsupported metering provider")),
        }
    }
}

impl ObjectStore for Store {
    fn maintain(&self) -> MaintenanceFuture<'_> {
        match self {
            Self::Local(store) => store.maintain(),
            Self::Cloud(store) => store.maintain(),
        }
    }

    fn put_new<'a>(&'a self, key: &'a str, body: Vec<u8>) -> UploadFuture<'a> {
        match self {
            Self::Local(store) => store.put_new(key, body),
            Self::Cloud(store) => store.put_new(key, body),
        }
    }
}

struct DisabledState {
    consumer: Consumer<DisabledSink>,
    accepting: bool,
}

enum Mode {
    Enabled(Arc<Meter<Store>>),
    Disabled {
        state: Mutex<DisabledState>,
        started: AtomicBool,
    },
}

/// One native meter selected from Go-compatible, restart-pinned configuration.
///
/// Empty provider type OR empty bucket disables billing for every provider,
/// including `LocalFS`. Disabled intake still persists the absolute consumer and
/// clears its pending deltas before ACK; it never opens or modifies an outbox.
/// The caller must hold exclusive ownership of both files and the producer WAL.
/// Stop sessions, join the sampler, stop/join this worker, then retire the owner.
pub struct Service {
    mode: Mode,
}

impl Service {
    /// Opens the selected provider, with durable state I/O on the blocking pool.
    /// Paths are explicit so the process owner can reuse the Go state locations.
    ///
    /// # Errors
    /// Rejects invalid enabled storage, malformed state, retired ownership, or
    /// missing/mismatched enabled outbox checkpoints. Disabled outbox paths are ignored.
    pub async fn open(
        config: &MeteringConfig,
        consumer_path: PathBuf,
        outbox_path: PathBuf,
        owner: OwnerToken,
    ) -> Result<Arc<Self>, Error> {
        if !owner.is_current() {
            return Err(Error::Retired);
        }
        let enabled = !config.provider_type.is_empty() && !config.bucket.is_empty();
        let store = if enabled {
            Some(Store::new(config).await?)
        } else {
            None
        };
        let shared_pool_id = config.shared_pool_id.clone();
        tokio::task::spawn_blocking(move || {
            let mode = if let Some(store) = store {
                let outbox = Outbox::open(outbox_path, owner.clone())?;
                let consumer = Consumer::open(consumer_path, owner, outbox)?;
                Mode::Enabled(Meter::new(consumer, store, shared_pool_id))
            } else {
                Mode::Disabled {
                    state: Mutex::new(DisabledState {
                        consumer: Consumer::open(consumer_path, owner, DisabledSink)?,
                        accepting: true,
                    }),
                    started: AtomicBool::new(false),
                }
            };
            Ok(Arc::new(Self { mode }))
        })
        .await
        .map_err(|_| Error::Export("meter state worker failed"))?
    }

    /// Current native intake readiness, including ownership and export health.
    #[must_use]
    pub fn healthy(&self) -> bool {
        match &self.mode {
            Mode::Enabled(meter) => meter.healthy(),
            Mode::Disabled { state, .. } => state
                .lock()
                .is_ok_and(|state| state.accepting && state.consumer.healthy()),
        }
    }

    /// Last staged sequence; only successful intake permits a producer ACK.
    ///
    /// # Errors
    /// Returns unhealthy if the state lock is poisoned.
    pub fn checkpoint(&self) -> Result<Checkpoint, Error> {
        match &self.mode {
            Mode::Enabled(meter) => meter.checkpoint(),
            Mode::Disabled { state, .. } => Ok(state
                .lock()
                .map_err(|_| Error::Unhealthy)?
                .consumer
                .checkpoint()),
        }
    }

    /// Export failures when billing is enabled, for process metrics/logging.
    #[must_use]
    pub fn export_failures(&self) -> Option<watch::Receiver<u64>> {
        match &self.mode {
            Mode::Enabled(meter) => Some(meter.export_failures()),
            Mode::Disabled { .. } => None,
        }
    }

    /// Starts the one export lifecycle, or waits for shutdown when billing is disabled.
    ///
    /// # Errors
    /// Rejects repeated starts and reports a failed final enabled export.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), Error> {
        match &self.mode {
            Mode::Enabled(meter) => meter.run(shutdown).await,
            Mode::Disabled { state, started } => {
                if started.swap(true, Ordering::AcqRel) {
                    return Err(Error::Invalid("meter export worker already started"));
                }
                while !*shutdown.borrow() {
                    if shutdown.changed().await.is_err() {
                        break;
                    }
                }
                state.lock().map_err(|_| Error::Unhealthy)?.accepting = false;
                Ok(())
            }
        }
    }
}

impl Intake for Service {
    fn apply(&self, batch: &Batch) -> Result<bool, Error> {
        match &self.mode {
            Mode::Enabled(meter) => meter.apply(batch),
            Mode::Disabled { state, .. } => {
                let mut state = state.lock().map_err(|_| Error::Unhealthy)?;
                if !state.accepting || !state.consumer.healthy() {
                    return Err(Error::Unhealthy);
                }
                state.consumer.apply(batch)
            }
        }
    }
}
