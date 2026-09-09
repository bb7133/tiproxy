// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A diagnostic child task, never a mandatory SQL supervisor child.
use crate::{
    MAX_FRAME_BYTES,
    live::{self, Frame},
};
use control_router::shadow::{
    Epoch, Event, InvalidReason, Limits, Progress, Status, live::LiveState,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::UnixStream,
    sync::watch,
    task::JoinHandle,
    time::{Instant, timeout},
};

/// Fixed observation freshness deadline, independent of SQL/control liveness.
pub const STALE_DEADLINE: Duration = Duration::from_secs(3);

/// Bounded externally readable diagnostics; excludes all routing authority.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Successfully decoded batches, including invalid-owner retained history.
    pub batches: u64,
    /// Number of lifecycle events in those batches.
    pub events: u64,
    /// Independently compared complete native evaluations.
    pub evaluations: u64,
    /// Independently accepted complete native configuration evaluations.
    pub native_configurations: u64,
    /// Current charged native metadata/history, excluding transient staging.
    pub native_retained_bytes: usize,
    /// Highest admitted native retained plus decoder/clone/staging charge.
    pub native_peak_bytes: usize,
    /// Owners whose immutable factory installed native factor capture.
    pub native_owners: std::collections::BTreeSet<Epoch>,
    /// Qualified accepted lifecycle transitions, excluding identity/coverage events.
    pub operations: u64,
    /// Independently derived retained score count across known exact owners.
    pub score: u64,
    /// Independently derived retained physical count across known exact owners.
    pub physical: u64,
    /// The owned task has stopped; teardown still joins its handle.
    pub stopped: bool,
    /// Socket intervals successfully connected to a same-UID peer.
    pub connections: u64,
    /// Failed/malformed/disconnected intervals; these never fail SQL startup.
    pub transport_errors: u64,
    /// Last status and successfully compared sequence, bounded to 128 owners.
    pub owners: BTreeMap<Epoch, Progress>,
    /// Original producer cause and last admitted sequence, never comparison proof.
    pub producer_invalid: BTreeMap<Epoch, (live::InvalidCause, u64)>,
    // Per-owner contributions avoid rescanning every account on every frame.
    totals_by_owner: BTreeMap<Epoch, (u64, u64)>,
}
/// Read-only diagnostic handle. The consumer never calls a production object.
#[derive(Clone)]
pub struct Diagnostics(Arc<Mutex<Report>>);
impl Diagnostics {
    /// Copy bounded report values for tests or diagnostic endpoints.
    #[must_use]
    pub fn snapshot(&self) -> Report {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Owned optional consumer task; startup rollback and shutdown must join it.
pub struct Task {
    shutdown: watch::Sender<bool>,
    handle: JoinHandle<()>,
    diagnostics: Diagnostics,
}
impl Task {
    /// Nonblocking startup. Connect/decode errors stay in diagnostic state and
    /// do not change the lifetime or readiness of the hosting SQL runtime.
    #[must_use]
    pub fn spawn(path: PathBuf) -> Self {
        let (shutdown, receiver) = watch::channel(false);
        let diagnostics = Diagnostics(Arc::new(Mutex::new(Report::default())));
        let copy = diagnostics.clone();
        let task = tokio::spawn(async move {
            run(&path, receiver, &copy).await;
        });
        Self {
            shutdown,
            handle: task,
            diagnostics,
        }
    }
    /// Read-only bounded diagnostics, with no control commands or subscriptions.
    #[must_use]
    pub fn diagnostics(&self) -> Diagnostics {
        self.diagnostics.clone()
    }
    /// Cancel pending reads/connect/retry delay, then join the sole consumer.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        if self.handle.await.is_err() {
            self.diagnostics
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .transport_errors += 1;
        }
        self.diagnostics
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stopped = true;
    }
}

async fn run(path: &Path, mut shutdown: watch::Receiver<bool>, diagnostics: &Diagnostics) {
    let mut state = LiveState::new(Limits::default());
    let mut epochs = BTreeMap::<Epoch, Instant>::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        let connected = tokio::select! {
            _=shutdown.changed()=>break,
            result=timeout(Duration::from_millis(500),connect(path))=>result,
        };
        if let Ok(Ok(mut stream)) = connected {
            diagnostics
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .connections += 1;
            let result = tokio::select! {
                _=shutdown.changed()=>Ok(()),
                result=consume(&mut stream,&mut state,&mut epochs,diagnostics)=>result,
            };
            if result == Err("stale") || result == Err("history_capacity") {
                for epoch in epochs.keys() {
                    state.invalidate(
                        *epoch,
                        if result == Err("history_capacity") {
                            InvalidReason::Capacity
                        } else {
                            InvalidReason::Stale
                        },
                    );
                }
            }
            state.transport_lost();
            publish(&state, &epochs, diagnostics, None);
            if *shutdown.borrow() {
                break;
            }
            if let Err(reason) = result {
                eprintln!(
                    "routing_shadow selection=false scheduler=false interval_invalid={reason}"
                );
            }
        }
        {
            let mut report = diagnostics
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            report.transport_errors += 1;
            if report.transport_errors % 20 == 1 {
                eprintln!(
                    "routing_shadow selection=false scheduler=false connection_unavailable=true transport_errors={}",
                    report.transport_errors
                );
            }
        }
        tokio::select! {_=shutdown.changed()=>break,()=tokio::time::sleep(Duration::from_millis(500))=>{}}
    }
    state.transport_lost();
    publish(&state, &epochs, diagnostics, None);
}

async fn connect(path: &Path) -> Result<UnixStream, &'static str> {
    if !path.is_absolute() {
        return Err("path");
    }
    let uid = rustix::process::geteuid().as_raw();
    let socket = std::fs::symlink_metadata(path).map_err(|_| "socket")?;
    let parent =
        std::fs::symlink_metadata(path.parent().ok_or("directory")?).map_err(|_| "directory")?;
    if !parent.is_dir()
        || parent.uid() != uid
        || parent.permissions().mode() & 0o077 != 0
        || socket.uid() != uid
        || socket.permissions().mode() & 0o777 != 0o600
        || socket.file_type().is_symlink()
    {
        return Err("permissions");
    }
    let stream = UnixStream::connect(path).await.map_err(|_| "connect")?;
    if stream.peer_cred().map_err(|_| "peer_credential")?.uid() != uid {
        return Err("peer_uid");
    }
    Ok(stream)
}

async fn consume(
    stream: &mut UnixStream,
    state: &mut LiveState,
    epochs: &mut BTreeMap<Epoch, Instant>,
    diagnostics: &Diagnostics,
) -> Result<(), &'static str> {
    let mut identity = None;
    let mut last_report = Instant::now();
    loop {
        let frame = read_frame(stream, state).await?;
        let staging = frame
            .len()
            .checked_mul(crate::native::DECODE_MULTIPLIER)
            .ok_or("history_capacity")?;
        let changed = if let Some(epoch) = crate::native::envelope(&frame).map_err(|_| "schema")? {
            if identity != Some((epoch.process, epoch.nonce)) {
                return Err("identity");
            }
            consume_native(&frame, epoch, state, epochs, diagnostics, staging)?
        } else {
            match live::decode(&frame).map_err(|_| "schema")? {
                Frame::Coverage { process, nonce } => {
                    if identity.replace((process, nonce)).is_some() {
                        return Err("duplicate_coverage");
                    }
                    None
                }
                Frame::Batch(batch) => {
                    if identity != Some((batch.epoch.process, batch.epoch.nonce)) {
                        return Err("identity");
                    }
                    if !epochs.contains_key(&batch.epoch)
                        && epochs.len() >= Limits::default().owners
                    {
                        return Err("owner_capacity");
                    }
                    epochs.insert(batch.epoch, Instant::now());
                    let progress = state.observe(&batch);
                    let operations = if progress.status == Status::Comparing {
                        business_operations(&batch.events)
                    } else {
                        0
                    };
                    let mut report = diagnostics
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    report.batches += 1;
                    report.operations +=
                        u64::try_from(operations).map_err(|_| "operation_count")?;
                    report.events +=
                        u64::try_from(batch.events.len()).map_err(|_| "event_count")?;
                    Some(batch.epoch)
                }
                Frame::Invalid {
                    epoch,
                    reason,
                    last_admitted,
                } => {
                    if identity != Some((epoch.process, epoch.nonce)) {
                        return Err("identity");
                    }
                    if !epochs.contains_key(&epoch) && epochs.len() >= Limits::default().owners {
                        return Err("owner_capacity");
                    }
                    epochs.insert(epoch, Instant::now());
                    state.invalidate(epoch, InvalidReason::Transport);
                    diagnostics
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .producer_invalid
                        .insert(epoch, (reason, last_admitted));
                    Some(epoch)
                }
            }
        };
        let mut expired = false;
        let now = Instant::now();
        for (epoch, last) in epochs.iter() {
            if now.duration_since(*last) > STALE_DEADLINE
                && state.progress(*epoch).status == Status::Comparing
            {
                state.invalidate(*epoch, InvalidReason::Stale);
                expired = true;
            }
        }
        publish(
            state,
            epochs,
            diagnostics,
            if expired { None } else { changed },
        );
        if last_report.elapsed() >= Duration::from_secs(10) {
            log_progress(diagnostics);
            last_report = Instant::now();
        }
    }
}
fn log_progress(diagnostics: &Diagnostics) {
    let report = diagnostics.snapshot();
    let invalid = report
        .owners
        .values()
        .filter(|p| matches!(p.status, Status::Invalid(_)))
        .count();
    eprintln!(
        "routing_shadow native_owners={} factors_compared={} selection=false scheduler=false owners={} batches={} events={} invalid={invalid}",
        report.native_owners.len(),
        report.evaluations,
        report.owners.len(),
        report.batches,
        report.events
    );
}

fn consume_native(
    frame: &[u8],
    epoch: Epoch,
    state: &mut LiveState,
    epochs: &mut BTreeMap<Epoch, Instant>,
    diagnostics: &Diagnostics,
    staging: usize,
) -> Result<Option<Epoch>, &'static str> {
    let origin = state.native_coverage(epoch).map(|coverage| coverage.origin);
    let owner = match crate::native::decode(frame, origin).map_err(|_| "native_schema")? {
        crate::native::Frame::Coverage(coverage) => {
            state
                .install_native(coverage)
                .map_err(|_| "native_coverage")?;
            diagnostics
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .native_owners
                .insert(epoch);
            None
        }
        crate::native::Frame::Evaluation(e) => {
            if !epochs.contains_key(&epoch) && epochs.len() >= Limits::default().owners {
                return Err("owner_capacity");
            }
            epochs.insert(epoch, Instant::now());
            let progress = state.observe_native(&e, staging);
            if progress.status == Status::Comparing {
                let mut report = diagnostics
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                report.evaluations += 1;
                if e.entry == control_router::shadow::native::Entry::Config {
                    report.native_configurations += 1;
                }
            }
            Some(epoch)
        }
    };
    let mut report = diagnostics
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    report.native_retained_bytes = state.native_retained_bytes();
    report.native_peak_bytes = state.native_peak_bytes();
    Ok(owner)
}

fn business_operations(events: &[control_router::shadow::live::LiveEvent]) -> usize {
    events
        .iter()
        .filter(|event| {
            matches!(
                event,
                control_router::shadow::live::LiveEvent::Lifecycle {
                    event: Event::Reserve { .. }
                        | Event::Created { .. }
                        | Event::Redirect { .. }
                        | Event::Redirected { .. }
                        | Event::Closing { .. }
                        | Event::Closed(_)
                        | Event::Rehydrate { .. },
                    ..
                }
            )
        })
        .count()
}

fn publish(
    state: &LiveState,
    epochs: &BTreeMap<Epoch, Instant>,
    diagnostics: &Diagnostics,
    only: Option<Epoch>,
) {
    let mut report = diagnostics
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for epoch in epochs
        .keys()
        .filter(|epoch| only.is_none_or(|key| key == **epoch))
    {
        let progress = state.progress(*epoch);
        if matches!(progress.status, Status::Invalid(_))
            && report
                .owners
                .get(epoch)
                .is_none_or(|old| !matches!(old.status, Status::Invalid(_)))
        {
            eprintln!(
                "routing_shadow owner={} process={} compared={} invalid={:?} producer={:?}",
                epoch.owner,
                epoch.process,
                progress.compared_sequence,
                progress.status,
                report.producer_invalid.get(epoch)
            );
        }
        report.owners.insert(*epoch, progress);
        let totals = state.totals(*epoch).unwrap_or_default();
        let previous = report
            .totals_by_owner
            .insert(*epoch, totals)
            .unwrap_or_default();
        report.score = report.score - previous.0 + totals.0;
        report.physical = report.physical - previous.1 + totals.1;
    }
}

#[cfg(test)]
#[path = "consumer_tests.rs"]
mod tests;

async fn read_frame(
    stream: &mut UnixStream,
    state: &mut LiveState,
) -> Result<Vec<u8>, &'static str> {
    let mut prefix = [0; 4];
    timeout(STALE_DEADLINE, stream.read_exact(&mut prefix))
        .await
        .map_err(|_| "stale")?
        .map_err(|_| "read")?;
    let size = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| "size")?;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err("size");
    }
    let staging = (size + 4)
        .checked_mul(crate::native::DECODE_MULTIPLIER)
        .ok_or("history_capacity")?;
    if !state.native_admit_stage(staging) {
        return Err("history_capacity");
    }
    // Admission precedes allocation. The frame and decoder staging are released
    // before the next read; no consumer backlog exists.
    let mut frame = vec![0; size + 4];
    frame[..4].copy_from_slice(&prefix);
    timeout(
        Duration::from_millis(500),
        stream.read_exact(&mut frame[4..]),
    )
    .await
    .map_err(|_| "body_timeout")?
    .map_err(|_| "body")?;
    Ok(frame)
}
