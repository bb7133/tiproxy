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
            if result == Err("stale") {
                for epoch in epochs.keys() {
                    state.invalidate(*epoch, InvalidReason::Stale);
                }
            }
            state.transport_lost();
            publish(&state, &epochs, diagnostics);
            if *shutdown.borrow() {
                break;
            }
            if let Err(reason) = result {
                eprintln!(
                    "routing_shadow lifecycle_only=true factors=false selection=false scheduler=false interval_invalid={reason}"
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
                    "routing_shadow lifecycle_only=true factors=false selection=false scheduler=false connection_unavailable=true transport_errors={}",
                    report.transport_errors
                );
            }
        }
        tokio::select! {_=shutdown.changed()=>break,()=tokio::time::sleep(Duration::from_millis(500))=>{}}
    }
    state.transport_lost();
    publish(&state, &epochs, diagnostics);
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
        let frame = read_frame(stream).await?;
        match live::decode(&frame).map_err(|_| "schema")? {
            Frame::Coverage { process, nonce } => {
                if identity.replace((process, nonce)).is_some() {
                    return Err("duplicate_coverage");
                }
            }
            Frame::Batch(batch) => {
                if identity != Some((batch.epoch.process, batch.epoch.nonce)) {
                    return Err("identity");
                }
                if !epochs.contains_key(&batch.epoch) && epochs.len() >= Limits::default().owners {
                    return Err("owner_capacity");
                }
                epochs.insert(batch.epoch, Instant::now());
                let progress = state.observe(&batch);
                let operations = if progress.status == Status::Comparing {
                    batch
                        .events
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
                } else {
                    0
                };
                let mut report = diagnostics
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                report.batches += 1;
                report.operations += u64::try_from(operations).map_err(|_| "operation_count")?;
                report.events += u64::try_from(batch.events.len()).map_err(|_| "event_count")?;
            }
            Frame::Invalid { epoch, .. } => {
                if identity != Some((epoch.process, epoch.nonce)) {
                    return Err("identity");
                }
                if !epochs.contains_key(&epoch) && epochs.len() >= Limits::default().owners {
                    return Err("owner_capacity");
                }
                epochs.insert(epoch, Instant::now());
                state.invalidate(epoch, InvalidReason::Transport);
            }
        }
        let now = Instant::now();
        for (epoch, last) in epochs.iter() {
            if now.duration_since(*last) > STALE_DEADLINE
                && state.progress(*epoch).status == Status::Comparing
            {
                state.invalidate(*epoch, InvalidReason::Stale);
            }
        }
        publish(state, epochs, diagnostics);
        if last_report.elapsed() >= Duration::from_secs(10) {
            let report = diagnostics.snapshot();
            let invalid = report
                .owners
                .values()
                .filter(|p| matches!(p.status, Status::Invalid(_)))
                .count();
            eprintln!(
                "routing_shadow lifecycle_only=true factors=false selection=false scheduler=false owners={} batches={} events={} invalid={invalid}",
                report.owners.len(),
                report.batches,
                report.events
            );
            last_report = Instant::now();
        }
    }
}
fn publish(state: &LiveState, epochs: &BTreeMap<Epoch, Instant>, diagnostics: &Diagnostics) {
    let mut report = diagnostics
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    report.score = 0;
    report.physical = 0;
    for epoch in epochs.keys() {
        let progress = state.progress(*epoch);
        if matches!(progress.status, Status::Invalid(_))
            && report
                .owners
                .get(epoch)
                .is_none_or(|old| !matches!(old.status, Status::Invalid(_)))
        {
            eprintln!(
                "routing_shadow lifecycle_only=true owner={} process={} compared={} invalid={:?}",
                epoch.owner, epoch.process, progress.compared_sequence, progress.status
            );
        }
        report.owners.insert(*epoch, progress);
        if let Some((score, physical)) = state.totals(*epoch) {
            report.score += score;
            report.physical += physical;
        }
    }
}

#[cfg(test)]
#[path = "consumer_tests.rs"]
mod tests;

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
    let mut prefix = [0; 4];
    timeout(STALE_DEADLINE, stream.read_exact(&mut prefix))
        .await
        .map_err(|_| "stale")?
        .map_err(|_| "read")?;
    let size = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| "size")?;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err("size");
    }
    // One owned frame, released before the next read. No consumer backlog.
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
