// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::{io::AsyncWriteExt, net::UnixListener};
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Box<dyn std::error::Error>> {
        let dir = PathBuf::from(format!(
            "/tmp/routing-shadow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let path = dir.join("observer.sock");
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
fn begin(owner: u64) -> Vec<u8> {
    let raw = include_str!("../../../../tests/controlplane/cproute/shadow/v2-begin.json")
        .replace("\"owner\":\"1\"", &format!("\"owner\":\"{owner}\""));
    framed(raw.as_bytes())
}
fn framed(body: &[u8]) -> Vec<u8> {
    let mut bytes = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    bytes.extend(body);
    bytes
}
fn coverage() -> Vec<u8> {
    framed(br#"{"version":2,"kind":"coverage","process":"41","owner":"0","nonce":"43","lifecycle_only":true,"factors":false,"selection":false,"scheduler":false}"#)
}
async fn until(
    d: &Diagnostics,
    predicate: impl Fn(&Report) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    timeout(Duration::from_secs(5), async {
        loop {
            if predicate(&d.snapshot()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}
#[tokio::test]
async fn consumer_disconnect_retains_invalid_owner_and_allows_only_fresh_begin()
-> Result<(), Box<dyn std::error::Error>> {
    let (socket, listener) = Socket::new()?;
    let task = Task::spawn(socket.0.clone());
    let d = task.diagnostics();
    let (mut peer, _) = listener.accept().await?;
    peer.write_all(&coverage()).await?;
    peer.write_all(&begin(1)).await?;
    let old = Epoch {
        process: 41,
        owner: 1,
        nonce: 43,
    };
    let new = Epoch { owner: 2, ..old };
    until(&d, |r| {
        r.owners
            .get(&old)
            .is_some_and(|p| p.status == Status::Comparing)
    })
    .await?;
    drop(peer);
    until(&d, |r| {
        r.owners
            .get(&old)
            .is_some_and(|p| matches!(p.status, Status::Invalid(_)))
    })
    .await?;
    let (mut peer, _) = listener.accept().await?;
    peer.write_all(&coverage()).await?;
    // Replayed old Begin must not repair its interval; a fresh owner is separate.
    peer.write_all(&begin(1)).await?;
    peer.write_all(&begin(2)).await?;
    until(&d, |r| r.owners.contains_key(&new)).await?;
    let report = d.snapshot();
    assert_eq!(report.owners[&old].compared_sequence, 1);
    assert!(matches!(report.owners[&old].status, Status::Invalid(_)));
    assert_eq!(report.owners[&new].status, Status::Comparing);
    timeout(Duration::from_secs(1), task.shutdown()).await?;
    assert!(d.snapshot().stopped);
    Ok(())
}
#[tokio::test]
async fn consumer_rejects_v1_malformed_identity_and_expires_stalled_watermark()
-> Result<(), Box<dyn std::error::Error>> {
    let (socket, listener) = Socket::new()?;
    let task = Task::spawn(socket.0.clone());
    let d = task.diagnostics();
    let (mut peer, _) = listener.accept().await?;
    peer.write_all(&coverage()).await?;
    peer.write_all(&begin(1)).await?;
    let epoch = Epoch {
        process: 41,
        owner: 1,
        nonce: 43,
    };
    until(&d, |r| r.owners.contains_key(&epoch)).await?;
    until(&d, |r| {
        r.owners
            .get(&epoch)
            .is_some_and(|p| p.status == Status::Invalid(InvalidReason::Stale))
    })
    .await?;
    drop(peer);
    let (mut peer, _) = listener.accept().await?;
    peer.write_all(&coverage()).await?;
    peer.write_all(&framed(br#"{"version":1}"#)).await?;
    until(&d, |r| r.transport_errors >= 2).await?;
    assert_eq!(d.snapshot().owners[&epoch].compared_sequence, 1);
    timeout(Duration::from_secs(1), task.shutdown()).await?;
    assert!(d.snapshot().stopped);
    Ok(())
}
#[tokio::test]
async fn consumer_initial_connect_failure_and_public_directory_are_diagnostic_only()
-> Result<(), Box<dyn std::error::Error>> {
    let (socket, _listener) = Socket::new()?;
    let parent = socket.0.parent().ok_or("directory")?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
    let task = Task::spawn(socket.0.clone());
    let d = task.diagnostics();
    until(&d, |r| r.transport_errors > 0).await?;
    assert_eq!(d.snapshot().connections, 0);
    timeout(Duration::from_secs(1), task.shutdown()).await?;
    assert!(d.snapshot().stopped);
    let task = Task::spawn(parent.join("missing.sock"));
    let d = task.diagnostics();
    until(&d, |r| r.transport_errors > 0).await?;
    timeout(Duration::from_secs(1), task.shutdown()).await?;
    assert!(d.snapshot().stopped);
    Ok(())
}

// All cases use the actual owned socket consumer, including the out-of-band
// loss summary whose last_admitted is expressly not compared progress.
#[tokio::test]
async fn consumer_invalid_summary_and_bad_frames_never_advance_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let raw = include_str!("../../../../tests/controlplane/cproute/shadow/v2-begin.json");
    let oversized = u32::try_from(MAX_FRAME_BYTES + 1)?.to_be_bytes().to_vec();
    let mut truncated = 100_u32.to_be_bytes().to_vec();
    truncated.extend(b"{");
    let invalid = br#"{"version":2,"kind":"invalid","process":"41","owner":"1","nonce":"43","lifecycle_only":true,"factors":false,"selection":false,"scheduler":false,"last_admitted":"18446744073709551615","reason":"capacity"}"#;
    for (name, bytes, transport) in [
        ("last_admitted", framed(invalid), false),
        (
            "unpaired_discard",
            framed(
                String::from_utf8_lossy(invalid)
                    .replace("capacity", "unpaired_discard")
                    .as_bytes(),
            ),
            false,
        ),
        (
            "gap",
            framed(
                raw.replace("\"sequence\":\"1\"", "\"sequence\":\"3\"")
                    .replace("\"kind\":\"begin\"", "\"kind\":\"watermark\"")
                    .as_bytes(),
            ),
            false,
        ),
        (
            "wrong_nonce",
            framed(
                raw.replace("\"nonce\":\"43\"", "\"nonce\":\"44\"")
                    .as_bytes(),
            ),
            true,
        ),
        ("oversized", oversized, true),
        ("truncated", truncated, true),
        (
            "unknown",
            framed(
                raw.replace("\"version\":2", "\"version\":2,\"unknown\":0")
                    .as_bytes(),
            ),
            true,
        ),
    ] {
        let (socket, listener) = Socket::new()?;
        let task = Task::spawn(socket.0.clone());
        let d = task.diagnostics();
        let (mut peer, _) = listener.accept().await?;
        peer.write_all(&coverage()).await?;
        peer.write_all(&begin(1)).await?;
        let epoch = Epoch {
            process: 41,
            owner: 1,
            nonce: 43,
        };
        until(&d, |r| r.owners.contains_key(&epoch)).await?;
        peer.write_all(&bytes).await?;
        until(&d, |r| {
            r.owners
                .get(&epoch)
                .is_some_and(|p| matches!(p.status, Status::Invalid(_)))
        })
        .await?;
        let report = d.snapshot();
        if name == "last_admitted" || name == "unpaired_discard" {
            let expected = if name == "unpaired_discard" {
                live::InvalidCause::UnpairedDiscard
            } else {
                live::InvalidCause::Capacity
            };
            assert_eq!(
                report.producer_invalid.get(&epoch),
                Some(&(expected, u64::MAX)),
                "LIVE_PRODUCER_REASON"
            );
        }
        assert_eq!(
            report.owners[&epoch].compared_sequence, 1,
            "LIVE_SOCKET_PROGRESS: {name}"
        );
        assert_eq!(report.operations, 0, "LIVE_SOCKET_PROGRESS: {name}");
        assert_eq!(
            report.transport_errors > 0,
            transport,
            "LIVE_SOCKET_TRANSPORT: {name}"
        );
        timeout(Duration::from_secs(1), task.shutdown()).await?;
        assert!(d.snapshot().stopped, "LIVE_SOCKET_JOIN: {name}");
    }
    Ok(())
}

#[test]
fn incremental_report_preserves_other_owners_and_replaces_one_contribution() {
    use control_router::shadow::live::{AccountWitness, Batch, LiveEvent, Witness};
    let mut state = LiveState::new(Limits::default());
    let mut epochs = BTreeMap::new();
    let diagnostics = Diagnostics(Arc::new(Mutex::new(Report::default())));
    for owner in 1..=2 {
        let epoch = Epoch {
            process: 41,
            owner,
            nonce: 43,
        };
        epochs.insert(epoch, Instant::now());
        reserve_for_report(&mut state, epoch);
        publish(&state, &epochs, &diagnostics, Some(epoch));
    }
    assert_eq!(diagnostics.snapshot().score, 2, "LIVE_INCREMENTAL_TOTALS");
    let epoch = Epoch {
        process: 41,
        owner: 1,
        nonce: 43,
    };
    assert_eq!(
        state
            .observe(&Batch {
                epoch,
                sequence: 6,
                events: vec![LiveEvent::Lifecycle {
                    event: Event::Created {
                        session: 3,
                        operation: 1,
                        success: false
                    },
                    source: 0,
                    target: 0
                }],
                witness: Witness {
                    accounts: vec![AccountWitness {
                        id: 2,
                        score: 0,
                        physical: 0,
                        head: 0,
                        tail: 0
                    }],
                    session: 3,
                    ..Witness::default()
                }
            })
            .status,
        Status::Comparing
    );
    publish(&state, &epochs, &diagnostics, Some(epoch));
    assert_eq!(diagnostics.snapshot().score, 1, "LIVE_INCREMENTAL_TOTALS");
    publish(&state, &epochs, &diagnostics, None);
    assert_eq!(diagnostics.snapshot().score, 1, "LIVE_INCREMENTAL_TOTALS");
}

fn reserve_for_report(state: &mut LiveState, epoch: Epoch) {
    use control_router::shadow::live::{AccountWitness, Batch, LiveEvent, Witness};
    let life = |event| LiveEvent::Lifecycle {
        event,
        source: 0,
        target: 0,
    };
    let account = |score| AccountWitness {
        id: 2,
        score,
        physical: 0,
        head: 0,
        tail: 0,
    };
    for (sequence, events, witness) in [
        (1, vec![life(Event::Begin)], Witness::default()),
        (2, vec![LiveEvent::GroupCreated(1)], Witness::default()),
        (
            3,
            vec![life(Event::Account { id: 2, group: 1 })],
            Witness {
                accounts: vec![account(0)],
                ..Witness::default()
            },
        ),
        (
            4,
            vec![
                life(Event::Open(3)),
                life(Event::Reserve {
                    session: 3,
                    operation: 1,
                    account: 2,
                }),
            ],
            Witness {
                accounts: vec![account(1)],
                session: 3,
                ..Witness::default()
            },
        ),
    ] {
        assert_eq!(
            state
                .observe(&Batch {
                    epoch,
                    sequence,
                    events,
                    witness
                })
                .status,
            Status::Comparing
        );
    }
}
