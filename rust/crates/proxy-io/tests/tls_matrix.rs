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

//! WIRE-04 acceptance matrix: handshake outcomes, buffered upgrade, and
//! snapshot-driven last-good reload semantics.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use control_proto::snapshot::SnapshotStore;
use control_proto::v1::{
    ConfigSnapshot, KeepalivePolicy, Listener, ProxyProtocolMode, StateSnapshot, TlsPolicy,
};
use proxy_io::tls::{
    TlsSetupError, accept_frontend, build_backend_config, connect_backend, tls_buffer_sizes,
};
use rcgen::{CertificateParams, Issuer, KeyPair, date_time_ymd};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const VALIDATION_TIME_SECONDS: u64 = 1_800_000_000;

struct TestCa {
    ca_cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct LeafPair {
    cert_pem: String,
    key_pem: String,
}

fn make_ca() -> Result<TestCa, Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::new())?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = params.self_signed(&ca_key)?;
    let ca_cert_pem = ca_cert.pem();
    let issuer = Issuer::new(params, ca_key);
    Ok(TestCa {
        ca_cert_pem,
        issuer,
    })
}

fn make_leaf(ca: &TestCa, name: &str, expired: bool) -> Result<LeafPair, Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![name.to_owned()])?;
    if expired {
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
    }
    let cert = params.signed_by(&key, &ca.issuer)?;
    Ok(LeafPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

fn server_config(leaf: &LeafPair) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
    let chain = vec![CertificateDer::from_pem_slice(leaf.cert_pem.as_bytes())?];
    let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes())?;
    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
    ))
}

fn client_config_with_roots(ca_pem: Option<&str>) -> Result<Arc<ClientConfig>, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    if let Some(pem) = ca_pem {
        roots.add(CertificateDer::from_pem_slice(pem.as_bytes())?)?;
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Frontend upgrade with part of the client hello already buffered: the
/// prefix is replayed before the socket, so no handshake byte is lost.
#[tokio::test]
async fn frontend_accept_replays_buffered_prefix() -> Result<(), Box<dyn Error>> {
    let ca = make_ca()?;
    let leaf = make_leaf(&ca, "frontend.local", false)?;
    let config = server_config(&leaf)?;
    let (client_end, mut server_end) = tokio::io::duplex(64 * 1024);

    let client_roots = client_config_with_roots(Some(&ca.ca_cert_pem))?;
    let client = tokio::spawn(async move {
        let connector = TlsConnector::from(client_roots);
        let name = ServerName::try_from("frontend.local".to_owned())?;
        let mut stream = connector.connect(name, client_end).await?;
        stream.write_all(b"ping").await?;
        stream.flush().await?;
        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(reply)
    });

    // Simulate bytes the packet layer had already prefetched: pull the first
    // five client-hello bytes off the socket before starting the upgrade.
    let mut prefetched = vec![0_u8; 5];
    server_end.read_exact(&mut prefetched).await?;
    let mut frontend =
        accept_frontend(server_end, prefetched, config, HANDSHAKE_TIMEOUT, 0).await?;

    assert_eq!(frontend.info.server_name.as_deref(), Some("frontend.local"));
    assert!(frontend.info.protocol_version.is_some());
    assert!(frontend.info.cipher_suite.is_some());
    assert!(!frontend.info.peer_certificate_present);
    assert_eq!(frontend.buffer_sizes, tls_buffer_sizes(0));

    let mut request = [0_u8; 4];
    frontend.stream.read_exact(&mut request).await?;
    assert_eq!(&request, b"ping");
    frontend.stream.write_all(b"pong").await?;
    frontend.stream.flush().await?;
    let reply = client
        .await?
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    assert_eq!(&reply, b"pong");
    Ok(())
}

/// A client without the CA fails the handshake, and the server observes a
/// typed handshake error rather than a hang or a plaintext fallback.
#[tokio::test]
async fn untrusted_ca_is_rejected_on_both_sides() -> Result<(), Box<dyn Error>> {
    let ca = make_ca()?;
    let leaf = make_leaf(&ca, "frontend.local", false)?;
    let config = server_config(&leaf)?;
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);

    let empty_roots = client_config_with_roots(None)?;
    let client = tokio::spawn(async move {
        let connector = TlsConnector::from(empty_roots);
        let name = ServerName::try_from("frontend.local".to_owned())?;
        match connector.connect(name, client_end).await {
            Ok(_) => Err::<String, Box<dyn Error + Send + Sync>>("unexpected success".into()),
            Err(error) => Ok(error.to_string()),
        }
    });

    let server = accept_frontend(server_end, Vec::new(), config, HANDSHAKE_TIMEOUT, 0).await;
    assert!(matches!(server, Err(TlsSetupError::Handshake(_))));
    let client_error = client
        .await?
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    assert!(
        client_error.contains("UnknownIssuer"),
        "unexpected client error: {client_error}"
    );
    Ok(())
}

/// A certificate for another name fails hostname verification.
#[tokio::test]
async fn wrong_hostname_is_rejected() -> Result<(), Box<dyn Error>> {
    let ca = make_ca()?;
    let leaf = make_leaf(&ca, "backend.local", false)?;
    let config = server_config(&leaf)?;
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        accept_frontend(server_end, Vec::new(), config, HANDSHAKE_TIMEOUT, 0).await
    });
    let client = connect_backend(
        client_end,
        "wrong.local",
        client_config_with_roots(Some(&ca.ca_cert_pem))?,
        HANDSHAKE_TIMEOUT,
        0,
    )
    .await;
    let Err(TlsSetupError::Handshake(error)) = client else {
        return Err("expected hostname mismatch".into());
    };
    assert!(
        error.to_string().contains("not valid for name"),
        "unexpected error: {error}"
    );
    drop(server);
    Ok(())
}

/// An expired certificate fails validation.
#[tokio::test]
async fn expired_certificate_is_rejected() -> Result<(), Box<dyn Error>> {
    let ca = make_ca()?;
    let leaf = make_leaf(&ca, "backend.local", true)?;
    let config = server_config(&leaf)?;
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        accept_frontend(server_end, Vec::new(), config, HANDSHAKE_TIMEOUT, 0).await
    });
    let client = connect_backend(
        client_end,
        "backend.local",
        client_config_with_roots(Some(&ca.ca_cert_pem))?,
        HANDSHAKE_TIMEOUT,
        0,
    )
    .await;
    let Err(TlsSetupError::Handshake(error)) = client else {
        return Err("expected expiry failure".into());
    };
    assert!(
        error.to_string().contains("expired"),
        "unexpected error: {error}"
    );
    drop(server);
    Ok(())
}

/// A silent peer trips the handshake deadline with a typed timeout.
#[tokio::test]
async fn handshake_timeout_is_typed() -> Result<(), Box<dyn Error>> {
    let ca = make_ca()?;
    let (client_end, _server_end_held_open) = tokio::io::duplex(64 * 1024);
    let result = connect_backend(
        client_end,
        "backend.local",
        client_config_with_roots(Some(&ca.ca_cert_pem))?,
        Duration::from_millis(200),
        0,
    )
    .await;
    assert!(matches!(result, Err(TlsSetupError::Timeout(_))));
    Ok(())
}

/// An invalid SNI name is rejected before any bytes are written.
#[tokio::test]
async fn invalid_server_name_is_typed() -> Result<(), Box<dyn Error>> {
    let ca = make_ca()?;
    let (client_end, _server_end) = tokio::io::duplex(1024);
    let result = connect_backend(
        client_end,
        "bad name with spaces",
        client_config_with_roots(Some(&ca.ca_cert_pem))?,
        HANDSHAKE_TIMEOUT,
        0,
    )
    .await;
    assert!(matches!(
        result,
        Err(TlsSetupError::InvalidServerName { .. })
    ));
    Ok(())
}

// ---- Snapshot-driven configuration and last-good reload ----

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Result<Self, Box<dyn Error>> {
        let identifier = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tiproxy-wire04-{}-{identifier}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn path_text(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(path.to_str().ok_or("test path is not UTF-8")?.to_owned())
}

fn write_pair(directory: &Path, name: &str, pair: &LeafPair) -> Result<TlsPolicy, Box<dyn Error>> {
    let certificate_path = directory.join(format!("{name}.crt"));
    let private_key_path = directory.join(format!("{name}.key"));
    fs::write(&certificate_path, &pair.cert_pem)?;
    fs::write(&private_key_path, &pair.key_pem)?;
    Ok(TlsPolicy {
        certificate_path: path_text(&certificate_path)?,
        private_key_path: path_text(&private_key_path)?,
        minimum_version: "1.2".to_owned(),
        ..Default::default()
    })
}

fn snapshot(frontend_tls: TlsPolicy, backend_tls: TlsPolicy) -> StateSnapshot {
    let keepalive = KeepalivePolicy {
        enabled: true,
        idle_millis: 60_000,
        probe_count: 5,
        interval_millis: 3_000,
        user_timeout_millis: 15_000,
    };
    StateSnapshot {
        config: Some(ConfigSnapshot {
            high_memory_reject_threshold: 0.9,
            connection_buffer_bytes: 32 * 1024,
            frontend_keepalive: Some(keepalive),
            healthy_backend_keepalive: Some(keepalive),
            unhealthy_backend_keepalive: Some(keepalive),
            proxy_protocol: ProxyProtocolMode::Disabled as i32,
            listeners: vec![Listener {
                address: "127.0.0.1".to_owned(),
                port: 6000,
                name: "sql-0".to_owned(),
            }],
            server_version: "TiProxy-test".to_owned(),
            frontend_tls: Some(frontend_tls),
            backend_tls: Some(backend_tls),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn validation_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(VALIDATION_TIME_SECONDS))
}

/// Connects a TLS client over one duplex end, exchanges `request`/`reply`
/// against the accept side, and verifies both directions.
async fn frontend_echo_exchange(
    config: Arc<ServerConfig>,
    ca_pem: &str,
    request: &'static [u8],
    reply: &'static [u8],
) -> Result<(), Box<dyn Error>> {
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);
    let roots = client_config_with_roots(Some(ca_pem))?;
    let client = tokio::spawn(async move {
        let connector = TlsConnector::from(roots);
        let name = ServerName::try_from("frontend.local".to_owned())?;
        let mut stream = connector.connect(name, client_end).await?;
        stream.write_all(request).await?;
        stream.flush().await?;
        // Stay alive until the server replies, so the duplex half is not
        // dropped while the server still writes post-handshake messages.
        let mut received = vec![0_u8; reply.len()];
        stream.read_exact(&mut received).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(received)
    });
    let mut accepted =
        match accept_frontend(server_end, Vec::new(), config, HANDSHAKE_TIMEOUT, 0).await {
            Ok(accepted) => accepted,
            Err(accept_error) => {
                let client_side = client.await?;
                return Err(
                    format!("accept failed: {accept_error}; client side: {client_side:?}").into(),
                );
            }
        };
    let mut received = vec![0_u8; request.len()];
    accepted.stream.read_exact(&mut received).await?;
    assert_eq!(received, request);
    accepted.stream.write_all(reply).await?;
    accepted.stream.flush().await?;
    let echoed = client
        .await?
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    assert_eq!(echoed, reply);
    Ok(())
}

/// The full acceptance chain: a validated snapshot serves frontend TLS, a
/// failed reload preserves last-good for new sessions while established
/// sessions keep their captured configuration, and a valid new certificate
/// applies to sessions created after it.
#[tokio::test]
async fn snapshot_reload_preserves_last_good_and_applies_new() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let ca = make_ca()?;
    let first_leaf = make_leaf(&ca, "frontend.local", false)?;
    let first = write_pair(directory.path(), "first", &first_leaf)?;
    let backend_skip = TlsPolicy {
        skip_ca_verification: true,
        ..Default::default()
    };
    let store = SnapshotStore::new([directory.path().to_path_buf()])?;
    let generation_one = store.apply(
        1,
        snapshot(first.clone(), backend_skip.clone()),
        validation_time(),
    )?;
    let config_one = generation_one
        .snapshot
        .frontend_server_config
        .clone()
        .ok_or("generation 1 must build a frontend server config")?;

    // An established session captures its Arc and keeps working later.
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);
    let established_roots = client_config_with_roots(Some(&ca.ca_cert_pem))?;
    let established_client = tokio::spawn(async move {
        let connector = TlsConnector::from(established_roots);
        let name = ServerName::try_from("frontend.local".to_owned())?;
        let mut stream = connector.connect(name, client_end).await?;
        stream.write_all(b"before-reload").await?;
        stream.flush().await?;
        let mut reply = [0_u8; 13];
        stream.read_exact(&mut reply).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(reply)
    });
    let mut established = match accept_frontend(
        server_end,
        Vec::new(),
        Arc::clone(&config_one),
        HANDSHAKE_TIMEOUT,
        0,
    )
    .await
    {
        Ok(established) => established,
        Err(accept_error) => {
            let client_side = established_client.await?;
            return Err(
                format!("accept failed: {accept_error}; client side: {client_side:?}").into(),
            );
        }
    };

    // A reload with a mismatched key fails and keeps last-good current.
    let second_leaf = make_leaf(&ca, "frontend.local", false)?;
    let mismatched = TlsPolicy {
        certificate_path: write_pair(directory.path(), "second", &second_leaf)?.certificate_path,
        private_key_path: first.private_key_path.clone(),
        minimum_version: "1.2".to_owned(),
        ..Default::default()
    };
    let failed = store.apply(
        2,
        snapshot(mismatched, backend_skip.clone()),
        validation_time(),
    );
    assert!(failed.is_err(), "mismatched key must be rejected");
    let current = store
        .current()?
        .ok_or("store must retain a last-good snapshot")?;
    assert_eq!(current.generation(), 1);

    // The established session still works after the failed reload.
    let mut request = [0_u8; 13];
    established.stream.read_exact(&mut request).await?;
    assert_eq!(&request, b"before-reload");
    established.stream.write_all(b"still-serving").await?;
    established.stream.flush().await?;
    let reply = established_client
        .await?
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    assert_eq!(&reply, b"still-serving");

    // A valid new certificate applies to sessions created after it.
    let third = write_pair(
        directory.path(),
        "third",
        &make_leaf(&ca, "frontend.local", false)?,
    )?;
    let generation_three = store.apply(3, snapshot(third, backend_skip), validation_time())?;
    let config_three = generation_three
        .snapshot
        .frontend_server_config
        .clone()
        .ok_or("generation 3 must build a frontend server config")?;
    assert!(!Arc::ptr_eq(&config_one, &config_three));
    frontend_echo_exchange(config_three, &ca.ca_cert_pem, b"new", b"k").await?;

    Ok(())
}

/// A backend policy with `skip_ca_verification` accepts a certificate signed
/// by an unknown CA, mirroring Go `InsecureSkipVerify`.
#[tokio::test]
async fn skip_ca_policy_accepts_untrusted_backend() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create()?;
    let ca = make_ca()?;
    let frontend_pair = write_pair(
        directory.path(),
        "frontend",
        &make_leaf(&ca, "frontend.local", false)?,
    )?;
    let backend_skip = TlsPolicy {
        skip_ca_verification: true,
        ..Default::default()
    };
    let store = SnapshotStore::new([directory.path().to_path_buf()])?;
    let applied = store.apply(1, snapshot(frontend_pair, backend_skip), validation_time())?;
    let backend_config = build_backend_config(&applied.snapshot.backend_tls)
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;

    let other_ca = make_ca()?;
    let untrusted_server = server_config(&make_leaf(&other_ca, "backend.local", false)?)?;
    let (client_end, server_end) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        accept_frontend(
            server_end,
            Vec::new(),
            untrusted_server,
            HANDSHAKE_TIMEOUT,
            0,
        )
        .await
    });
    let connected = connect_backend(
        client_end,
        "backend.local",
        backend_config,
        HANDSHAKE_TIMEOUT,
        0,
    )
    .await
    .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    assert!(connected.info.peer_certificate_present);
    drop(server);
    Ok(())
}

/// Throughput smoke benchmark over an in-memory TLS pair.
///
/// Run explicitly with:
/// `cargo test -p proxy-io --test tls_matrix --release -- --ignored bench`
#[tokio::test]
#[ignore = "benchmark; run explicitly in release mode"]
async fn bench_tls_throughput_smoke() -> Result<(), Box<dyn Error>> {
    const TOTAL: usize = 64 * 1024 * 1024;
    const TOTAL_MIB: f64 = 64.0;
    const CHUNK: usize = 32 * 1024;
    let ca = make_ca()?;
    let leaf = make_leaf(&ca, "frontend.local", false)?;
    let config = server_config(&leaf)?;
    let (client_end, server_end) = tokio::io::duplex(256 * 1024);

    let client_roots = client_config_with_roots(Some(&ca.ca_cert_pem))?;
    let writer = tokio::spawn(async move {
        let connector = TlsConnector::from(client_roots);
        let name = ServerName::try_from("frontend.local".to_owned())?;
        let mut stream = connector.connect(name, client_end).await?;
        let chunk = vec![0xa5_u8; CHUNK];
        let mut sent = 0_usize;
        while sent < TOTAL {
            stream.write_all(&chunk).await?;
            sent += CHUNK;
        }
        stream.flush().await?;
        let mut ack = [0_u8; 1];
        stream.read_exact(&mut ack).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let mut frontend =
        accept_frontend(server_end, Vec::new(), config, HANDSHAKE_TIMEOUT, 0).await?;
    let started = std::time::Instant::now();
    let mut buffer = vec![0_u8; CHUNK];
    let mut received = 0_usize;
    while received < TOTAL {
        frontend.stream.read_exact(&mut buffer).await?;
        received += CHUNK;
    }
    let elapsed = started.elapsed();
    frontend.stream.write_all(b"k").await?;
    frontend.stream.flush().await?;
    writer
        .await?
        .map_err(|error| -> Box<dyn Error> { error.to_string().into() })?;
    let throughput = TOTAL_MIB / elapsed.as_secs_f64();
    println!("TLS throughput: {throughput:.1} MiB/s over in-memory duplex");
    assert!(received == TOTAL);
    Ok(())
}
