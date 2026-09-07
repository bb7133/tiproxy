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

use super::*;
use crate::{CombinedFence, HttpTarget};

type TestError = Box<dyn std::error::Error + Send + Sync>;

#[test]
fn metric_targets_are_bounded_origin_form() -> Result<(), TestError> {
    for target in [
        "",
        "metrics",
        "http://host/metrics",
        "//host/metrics",
        "/a#b",
        "/a b",
        "/a\r\nHost: other",
        "/é",
    ] {
        assert!(
            HttpTarget::new(target).is_err(),
            "unsafe target accepted: {target:?}"
        );
    }
    assert!(HttpTarget::new(format!("/{}", "a".repeat(8192))).is_err());
    assert!(HttpTarget::new(format!("/{}", "a".repeat(8191))).is_ok());
    for target in [
        "/metrics",
        "/api/backend/metrics?cluster=a%2Fb%26c",
        "/api/v1/query?query=rate%28cpu%5B1m%5D%29",
    ] {
        assert_eq!(HttpTarget::new(target)?.as_str(), target);
    }
    assert_eq!(HttpTarget::status().as_str(), "/status");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metric_target_preserves_explicit_dns_tls_sni_and_large_bounded_body()
-> Result<(), TestError> {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (_ca, issuer) = make_ca("test-ca");
        let (cert, key) = make_leaf(&issuer, "backend", "svc.test", true);
        let dns = spawn_dns(vec![Ipv4Addr::LOCALHOST], Vec::new()).await;
        let expected = vec![b'x'; 96 * 1024];
        let (addr, captured) = spawn_server(
            Some(server_acceptor(&cert, &key, None, rustls::ALL_VERSIONS)),
            Response::Ok200(expected.clone()),
        )
        .await;
        let (_registry, lease) = owner_lease();
        let client = ClusterHttpClient::from_cluster_material(
            &ns_config(dns, Some(skip_ca_tls(&[], None, None))),
            lease.token(),
            policy(Duration::from_secs(2), MAX_HTTP_RESPONSE_BYTES),
        )?;
        let source = GenerationGate::new();
        let work = GenerationGate::new();
        let target = HttpTarget::new("/api/backend/metrics?cluster=a%2Fb%26c")?;
        assert_eq!(
            client
                .get_target_once(
                    "svc.test",
                    addr.port(),
                    &target,
                    &CombinedFence::new(&source, &work)
                )
                .await?
                .as_ref(),
            expected
        );
        let observed = lock(&captured);
        assert_eq!(observed.sni.as_deref(), Some("svc.test"));
        assert_eq!(
            observed.host_header.as_deref(),
            Some(format!("svc.test:{}", addr.port()).as_str())
        );
        assert_eq!(
            observed.request_line.as_deref(),
            Some("GET /api/backend/metrics?cluster=a%2Fb%26c HTTP/1.1"),
            "METRIC_TARGET_WIRE"
        );
        Ok::<_, TestError>(())
    })
    .await??;
    Ok(())
}

fn spawn_metric_probe(
    client: ClusterHttpClient,
    host: &str,
    port: u16,
    source: GenerationGate,
    work: GenerationGate,
) -> tokio::task::JoinHandle<Result<hyper::body::Bytes, ClusterHttpError>> {
    let host = host.to_owned();
    tokio::spawn(async move {
        let target = HttpTarget::new("/metrics")?;
        client
            .get_target_once(&host, port, &target, &CombinedFence::new(&source, &work))
            .await
    })
}

#[tokio::test]
async fn metric_either_fence_prevents_admission_and_retry_io() -> Result<(), TestError> {
    let (_registry, lease) = owner_lease();
    let client = plaintext_client(&lease, Duration::from_secs(2));
    for revoke_work in [false, true] {
        let source = GenerationGate::new();
        let work = GenerationGate::new();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        if revoke_work {
            work.revoke();
        } else {
            source.revoke();
        }
        for _attempt in 0..2 {
            let result = spawn_metric_probe(
                client.clone(),
                "127.0.0.1",
                port,
                source.clone(),
                work.clone(),
            )
            .await?;
            assert!(
                matches!(result, Err(ClusterHttpError::Fenced)),
                "METRIC_ADMISSION_FENCE: {result:?}"
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err(),
            "METRIC_ADMISSION_ZERO_IO"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metric_either_fence_wins_dns_tls_and_body_failure() -> Result<(), TestError> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (_registry, lease) = owner_lease();
        for revoke_work in [false, true] {
            for stage in ["dns", "tls", "body"] {
                let source = GenerationGate::new();
                let work = GenerationGate::new();
                let (dns, query_received, dns_release) = spawn_gated_dns().await;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let port = listener.local_addr()?.port();
                let entered = Arc::new(Notify::new());
                let release = Arc::new(Notify::new());
                let (config, host, server) = match stage {
                    "dns" => (ns_config(dns, None), "svc.invalid", None),
                    "tls" => (
                        tls_config(skip_ca_tls(&[], None, None)),
                        "127.0.0.1",
                        Some(tokio::spawn(serve_gated_tls(
                            listener,
                            None,
                            Arc::clone(&entered),
                            Arc::clone(&release),
                            Arc::new(AtomicUsize::new(0)),
                        ))),
                    ),
                    _ => (
                        plaintext_config(),
                        "127.0.0.1",
                        Some(tokio::spawn(serve_gated_body(
                            listener,
                            b"partial".to_vec(),
                            Arc::clone(&entered),
                            Arc::clone(&release),
                            true,
                        ))),
                    ),
                };
                let client = ClusterHttpClient::from_cluster_material(
                    &config,
                    lease.token(),
                    policy(Duration::from_secs(2), MAX_HTTP_RESPONSE_BYTES),
                )?;
                let probe = spawn_metric_probe(client, host, port, source.clone(), work.clone());
                if stage == "dns" {
                    query_received.notified().await;
                } else {
                    entered.notified().await;
                }
                if revoke_work {
                    work.revoke();
                } else {
                    source.revoke();
                }
                dns_release.store(true, Ordering::SeqCst);
                release.notify_one();
                let result = probe.await?;
                assert!(
                    matches!(result, Err(ClusterHttpError::Fenced)),
                    "METRIC_{stage}_FENCE work={revoke_work}: {result:?}"
                );
                if let Some(server) = server {
                    server.await?;
                }
            }
        }
        Ok::<_, TestError>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn metric_system_http_target_and_cancel_close_real_connection() -> Result<(), TestError> {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (_registry, lease) = owner_lease();
        let client = ClusterHttpClient::system_http(
            lease.token(),
            policy(Duration::from_secs(2), MAX_HTTP_RESPONSE_BYTES),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let entered = Arc::new(Notify::new());
        let server_entered = Arc::clone(&entered);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await;
            server_entered.notify_one();
            let mut byte = [0u8; 1];
            let eof = stream.read(&mut byte).await?;
            Ok::<_, TestError>((head, eof))
        });
        let source = GenerationGate::new();
        let task = tokio::spawn(async move {
            client
                .get_target_once(
                    "localhost",
                    port,
                    &HttpTarget::new("/api/v1/query?query=up%7Bjob%3D%22tidb%22%7D")?,
                    &source,
                )
                .await
        });
        entered.notified().await;
        task.abort();
        assert!(task.await.is_err_and(|error| error.is_cancelled()));
        let (_head, eof) = server.await??;
        assert_eq!(eof, 0, "METRIC_CANCEL_SOCKET_CLOSED");
        Ok::<_, TestError>(())
    })
    .await??;
    Ok(())
}
