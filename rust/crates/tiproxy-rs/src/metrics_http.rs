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

//! Native Prometheus exposition endpoint (CP-ADMIN prerequisite B0).
//!
//! `GET /metrics` (and the Go-compatible alias `GET /api/metrics`) renders the
//! process-local [`MetricsRegistry`] as `text/plain; version=0.0.4`, the same
//! families the Go `promhttp` handler publishes for the merged Rust deltas.
//! Like the readiness probe, the HTTP/1.0 responder is hand-rolled over the
//! runtime's socket types: one bounded read of the request head, one write,
//! close. Connections are handled inline with deadlines, so aborting this one
//! task leaves nothing detached and a silent peer can delay, but never block,
//! later scrapes.

use std::sync::Arc;
use std::time::Duration;

use dataplane::MetricsRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Longest a peer may take to send its request head or drain the response.
const IO_DEADLINE: Duration = Duration::from_secs(2);
/// Largest request head accepted; scrapers send a few hundred bytes.
const MAX_REQUEST_HEAD: usize = 4 * 1024;
/// Exposition content type expected by Prometheus for the text format.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Serves scrapes until the listener errors or the task is aborted.
pub async fn serve(listener: TcpListener, registry: Arc<MetricsRegistry>) {
    let mut head = vec![0_u8; MAX_REQUEST_HEAD];
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let request = read_request_head(&mut stream, &mut head).await;
        let response = respond(request.as_deref(), &registry);
        let _ = tokio::time::timeout(IO_DEADLINE, stream.write_all(response.as_bytes())).await;
        let _ = stream.shutdown().await;
    }
}

/// Reads until the end of the request head, the buffer limit, EOF, or the
/// deadline; returns the head as text (lossily) or `None` when nothing usable
/// arrived.
async fn read_request_head(
    stream: &mut tokio::net::TcpStream,
    buffer: &mut [u8],
) -> Option<String> {
    let mut filled = 0;
    let deadline = tokio::time::sleep(IO_DEADLINE);
    tokio::pin!(deadline);
    loop {
        if filled >= buffer.len() {
            break;
        }
        tokio::select! {
            () = &mut deadline => break,
            read = stream.read(&mut buffer[filled..]) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        filled += n;
                        if buffer[..filled].windows(4).any(|w| w == b"\r\n\r\n")
                            || buffer[..filled].windows(2).any(|w| w == b"\n\n")
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
    if filled == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buffer[..filled]).into_owned())
}

/// Builds the full HTTP response for one request head.
fn respond(request: Option<&str>, registry: &MetricsRegistry) -> String {
    let Some(request) = request else {
        return simple(400, "Bad Request", "missing request line\n");
    };
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return simple(400, "Bad Request", "malformed request line\n");
    };
    let path = target.split('?').next().unwrap_or(target);
    if path != "/metrics" && path != "/api/metrics" {
        return simple(404, "Not Found", "not found\n");
    }
    if method != "GET" && method != "HEAD" {
        return simple(405, "Method Not Allowed", "method not allowed\n");
    }
    let body = registry.render_prometheus_text();
    let mut response = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: {CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if method == "GET" {
        response.push_str(&body);
    }
    response
}

fn simple(code: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.0 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_metrics_paths_and_rejects_others() {
        let registry = MetricsRegistry::new();
        let ok = respond(Some("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"), &registry);
        assert!(ok.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(ok.contains(CONTENT_TYPE));
        assert!(ok.contains("# TYPE tiproxy_server_connections gauge\n"));
        let alias = respond(Some("GET /api/metrics?x=1 HTTP/1.0\r\n\r\n"), &registry);
        assert!(alias.starts_with("HTTP/1.0 200 OK\r\n"));
        let head = respond(Some("HEAD /metrics HTTP/1.1\r\n\r\n"), &registry);
        assert!(head.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(
            respond(Some("POST /metrics HTTP/1.1\r\n\r\n"), &registry).starts_with("HTTP/1.0 405")
        );
        assert!(
            respond(Some("GET /health HTTP/1.1\r\n\r\n"), &registry).starts_with("HTTP/1.0 404")
        );
        assert!(respond(Some("garbage"), &registry).starts_with("HTTP/1.0 400"));
        assert!(respond(None, &registry).starts_with("HTTP/1.0 400"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serves_a_real_scrape_and_survives_a_silent_peer() {
        let registry = Arc::new(MetricsRegistry::new());
        let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)).await else {
            unreachable!("ephemeral bind")
        };
        let Ok(address) = listener.local_addr() else {
            unreachable!("local addr")
        };
        let task = tokio::spawn(serve(listener, Arc::clone(&registry)));
        // A peer that connects and never sends anything must not block the
        // following scrape beyond the bounded deadline.
        let silent = tokio::net::TcpStream::connect(address).await;
        assert!(silent.is_ok());
        let Ok(mut stream) = tokio::net::TcpStream::connect(address).await else {
            unreachable!("connect")
        };
        assert!(
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .is_ok()
        );
        let mut response = String::new();
        assert!(stream.read_to_string(&mut response).await.is_ok());
        assert!(response.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
        assert!(response.contains("tiproxy_server_create_connection_total 0\n"));
        task.abort();
        drop(silent);
    }
}
