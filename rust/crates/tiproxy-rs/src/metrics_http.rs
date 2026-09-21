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
//! close. Only a head that actually ended (blank line) with a well-formed
//! `METHOD TARGET HTTP/1.x` request line reaches the registry; a truncated,
//! timed-out, or oversized head is rejected. Connections are handled inline
//! with deadlines, so aborting this one task leaves nothing detached and a
//! silent peer can delay, but never block, later scrapes.

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
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8; escaping=underscores";

/// Outcome of reading one request head.
#[derive(Debug, PartialEq, Eq)]
enum RequestHead {
    /// The full head (through the blank line) arrived within the bounds.
    Complete(String),
    /// The peer closed or the deadline passed before the head ended.
    Truncated,
    /// The head exceeded [`MAX_REQUEST_HEAD`] without ending.
    TooLarge,
}

/// Serves scrapes until the listener errors or the task is aborted.
pub async fn serve(listener: TcpListener, registry: Arc<MetricsRegistry>) {
    let mut head = vec![0_u8; MAX_REQUEST_HEAD];
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let request = read_request_head(&mut stream, &mut head).await;
        let response = respond(&request, &registry);
        let _ = tokio::time::timeout(IO_DEADLINE, stream.write_all(response.as_bytes())).await;
        let _ = stream.shutdown().await;
    }
}

/// Reads until the blank line that ends the request head. Only a head that
/// actually ended is `Complete`; EOF or the deadline before that is
/// `Truncated`, and filling the buffer without an end is `TooLarge`.
async fn read_request_head(stream: &mut tokio::net::TcpStream, buffer: &mut [u8]) -> RequestHead {
    let mut filled = 0;
    let deadline = tokio::time::sleep(IO_DEADLINE);
    tokio::pin!(deadline);
    loop {
        if filled >= buffer.len() {
            return RequestHead::TooLarge;
        }
        tokio::select! {
            () = &mut deadline => return RequestHead::Truncated,
            read = stream.read(&mut buffer[filled..]) => {
                match read {
                    Ok(0) | Err(_) => return RequestHead::Truncated,
                    Ok(n) => {
                        filled += n;
                        if head_ended(&buffer[..filled]) {
                            return RequestHead::Complete(
                                String::from_utf8_lossy(&buffer[..filled]).into_owned(),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn head_ended(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == b"\r\n\r\n") || bytes.windows(2).any(|w| w == b"\n\n")
}

/// Builds the full HTTP response for one request head. Only a complete head
/// with a well-formed `METHOD TARGET HTTP/1.x` request line can reach the
/// exposition; everything else is rejected without reading the registry.
fn respond(request: &RequestHead, registry: &MetricsRegistry) -> String {
    let request = match request {
        RequestHead::Complete(request) => request,
        RequestHead::Truncated => {
            return simple(400, "Bad Request", "incomplete request head\n");
        }
        RequestHead::TooLarge => {
            return simple(
                431,
                "Request Header Fields Too Large",
                "request head too large\n",
            );
        }
    };
    let mut parts = request.lines().next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return simple(400, "Bad Request", "malformed request line\n");
    };
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return simple(400, "Bad Request", "unsupported HTTP version\n");
    }
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

    fn complete(text: &str) -> RequestHead {
        RequestHead::Complete(text.to_owned())
    }

    #[test]
    fn routes_metrics_paths_and_rejects_others() {
        let registry = MetricsRegistry::new();
        let ok = respond(
            &complete("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"),
            &registry,
        );
        assert!(ok.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(ok.contains(CONTENT_TYPE));
        assert!(ok.contains("# TYPE tiproxy_server_connections gauge\n"));
        let alias = respond(
            &complete("GET /api/metrics?x=1 HTTP/1.0\r\n\r\n"),
            &registry,
        );
        assert!(alias.starts_with("HTTP/1.0 200 OK\r\n"));
        let head = respond(&complete("HEAD /metrics HTTP/1.1\r\n\r\n"), &registry);
        assert!(head.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        for (request, status) in [
            ("POST /metrics HTTP/1.1\r\n\r\n", "HTTP/1.0 405"),
            ("GET /health HTTP/1.1\r\n\r\n", "HTTP/1.0 404"),
            ("garbage\r\n\r\n", "HTTP/1.0 400"),
            ("GET /metrics\r\n\r\n", "HTTP/1.0 400"),
            ("GET /metrics HTTP/2\r\n\r\n", "HTTP/1.0 400"),
            ("GET /metrics HTTP/1.bad\r\n\r\n", "HTTP/1.0 400"),
            ("GET /metrics HTTP/1.10\r\n\r\n", "HTTP/1.0 400"),
            ("GET  /metrics HTTP/1.1\r\n\r\n", "HTTP/1.0 400"),
            ("GET /metrics HTTP/1.1 extra\r\n\r\n", "HTTP/1.0 400"),
        ] {
            assert!(
                respond(&complete(request), &registry).starts_with(status),
                "{request:?}"
            );
        }
        assert!(respond(&RequestHead::Truncated, &registry).starts_with("HTTP/1.0 400"));
        assert!(respond(&RequestHead::TooLarge, &registry).starts_with("HTTP/1.0 431"));
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fragmented_heads_complete_but_truncated_and_oversized_ones_do_not() {
        let registry = Arc::new(MetricsRegistry::new());
        let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)).await else {
            unreachable!("ephemeral bind")
        };
        let Ok(address) = listener.local_addr() else {
            unreachable!("local addr")
        };
        let task = tokio::spawn(serve(listener, Arc::clone(&registry)));
        // A request split across two writes is still one complete head.
        let Ok(mut fragmented) = tokio::net::TcpStream::connect(address).await else {
            unreachable!("connect")
        };
        assert!(fragmented.write_all(b"GET /metrics HT").await.is_ok());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            fragmented
                .write_all(b"TP/1.1\r\nHost: x\r\n\r\n")
                .await
                .is_ok()
        );
        let mut response = String::new();
        assert!(fragmented.read_to_string(&mut response).await.is_ok());
        assert!(response.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
        // A request line without its terminating blank line, then EOF, is
        // truncated: it must not be served as a scrape.
        let Ok(mut truncated) = tokio::net::TcpStream::connect(address).await else {
            unreachable!("connect")
        };
        assert!(
            truncated
                .write_all(b"GET /metrics HTTP/1.1\r\n")
                .await
                .is_ok()
        );
        assert!(truncated.shutdown().await.is_ok());
        let mut response = String::new();
        assert!(truncated.read_to_string(&mut response).await.is_ok());
        assert!(response.starts_with("HTTP/1.0 400"), "{response}");
        // A head that never ends within the bound is rejected as too large.
        let Ok(mut oversized) = tokio::net::TcpStream::connect(address).await else {
            unreachable!("connect")
        };
        let filler = format!(
            "GET /metrics HTTP/1.1\r\nX: {}\r\n",
            "y".repeat(MAX_REQUEST_HEAD)
        );
        let _ = oversized.write_all(filler.as_bytes()).await;
        let mut response = String::new();
        // The server stops reading at the bound and closes; depending on how
        // much of the flood was still queued, the peer sees the 431 or a
        // reset. Either way no exposition was served.
        match oversized.read_to_string(&mut response).await {
            Ok(_) => assert!(response.starts_with("HTTP/1.0 431"), "{response}"),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ),
                "{error}"
            ),
        }
        assert!(
            !response.contains("# TYPE"),
            "no exposition for an oversized head"
        );
        task.abort();
    }
}
