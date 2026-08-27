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

//! Minimal readiness endpoint for the integration topology (DPL-07).
//!
//! One GET on the configured port answers `200` once a configuration
//! generation has been applied — the SQL listeners are bound and
//! serving — and `503` before that. The HTTP/1.0 responder is
//! hand-rolled over the runtime's own socket types so the supply
//! chain gains no HTTP dependency for a health probe.

use std::time::Duration;

use dataplane::{DataplaneServingHandle, GenerationStatusSnapshot};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Serves readiness probes until the listener errors or the task is
/// aborted by the composition's shutdown.
/// Probes are handled INLINE — no per-connection task is ever spawned,
/// so aborting this one task leaves nothing detached. The response
/// depends only on the serving state, so it is written IMMEDIATELY on
/// accept: a prober that never sends a byte cannot head-of-line-block
/// later probes, and the write itself is deadline-bounded so a
/// non-reading peer cannot either.
pub async fn serve(listener: TcpListener, serving: DataplaneServingHandle) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let response = render(&serving.status(), serving.is_serving().await);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            stream.write_all(response.as_bytes()),
        )
        .await;
        let _ = stream.shutdown().await;
    }
}

/// Renders the full HTTP response for one probe: ready requires BOTH an
/// applied generation AND a live SQL owner still accepting — after a
/// drain begins or the owner exits, the probe turns not-ready even
/// though a generation was applied earlier.
fn render(status: &GenerationStatusSnapshot, serving_live: bool) -> String {
    let ready = status.applied_generation > 0 && serving_live;
    let (code, reason, state) = if ready {
        (200, "OK", "OK")
    } else {
        (503, "Service Unavailable", "NOT_READY")
    };
    let body = format!(
        "{{\"status\":\"{state}\",\"applied_generation\":{}}}",
        status.applied_generation
    );
    format!(
        "HTTP/1.0 {code} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(applied: u64) -> GenerationStatusSnapshot {
        GenerationStatusSnapshot {
            applied_generation: applied,
            ..Default::default()
        }
    }

    #[test]
    fn not_ready_before_the_first_applied_generation() {
        let response = render(&snapshot(0), true);
        assert!(response.starts_with("HTTP/1.0 503 "));
        assert!(response.contains("\"status\":\"NOT_READY\""));
        assert!(response.contains("\"applied_generation\":0"));
    }

    #[test]
    fn not_ready_once_the_sql_owner_is_gone_or_draining() {
        // An applied generation alone is not readiness: after the
        // owner exits or stop-accept begins, the probe must flip back.
        let response = render(&snapshot(3), false);
        assert!(response.starts_with("HTTP/1.0 503 "));
        assert!(response.contains("\"status\":\"NOT_READY\""));
    }

    #[tokio::test]
    async fn idle_probers_cannot_delay_later_probes() {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;

        use tokio::io::AsyncReadExt;

        use dataplane::{DataplaneSnapshotConsumer, SystemMemoryProbe};
        use tokio::net::TcpStream;

        struct NopHandler;
        impl dataplane::ConnectionHandler for NopHandler {
            fn handle(
                &self,
                _connection: dataplane::AcceptedConnection,
            ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                Box::pin(async {})
            }
        }
        let (_consumer, serving) = DataplaneSnapshotConsumer::new(
            Arc::new(SystemMemoryProbe::new()),
            Arc::new(NopHandler),
        );
        let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)).await else {
            unreachable!("ephemeral bind")
        };
        let Ok(address) = listener.local_addr() else {
            unreachable!("bound address")
        };
        let server = tokio::spawn(serve(listener, serving));

        // Several probers that never send a byte...
        let mut idle = Vec::new();
        for _ in 0..5 {
            let Ok(connection) = TcpStream::connect(address).await else {
                unreachable!("idle connect")
            };
            idle.push(connection);
        }
        // ...must not delay a real probe: the response is written on
        // accept, within one write deadline, not after N read windows.
        let Ok(mut probe) = TcpStream::connect(address).await else {
            unreachable!("probe connect")
        };
        let mut body = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(3), async {
            probe.read_to_end(&mut body).await
        })
        .await;
        assert!(
            read.is_ok(),
            "the probe answered promptly despite idle peers"
        );
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.starts_with("HTTP/1.0 503 "),
            "unbound consumer: {text}"
        );
        server.abort();
        drop(idle);
    }

    #[test]
    fn ready_once_a_generation_is_applied() {
        let response = render(&snapshot(3), true);
        assert!(response.starts_with("HTTP/1.0 200 OK"));
        assert!(response.contains("\"status\":\"OK\""));
        assert!(response.contains("\"applied_generation\":3"));
    }
}
