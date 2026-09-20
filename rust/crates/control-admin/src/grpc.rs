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

//! The `diagnosticspb.Diagnostics` gRPC service the Go API registers on its
//! HTTP port, served on the same Rust admin listener. Like gin's
//! `grpcServer` middleware, a request is handed to gRPC only when it is
//! HTTP/2 with a `Content-Type` starting with `application/grpc`; every
//! other request continues to the HTTP routes.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use control_external::diagnostics::diagnostics_server::{Diagnostics, DiagnosticsServer};
use control_external::diagnostics::{
    SearchLogRequest, SearchLogResponse, ServerInfoRequest, ServerInfoResponse,
};
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::diagnostics;

/// Go `sysutil.NewDiagnosticsServer(logFile)`: `SearchLog` scans the
/// configured log file's directory; `ServerInfo` is slice 4c.
#[derive(Debug, Clone)]
pub struct DiagnosticsService {
    /// The process log file; `None` mirrors Go's empty `log.log-file.filename`.
    log_file: Option<PathBuf>,
}

impl DiagnosticsService {
    /// Creates the service over the process log file path.
    #[must_use]
    pub const fn new(log_file: Option<PathBuf>) -> Self {
        Self { log_file }
    }

    /// The tonic server wrapper (cloneable, shared by every connection).
    #[must_use]
    pub fn server(self) -> DiagnosticsServer<Self> {
        DiagnosticsServer::new(self)
    }
}

/// Stream of `SearchLogResponse` batches produced by a blocking scan task.
pub struct BatchStream {
    receiver: mpsc::Receiver<Result<SearchLogResponse, Status>>,
}

impl Stream for BatchStream {
    type Item = Result<SearchLogResponse, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

#[tonic::async_trait]
impl Diagnostics for DiagnosticsService {
    type search_logStream = BatchStream;

    async fn search_log(
        &self,
        request: Request<SearchLogRequest>,
    ) -> Result<Response<Self::search_logStream>, Status> {
        let request = request.into_inner();
        let path = self.log_file.clone().unwrap_or_default();
        // Go answers resolution errors as the stream's status and streams
        // batches as the scan produces them; the client dropping the stream
        // (its context) stops the scan. The blocking scan lives on the
        // blocking pool; a bounded channel keeps its lead small.
        let (sender, receiver) = mpsc::channel(4);
        tokio::task::spawn_blocking(move || {
            // The response stream is dropped when the client cancels; the
            // scan polls that where Go polls `ctx.Done()`.
            let probe = {
                let sender = sender.clone();
                move || sender.is_closed()
            };
            let outcome = diagnostics::search(&path, &request, &probe, &mut |messages| {
                sender
                    .blocking_send(Ok(SearchLogResponse { messages }))
                    .map_err(|_| diagnostics::Cancelled)
            });
            if let Err(error) = outcome {
                let _ = sender.blocking_send(Err(Status::unknown(error.0)));
            }
        });
        Ok(Response::new(BatchStream { receiver }))
    }

    async fn server_info(
        &self,
        _request: Request<ServerInfoRequest>,
    ) -> Result<Response<ServerInfoResponse>, Status> {
        // Slice 4c: the Go item inventory is fixed first (declared).
        Err(Status::unimplemented(
            "server_info is not available on the Rust management plane yet",
        ))
    }
}

/// Whether gin's `grpcServer` middleware would take this request.
#[must_use]
pub fn is_grpc(request: &http::Request<axum::body::Body>) -> bool {
    request.version() == http::Version::HTTP_2
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/grpc"))
}

/// Shared gRPC service handle stored in the admin app state.
pub type SharedGrpc = Arc<DiagnosticsServer<DiagnosticsService>>;
