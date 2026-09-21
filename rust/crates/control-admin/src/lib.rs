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

//! Rust management plane for `TiProxy` (CP-ADMIN #150).
//!
//! The crate reproduces the Go `pkg/server/api` surface on one listener:
//! the same paths, status codes, bounded response bodies, middleware order
//! (rate limit, readiness gate, access log) and the same TLS split, where a
//! configured `security.server-http-tls` leaves only the readiness probe
//! reachable in plaintext. Process state reaches the handlers through
//! [`AdminHooks`]: the crate owns no dataplane, configuration or metrics
//! state and never logs request or response payloads.

pub mod config;
pub mod diagnostics;
pub mod drain;
pub mod grpc;
pub mod health;
pub mod router;
pub mod serve;
pub mod server_info;

pub use config::{AdminFuture, CommitError, ConfigAdmin, MemoryConfigAdmin, SharedConfigAdmin};
pub use drain::{
    DrainAdmin, DrainProgress, DrainRequest, DrainStartError, ScriptedDrainAdmin, SharedDrainAdmin,
};
pub use health::{
    HealthInputs, HealthOverride, HealthResponse, HealthState, go_json_document, go_json_string,
};
pub use router::{
    AdminApp, AdminHooks, DataplaneStatus, RateLimiter, full_router, plaintext_router,
};
pub use serve::{ServeOptions, TlsConfigSource, serve};
