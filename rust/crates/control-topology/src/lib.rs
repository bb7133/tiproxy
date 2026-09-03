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

//! `TiProxy` topology ownership for the Rust control plane.
//!
//! This crate is the single owner of the etcd `/topology/*` and
//! `/keyspaces/tidb/*` keyspace.  It has two responsibilities, mirroring the Go
//! `pkg/manager/infosync` behaviour so a Go/Rust differential stays exact:
//!
//! * **Self-registration** — every `TiProxy` instance publishes its own
//!   `/topology/tiproxy/<addr>/{info,ttl}` under a per-instance etcd lease and
//!   refreshes it, so peers and PD can discover live proxies.  This is a
//!   per-instance responsibility fenced only by the process
//!   [`control_plane::ownership::OwnerToken`]; it is deliberately NOT gated on
//!   control-plane leadership.
//! * **Discovery** — a poll of the `/topology/tidb/` and `/keyspaces/tidb/`
//!   prefixes produces a liveness-filtered [`TopologySnapshot`] of backend `TiDB`
//!   instances, with the keyspace derived from the etcd path.
//!
//! This crate never reads, watches, or writes `/config` — that is owned by the
//! configuration/namespace module, whose immutable snapshot this crate consumes
//! read-only for the backend-cluster list.

#![forbid(unsafe_code)]

mod model;

pub use model::{BackendInfo, TopologySnapshot, parse_tidb_topology};
