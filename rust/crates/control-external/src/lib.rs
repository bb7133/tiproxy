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

//! Bounded external-dependency foundation for Rust control modules.
//!
//! All clients carry the process-local owner-generation fence from
//! `control-plane`. Generated etcd protobuf types remain private to
//! `etcd-client`; only the diagnostics service that `TiProxy` actually exposes is
//! generated here.

#![forbid(unsafe_code)]

pub mod dns;
mod dns_transport;
pub mod etcd;
pub mod explicit_dns;
pub mod http;
pub mod retry;
mod tls;
mod transport;

/// Minimal wire-compatible `kvproto` diagnostics service binding.
#[allow(
    missing_docs,
    non_camel_case_types,
    unused_qualifications,
    clippy::all,
    clippy::pedantic
)]
pub mod diagnostics {
    include!("generated/diagnosticspb.rs");
}

pub use dns::{DnsError, DnsResolver, MAX_RESOLVED_ADDRESSES};
pub use etcd::{
    EtcdClientConfig, EtcdConfigError, EtcdConnectError, EtcdConnectSource, EtcdConnection,
    EtcdConnector, EtcdOperationError, EtcdTlsConfig, EtcdTlsPolicy, EtcdTlsVersion,
    GenerationGate,
};
pub use http::{BoundedHttpClient, HttpClientConfig, HttpConfigError, HttpError, HttpTlsConfig};
pub use retry::{RetryDecision, RetryError, RetryPolicy, RetryPolicyError, retry_bounded};

/// The sole direct `kvproto` service binding needed by the current Go server.
pub const DIRECT_KVPROTO_BINDINGS: &[&str] = &["diagnosticspb.Diagnostics"];

/// Generated etcd protobuf modules are intentionally not part of this crate's
/// public API; later modules use `etcd-client`'s semantic client operations.
pub const EXPOSES_ETCD_GENERATED_PROTO: bool = false;
