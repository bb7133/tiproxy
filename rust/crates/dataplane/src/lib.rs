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

//! Composition root for the `TiProxy` Rust dataplane.
//!
//! This crate owns SQL listener and connection admission lifecycle. `MySQL`
//! packet processing remains in `mysql-wire`, transport mechanics remain in
//! `proxy-io`, and session policy remains in `session-core`.

#![forbid(unsafe_code)]

pub mod admission;
pub mod control_commands;
pub mod registry;
pub mod route;
pub mod route_control;
pub mod server;
pub mod session;

pub use admission::{
    AdmissionController, AdmissionMetricsSnapshot, AdmissionPolicy, AdmissionPolicyError,
    AdmissionRejection, MemoryProbe, MemoryProbeError, MemorySample, SystemMemoryProbe,
};
pub use control_commands::{
    CloseAdmission, CommandGate, DrainAdmission, DrainPhase, MAX_COMPLETED_DRAINS,
    MAX_DELTAS_PER_BATCH, MAX_TERMINAL_REDIRECTS_PER_CONNECTION, MAX_UNACKED_METERING_BATCHES,
    MeteringError, MeteringLedger, ReconcileRepairs, RedirectAdmission,
};
pub use registry::{
    ConnectionId, ConnectionMetadata, ConnectionRegistry, ConnectionRegistrySnapshot, RegistryError,
};
pub use route::{
    AcquireError, AcquireStats, AcquiredBackend, BackendDialer, BackendInfo, CenteredJitter,
    DialFailure, DialSchedule, JitterSource, RouteChannel, RouteChannelError, RouteEngine,
    SplitMixJitter,
};
pub use route_control::{
    AssignmentRouter, ControlRouteChannel, EnvelopeSink, TcpDialer, TrafficTotals,
    connection_closed, connection_opened,
};
pub use server::{
    AcceptedConnection, BoundListenerInfo, ConnectionHandler, DataplaneHandle, DataplaneServer,
    ListenerSpec, ServerError, ServerMetricsSnapshot, preflight_snapshot,
};

/// Names and stable roles of the library crates composed by the dataplane.
#[must_use]
pub const fn component_roles() -> [(&'static str, &'static str); 4] {
    [
        ("control-proto", control_proto::CRATE_ROLE),
        ("mysql-wire", mysql_wire::CRATE_ROLE),
        ("proxy-io", proxy_io::CRATE_ROLE),
        ("session-core", session_core::CRATE_ROLE),
    ]
}

#[cfg(test)]
mod tests {
    use super::component_roles;

    #[test]
    fn workspace_has_all_component_boundaries() {
        assert_eq!(component_roles().len(), 4);
    }
}
