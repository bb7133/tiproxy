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

//! Protocol-independent CP-ROUTE domain values.
//!
//! These values are the seam between routing policy/selection and the
//! temporary legacy control bridge. They deliberately contain only routing
//! metadata: no transport envelope, protobuf type, or `MySQL` payload can cross
//! this crate's public API. Wire conversion stays at the bridge edge.

pub mod group;

/// Stable route outcome codes understood by the routing domain.
///
/// The variants mirror the control contract's semantic vocabulary while
/// remaining independent of its serialization and generated types. An edge
/// adapter maps unrecognized wire values to [`Self::Unspecified`], matching the
/// generated protocol accessor's behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RouteCode {
    /// No explicit code was supplied.
    #[default]
    Unspecified,
    /// The operation succeeded.
    Ok,
    /// The peer does not support this protocol version.
    UnsupportedVersion,
    /// A required capability is absent.
    MissingCapability,
    /// A control frame exceeds its bound.
    FrameTooLarge,
    /// A control frame is malformed.
    MalformedFrame,
    /// The control conversation violated its protocol.
    ProtocolViolation,
    /// The referenced process epoch is stale.
    StaleEpoch,
    /// The referenced owner generation is stale.
    StaleGeneration,
    /// A request was repeated.
    DuplicateRequest,
    /// A bounded queue is full.
    QueueFull,
    /// The control owner is unavailable.
    ControlUnavailable,
    /// A grace period elapsed.
    GraceExpired,
    /// A snapshot is invalid.
    InvalidSnapshot,
    /// The requested configuration is unsupported.
    UnsupportedConfiguration,
    /// No routeable backend remains.
    NoBackend,
    /// A backend dial failed.
    BackendDialFailed,
    /// A backend handshake was rejected.
    HandshakeRejected,
    /// A redirect is unsafe.
    RedirectUnsafe,
    /// A redirect failed.
    RedirectFailed,
    /// Draining is already in progress.
    DrainInProgress,
    /// State must be reconciled before proceeding.
    ReconciliationRequired,
    /// An internal routing error occurred.
    Internal,
}

/// Stable attribution for a route result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RouteErrorSource {
    /// No error source applies.
    #[default]
    Unspecified,
    /// The client-side network failed.
    ClientNetwork,
    /// The backend-side network failed.
    BackendNetwork,
    /// The backend returned a SQL error.
    BackendSql,
    /// The proxy itself failed.
    Proxy,
    /// The control conversation failed.
    Control,
    /// Process shutdown caused the outcome.
    Shutdown,
}

/// One backend assignment produced by a route owner.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteAssignment {
    /// Owning connection identifier.
    pub connection_id: u64,
    /// Unique reservation identifier.
    pub assignment_id: String,
    /// Stable backend accounting identifier.
    pub backend_id: String,
    /// Backend dial address.
    pub backend_address: String,
    /// Optional cluster scope used by cluster-aware resolution.
    pub cluster_name: String,
    /// Optional keyspace scope.
    pub keyspace: String,
    /// Health verdict observed when the route was selected.
    pub healthy: bool,
    /// Whether the selected backend is local to this proxy.
    pub local: bool,
    /// Assignment outcome.
    pub code: RouteCode,
    /// Bounded diagnostic detail; never a `MySQL` payload.
    pub detail: String,
}

/// The terminal result for one route assignment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteResult {
    /// Owning connection identifier.
    pub connection_id: u64,
    /// Assignment being retired.
    pub assignment_id: String,
    /// Whether the backend connection was established.
    pub connected: bool,
    /// Attribution for a failed result.
    pub error_source: RouteErrorSource,
    /// Result code.
    pub code: RouteCode,
    /// Bounded diagnostic detail; never a `MySQL` payload.
    pub detail: String,
}
