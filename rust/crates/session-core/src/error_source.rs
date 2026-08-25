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

//! Go-compatible failure-source taxonomy and client-response policy (WIRE-07).
//!
//! The reference is `pkg/proxy/backend/error.go`. Three contracts are frozen
//! here:
//!
//! 1. [`ErrorSource::metric_label`] values are byte-identical to Go's
//!    `ErrorSource.String()` — dashboards and alerts key on them.
//! 2. [`ErrorSource::classify`] encodes `Error2Source`'s precedence exactly:
//!    disconnect-with-side wins first, then malformed/sequence (treated as
//!    proxy bugs, per Go's comment), then handshake classes, authentication,
//!    no-backend, an already-MySQL error, cancellation, and finally the
//!    proxy-error catch-all.
//! 3. [`client_response`] is Go's `ErrToClient` allowlist: only the listed
//!    failures produce a client-visible `MySQL` error; everything else is
//!    silent. Internal detail (paths, certificates, control payloads) never
//!    reaches the client because responses are fixed static strings.

use core::fmt;

/// Which endpoint a failure is attributed to, mirroring Go `SourceComp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceComponent {
    /// No component: success paths.
    None,
    /// The frontend client.
    Client,
    /// `TiProxy` itself.
    Proxy,
    /// The `TiDB` backend.
    Backend,
}

/// Failure source attribution, mirroring Go `ErrorSource` exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSource {
    /// Success (`OnHandshake` succeeded; client quit normally).
    None,
    /// Client-side EOF/reset/refused/timeout.
    ClientNetwork,
    /// Client capability or TLS handshake failure.
    ClientHandshake,
    /// Backend rejected the client's authentication.
    ClientAuthFail,
    /// A SQL error returned to the client (label text is Go verbatim).
    ClientSqlError,
    /// Proxy graceful shutdown.
    ProxyQuit,
    /// Malformed packet or compressed-sequence violation (treated as a proxy
    /// bug, per Go's comment: "We assume the clients and `TiDB` are right").
    ProxyMalformed,
    /// No backend available.
    ProxyNoBackend,
    /// Handshake-hook or other unexpected proxy-side failure.
    ProxyError,
    /// Backend-side EOF/reset/refused/timeout.
    BackendNetwork,
    /// Backend dial/capability/TLS/PROXY-protocol handshake failure.
    BackendHandshake,
}

impl ErrorSource {
    /// Returns the Go-compatible metric/log label, byte-identical to
    /// `ErrorSource.String()`.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::None => "success",
            Self::ClientNetwork => "client network break",
            Self::ClientHandshake => "client handshake fail",
            Self::ClientAuthFail => "auth fail",
            Self::ClientSqlError => "SQL error",
            Self::ProxyQuit => "proxy shutdown",
            Self::ProxyMalformed => "malformed packet",
            Self::ProxyNoBackend => "get backend fail",
            Self::ProxyError => "proxy error",
            Self::BackendNetwork => "backend network break",
            Self::BackendHandshake => "backend handshake fail",
        }
    }

    /// Returns the owning component, mirroring Go `GetSourceComp`.
    #[must_use]
    pub const fn component(self) -> SourceComponent {
        match self {
            Self::None => SourceComponent::None,
            Self::ClientNetwork
            | Self::ClientHandshake
            | Self::ClientAuthFail
            | Self::ClientSqlError => SourceComponent::Client,
            Self::ProxyQuit | Self::ProxyMalformed | Self::ProxyNoBackend | Self::ProxyError => {
                SourceComponent::Proxy
            }
            Self::BackendNetwork | Self::BackendHandshake => SourceComponent::Backend,
        }
    }

    /// Returns whether the source is expected, mirroring Go `Normal()`:
    /// suppresses quit-reason logging for ordinary lifecycles.
    #[must_use]
    pub const fn is_normal(self) -> bool {
        matches!(
            self,
            Self::None | Self::ProxyQuit | Self::ClientNetwork | Self::ClientSqlError
        )
    }

    /// Classifies a failure descriptor with `Error2Source`'s exact precedence.
    #[must_use]
    pub const fn classify(failure: &FailureDescriptor) -> Self {
        // 1. Disconnects attributed to a side win over every wrapped context.
        match failure.disconnect {
            DisconnectState::Attributed(SideMarker::Client) => return Self::ClientNetwork,
            DisconnectState::Attributed(SideMarker::Backend) => return Self::BackendNetwork,
            DisconnectState::NotDisconnect | DisconnectState::Unattributed => {}
        }
        // 2. Malformed packets and sequence violations are proxy bugs even
        //    when wrapped in handshake context.
        if failure.malformed_or_sequence {
            return Self::ProxyMalformed;
        }
        // 3..8: the Go switch order.
        match failure.kind {
            Some(FailureKind::ClientHandshake | FailureKind::ClientCapability) => {
                Self::ClientHandshake
            }
            Some(FailureKind::PacketTooLarge) => Self::ClientHandshake,
            Some(FailureKind::AuthenticationFailed) => Self::ClientAuthFail,
            Some(
                FailureKind::BackendHandshake
                | FailureKind::BackendCapability
                | FailureKind::BackendNoTls
                | FailureKind::BackendProxyProtocol,
            ) => Self::BackendHandshake,
            Some(FailureKind::NoBackend) => Self::ProxyNoBackend,
            None | Some(FailureKind::ProxyInternal) => {
                if failure.mysql_error {
                    Self::ClientSqlError
                } else if failure.cancelled {
                    Self::ProxyQuit
                } else {
                    Self::ProxyError
                }
            }
        }
    }
}

impl fmt::Display for ErrorSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.metric_label())
    }
}

/// The failure context marker, mirroring Go's `ErrClientConn`/`ErrBackendConn`
/// wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideMarker {
    /// The failure was observed on the client connection.
    Client,
    /// The failure was observed on the backend connection.
    Backend,
}

/// Disconnect status of the underlying I/O failure, combining Go's
/// `IsDisconnectError` check with the side-marker wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisconnectState {
    /// The failure is not a disconnect.
    #[default]
    NotDisconnect,
    /// A disconnect without a side marker; falls through to wrapped classes
    /// exactly like Go.
    Unattributed,
    /// A disconnect observed on a marked connection side.
    Attributed(SideMarker),
}

/// Specific failure classes mirroring Go's typed sentinel errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Go `ErrClientHandshake`.
    ClientHandshake,
    /// Go `ErrClientCap`.
    ClientCapability,
    /// Go `pnet.ErrPacketTooLarge` (pre-handshake 1-MiB cap).
    PacketTooLarge,
    /// Go `ErrClientAuthFail`.
    AuthenticationFailed,
    /// Go `ErrBackendHandshake`.
    BackendHandshake,
    /// Go `ErrBackendCap`.
    BackendCapability,
    /// Go `ErrBackendNoTLS`.
    BackendNoTls,
    /// Go `ErrBackendPPV2`.
    BackendProxyProtocol,
    /// Go `ErrProxyNoBackend`.
    NoBackend,
    /// Go `ErrProxyErr`.
    ProxyInternal,
}

/// Structured failure descriptor the session layer builds for classification.
///
/// This replaces Go's `errors.Is` chain walking: each field corresponds to a
/// wrapped marker or sentinel in the Go error tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FailureDescriptor {
    /// Disconnect status with optional side attribution
    /// (EOF/reset/refused/timeout plus Go's side-marker wrapping).
    pub disconnect: DisconnectState,
    /// A malformed packet or an invalid compressed sequence was detected.
    pub malformed_or_sequence: bool,
    /// The specific failure class, when one applies.
    pub kind: Option<FailureKind>,
    /// The failure carries a `MySQL` server error.
    pub mysql_error: bool,
    /// The enclosing context was cancelled (Go `context.Canceled`).
    pub cancelled: bool,
}

/// A fixed, client-safe `MySQL` error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientErrorResponse {
    /// `MySQL` error code.
    pub code: u16,
    /// Five-byte SQLSTATE.
    pub sql_state: [u8; 5],
    /// Fixed message; never derived from internal error detail.
    pub message: &'static str,
}

/// Go `ErrProxyNoBackend` client-visible text.
pub const MSG_NO_BACKEND: &str = "No available TiDB instances, please make sure TiDB is available";
/// Go `ErrProxyNoTLS` client-visible text.
pub const MSG_PROXY_NO_TLS: &str = "Require TLS enabled on TiProxy when require-backend-tls=true";
/// Go `ErrBackendCap` client-visible text.
pub const MSG_BACKEND_CAPABILITY: &str = "Verify TiDB capability failed, please upgrade TiDB";
/// Go `ErrBackendHandshake` client-visible text.
pub const MSG_BACKEND_HANDSHAKE: &str =
    "TiProxy fails to connect to TiDB, please make sure TiDB is available";
/// Go `ErrBackendNoTLS` client-visible text.
pub const MSG_BACKEND_NO_TLS: &str = "Require TLS enabled on TiDB when require-backend-tls=true";
/// Go `ErrBackendPPV2` client-visible text.
pub const MSG_BACKEND_PPV2: &str = "TiProxy fails to connect to TiDB, please make sure TiDB \
     proxy-protocol is set correctly. If this error still exists, please contact PingCAP";

/// `MySQL` `ER_UNKNOWN_ERROR`, used by Go `MakeUserError` for proxy texts.
pub const ER_UNKNOWN_ERROR: u16 = 1105;
/// `MySQL` `ER_NET_PACKET_TOO_LARGE`, sent for the pre-handshake size cap.
pub const ER_NET_PACKET_TOO_LARGE: u16 = 1153;
/// The default message `MySQL` associates with `ER_NET_PACKET_TOO_LARGE`.
pub const MSG_NET_PACKET_TOO_LARGE: &str = "Got a packet bigger than 'max_allowed_packet' bytes";

const SQL_STATE_HY000: [u8; 5] = *b"HY000";
const SQL_STATE_08S01: [u8; 5] = *b"08S01";

/// Which client-visible failure to send, when any.
///
/// Mirrors Go `ErrToClient`: an allowlist of fixed responses. A failure that
/// already delivered a `MySQL` error sends nothing more; every unlisted
/// failure is silent, so internal detail cannot leak by construction.
#[must_use]
pub const fn client_response(failure: &FailureDescriptor) -> Option<ClientErrorResponse> {
    if failure.mysql_error {
        // Already sent to the client by the backend.
        return None;
    }
    let (code, sql_state, message) = match failure.kind {
        Some(FailureKind::NoBackend) => (ER_UNKNOWN_ERROR, SQL_STATE_HY000, MSG_NO_BACKEND),
        Some(FailureKind::BackendCapability) => {
            (ER_UNKNOWN_ERROR, SQL_STATE_HY000, MSG_BACKEND_CAPABILITY)
        }
        Some(FailureKind::BackendHandshake) => {
            (ER_UNKNOWN_ERROR, SQL_STATE_HY000, MSG_BACKEND_HANDSHAKE)
        }
        Some(FailureKind::BackendNoTls) => (ER_UNKNOWN_ERROR, SQL_STATE_HY000, MSG_BACKEND_NO_TLS),
        Some(FailureKind::BackendProxyProtocol) => {
            (ER_UNKNOWN_ERROR, SQL_STATE_HY000, MSG_BACKEND_PPV2)
        }
        Some(FailureKind::PacketTooLarge) => (
            ER_NET_PACKET_TOO_LARGE,
            SQL_STATE_08S01,
            MSG_NET_PACKET_TOO_LARGE,
        ),
        // ErrProxyNoTLS carries a fixed text as well but is reported through
        // the proxy-internal path in Go; keep it reachable via ProxyInternal
        // once the session layer wires configuration errors. All remaining
        // failures are silent by Go parity.
        _ => return None,
    };
    Some(ClientErrorResponse {
        code,
        sql_state,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact Go label set; a changed byte here breaks dashboards.
    #[test]
    fn metric_labels_are_byte_identical_to_go() {
        let expected: [(ErrorSource, &str); 11] = [
            (ErrorSource::None, "success"),
            (ErrorSource::ClientNetwork, "client network break"),
            (ErrorSource::ClientHandshake, "client handshake fail"),
            (ErrorSource::ClientAuthFail, "auth fail"),
            (ErrorSource::ClientSqlError, "SQL error"),
            (ErrorSource::ProxyQuit, "proxy shutdown"),
            (ErrorSource::ProxyMalformed, "malformed packet"),
            (ErrorSource::ProxyNoBackend, "get backend fail"),
            (ErrorSource::ProxyError, "proxy error"),
            (ErrorSource::BackendNetwork, "backend network break"),
            (ErrorSource::BackendHandshake, "backend handshake fail"),
        ];
        for (source, label) in expected {
            assert_eq!(source.metric_label(), label);
            assert_eq!(source.to_string(), label);
        }
    }

    /// Precedence proven on combined descriptors, not single-cause paths.
    #[test]
    fn classification_precedence_matches_error2source() {
        // Disconnect + side marker beats a wrapped backend-handshake context
        // (Go checks IsDisconnectError with side markers first).
        let disconnect_in_handshake = FailureDescriptor {
            disconnect: DisconnectState::Attributed(SideMarker::Backend),
            kind: Some(FailureKind::BackendHandshake),
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&disconnect_in_handshake),
            ErrorSource::BackendNetwork
        );

        // A disconnect without a side marker falls through to the wrapped
        // classes, exactly like Go.
        let unattributed_disconnect = FailureDescriptor {
            disconnect: DisconnectState::Unattributed,
            kind: Some(FailureKind::BackendHandshake),
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&unattributed_disconnect),
            ErrorSource::BackendHandshake
        );

        // Malformed/sequence beats handshake context even on a disconnect
        // without side attribution (Go's switch order).
        let malformed_in_backend_handshake = FailureDescriptor {
            malformed_or_sequence: true,
            kind: Some(FailureKind::BackendHandshake),
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&malformed_in_backend_handshake),
            ErrorSource::ProxyMalformed
        );

        // ...but a side-attributed disconnect still wins over malformed.
        let disconnect_and_malformed = FailureDescriptor {
            disconnect: DisconnectState::Attributed(SideMarker::Client),
            malformed_or_sequence: true,
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&disconnect_and_malformed),
            ErrorSource::ClientNetwork
        );

        // Auth failure carrying a MySQL error classifies as auth, not SQL
        // (Go matches ErrClientAuthFail before IsMySQLError).
        let auth_with_mysql = FailureDescriptor {
            kind: Some(FailureKind::AuthenticationFailed),
            mysql_error: true,
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&auth_with_mysql),
            ErrorSource::ClientAuthFail
        );

        // A bare MySQL error is a SQL error; cancellation maps to quit; and
        // the unclassified remainder is a proxy error.
        let bare_mysql = FailureDescriptor {
            mysql_error: true,
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&bare_mysql),
            ErrorSource::ClientSqlError
        );
        let cancelled = FailureDescriptor {
            cancelled: true,
            ..FailureDescriptor::default()
        };
        assert_eq!(ErrorSource::classify(&cancelled), ErrorSource::ProxyQuit);
        assert_eq!(
            ErrorSource::classify(&FailureDescriptor::default()),
            ErrorSource::ProxyError
        );

        // Packet-too-large classifies as a client handshake failure.
        let too_large = FailureDescriptor {
            kind: Some(FailureKind::PacketTooLarge),
            ..FailureDescriptor::default()
        };
        assert_eq!(
            ErrorSource::classify(&too_large),
            ErrorSource::ClientHandshake
        );
    }

    /// Component and normality matrices mirror Go exactly.
    #[test]
    fn component_and_normality_match_go() {
        use ErrorSource as E;
        use SourceComponent as C;
        let matrix: [(E, C, bool); 11] = [
            (E::None, C::None, true),
            (E::ClientNetwork, C::Client, true),
            (E::ClientHandshake, C::Client, false),
            (E::ClientAuthFail, C::Client, false),
            (E::ClientSqlError, C::Client, true),
            (E::ProxyQuit, C::Proxy, true),
            (E::ProxyMalformed, C::Proxy, false),
            (E::ProxyNoBackend, C::Proxy, false),
            (E::ProxyError, C::Proxy, false),
            (E::BackendNetwork, C::Backend, false),
            (E::BackendHandshake, C::Backend, false),
        ];
        for (source, component, normal) in matrix {
            assert_eq!(source.component(), component);
            assert_eq!(source.is_normal(), normal);
        }
    }

    /// The client-response allowlist pins code, SQLSTATE, and message; every
    /// unlisted failure is silent.
    #[test]
    fn client_responses_pin_code_state_and_message() {
        let no_backend = FailureDescriptor {
            kind: Some(FailureKind::NoBackend),
            ..FailureDescriptor::default()
        };
        let response = client_response(&no_backend);
        assert_eq!(
            response,
            Some(ClientErrorResponse {
                code: 1105,
                sql_state: *b"HY000",
                message: "No available TiDB instances, please make sure TiDB is available",
            })
        );

        let too_large = FailureDescriptor {
            kind: Some(FailureKind::PacketTooLarge),
            ..FailureDescriptor::default()
        };
        let response = client_response(&too_large);
        assert_eq!(
            response,
            Some(ClientErrorResponse {
                code: 1153,
                sql_state: *b"08S01",
                message: "Got a packet bigger than 'max_allowed_packet' bytes",
            })
        );

        // Already-sent MySQL errors add nothing, even for listed kinds.
        let already_sent = FailureDescriptor {
            kind: Some(FailureKind::BackendHandshake),
            mysql_error: true,
            ..FailureDescriptor::default()
        };
        assert_eq!(client_response(&already_sent), None);

        // Silent-by-default: client-side failures, network breaks, internal
        // proxy errors, and malformed packets never produce a response.
        for silent in [
            FailureDescriptor {
                kind: Some(FailureKind::ClientHandshake),
                ..FailureDescriptor::default()
            },
            FailureDescriptor {
                kind: Some(FailureKind::AuthenticationFailed),
                ..FailureDescriptor::default()
            },
            FailureDescriptor {
                disconnect: DisconnectState::Attributed(SideMarker::Backend),
                ..FailureDescriptor::default()
            },
            FailureDescriptor {
                malformed_or_sequence: true,
                ..FailureDescriptor::default()
            },
            FailureDescriptor::default(),
        ] {
            assert_eq!(client_response(&silent), None, "{silent:?} must be silent");
        }
    }

    /// Responses are fixed static strings: no formatting of internal detail,
    /// so paths/certificates/control payloads cannot leak by construction.
    #[test]
    fn responses_contain_no_dynamic_detail() {
        for message in [
            MSG_NO_BACKEND,
            MSG_PROXY_NO_TLS,
            MSG_BACKEND_CAPABILITY,
            MSG_BACKEND_HANDSHAKE,
            MSG_BACKEND_NO_TLS,
            MSG_BACKEND_PPV2,
            MSG_NET_PACKET_TOO_LARGE,
        ] {
            assert!(!message.contains('/') && !message.contains('\\'));
            assert!(!message.contains("{}") && !message.contains('%'));
        }
    }
}
