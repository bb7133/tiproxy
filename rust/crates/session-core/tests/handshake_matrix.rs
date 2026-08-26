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

//! SES-01 driver handshake matrix: representative client capability
//! profiles run end-to-end through the wire codec and the negotiation
//! policy, plus exhaustive truncation sweeps proving no panic on any
//! prefix. The profiles are synthetic reconstructions of common driver
//! masks; the live-driver matrix against a real backend belongs to the
//! runtime acceptance phases.

use mysql_wire::{
    Attribute, CapabilityFlags, ClientHandshake, HandshakeResponseParams, decode_client_handshake,
    encode_handshake_response,
};
use session_core::handshake::{
    ConnectionEndpoints, MIN_CLIENT_HANDSHAKE_LEN, SUPPORTED_SERVER_CAPABILITIES,
    check_min_client_handshake, negotiate_frontend, reconcile_tls_capabilities,
};

fn endpoints() -> ConnectionEndpoints {
    ConnectionEndpoints {
        listener_addr: match "10.0.0.1:6000".parse() {
            Ok(addr) => addr,
            Err(error) => unreachable!("listener addr: {error}"),
        },
        client_addr: match "192.0.2.7:51234".parse() {
            Ok(addr) => addr,
            Err(error) => unreachable!("client addr: {error}"),
        },
    }
}

struct DriverProfile {
    name: &'static str,
    capabilities: CapabilityFlags,
    auth_plugin: Option<&'static [u8]>,
    auth_response: &'static [u8],
    database: Option<&'static [u8]>,
    attributes: bool,
    zstd_level: Option<u8>,
    expect_plugin_auth_forced: bool,
    expect_unsupported: CapabilityFlags,
}

const BASE_41: u32 = CapabilityFlags::PROTOCOL_41.bits()
    | CapabilityFlags::LONG_PASSWORD.bits()
    | CapabilityFlags::TRANSACTIONS.bits()
    | CapabilityFlags::SECURE_CONNECTION.bits();

fn profiles() -> Vec<DriverProfile> {
    vec![
        DriverProfile {
            name: "mysql-cli-8.0",
            capabilities: CapabilityFlags::from_bits_retain(
                BASE_41
                    | CapabilityFlags::PLUGIN_AUTH.bits()
                    | CapabilityFlags::PLUGIN_AUTH_LENENC_CLIENT_DATA.bits()
                    | CapabilityFlags::CONNECT_ATTRS.bits()
                    | CapabilityFlags::LOCAL_FILES.bits()
                    | CapabilityFlags::MULTI_STATEMENTS.bits()
                    | CapabilityFlags::MULTI_RESULTS.bits()
                    | CapabilityFlags::PS_MULTI_RESULTS.bits()
                    | CapabilityFlags::SESSION_TRACK.bits()
                    | CapabilityFlags::DEPRECATE_EOF.bits(),
            ),
            auth_plugin: Some(b"caching_sha2_password"),
            auth_response: &[0x5a; 32],
            database: None,
            attributes: true,
            zstd_level: None,
            expect_plugin_auth_forced: false,
            expect_unsupported: CapabilityFlags::PS_MULTI_RESULTS
                .union(CapabilityFlags::SESSION_TRACK),
        },
        DriverProfile {
            name: "go-sql-driver",
            capabilities: CapabilityFlags::from_bits_retain(
                BASE_41
                    | CapabilityFlags::PLUGIN_AUTH.bits()
                    | CapabilityFlags::LONG_FLAG.bits()
                    | CapabilityFlags::MULTI_RESULTS.bits()
                    | CapabilityFlags::LOCAL_FILES.bits(),
            ),
            auth_plugin: Some(b"mysql_native_password"),
            auth_response: &[0x11; 20],
            database: None,
            attributes: false,
            zstd_level: None,
            expect_plugin_auth_forced: false,
            expect_unsupported: CapabilityFlags::from_bits_retain(0),
        },
        DriverProfile {
            name: "connector-j",
            capabilities: CapabilityFlags::from_bits_retain(
                BASE_41
                    | CapabilityFlags::PLUGIN_AUTH.bits()
                    | CapabilityFlags::CONNECT_WITH_DB.bits()
                    | CapabilityFlags::CONNECT_ATTRS.bits()
                    | CapabilityFlags::MULTI_STATEMENTS.bits()
                    | CapabilityFlags::MULTI_RESULTS.bits()
                    | CapabilityFlags::PS_MULTI_RESULTS.bits(),
            ),
            auth_plugin: Some(b"mysql_native_password"),
            auth_response: &[0x22; 20],
            database: Some(b"test"),
            attributes: true,
            zstd_level: None,
            expect_plugin_auth_forced: false,
            expect_unsupported: CapabilityFlags::PS_MULTI_RESULTS,
        },
        DriverProfile {
            name: "libmysqlclient-5.5",
            capabilities: CapabilityFlags::from_bits_retain(BASE_41),
            auth_plugin: None,
            auth_response: &[0x33; 20],
            database: None,
            attributes: false,
            zstd_level: None,
            expect_plugin_auth_forced: true,
            expect_unsupported: CapabilityFlags::from_bits_retain(0),
        },
        DriverProfile {
            name: "zstd-client",
            capabilities: CapabilityFlags::from_bits_retain(
                BASE_41
                    | CapabilityFlags::PLUGIN_AUTH.bits()
                    | CapabilityFlags::ZSTD_COMPRESSION_ALGORITHM.bits(),
            ),
            auth_plugin: Some(b"mysql_native_password"),
            auth_response: &[0x44; 20],
            database: None,
            attributes: false,
            zstd_level: Some(3),
            expect_plugin_auth_forced: false,
            expect_unsupported: CapabilityFlags::from_bits_retain(0),
        },
    ]
}

fn encode_profile(profile: &DriverProfile) -> Vec<u8> {
    let attributes = [
        Attribute {
            key: b"_client_name",
            value: b"libmysql",
        },
        Attribute {
            key: b"program_name",
            value: b"matrix",
        },
    ];
    let params = HandshakeResponseParams {
        capabilities: profile.capabilities,
        max_packet_size: 1 << 24,
        collation: 0x21,
        username: b"app_user",
        auth_response: profile.auth_response,
        database: profile.database,
        auth_plugin_name: profile.auth_plugin,
        attributes: profile.attributes.then_some(&attributes[..]),
        zstd_level: profile.zstd_level,
    };
    match encode_handshake_response(params) {
        Ok(encoded) => encoded,
        Err(error) => unreachable!("encode {}: {error}", profile.name),
    }
}

/// Every profile passes the size gates, decodes, negotiates to the exact
/// expected capability set, and yields a complete routing gate.
#[test]
fn driver_matrix_negotiates_like_go() {
    for profile in profiles() {
        let encoded = encode_profile(&profile);
        assert!(
            check_min_client_handshake(encoded.len()).is_ok(),
            "{}",
            profile.name
        );
        assert!(
            session_core::handshake::check_handshake_packet_size(encoded.len()).is_ok(),
            "{}",
            profile.name
        );
        let response = match decode_client_handshake(&encoded) {
            Ok(ClientHandshake::Response(response)) => response,
            other => unreachable!("{}: unexpected decode {other:?}", profile.name),
        };
        let negotiation =
            match negotiate_frontend(response.capabilities, SUPPORTED_SERVER_CAPABILITIES) {
                Ok(negotiation) => negotiation,
                Err(error) => unreachable!("{}: {error}", profile.name),
            };
        assert_eq!(
            negotiation.plugin_auth_forced(),
            profile.expect_plugin_auth_forced,
            "{}",
            profile.name
        );
        assert_eq!(
            negotiation.unsupported_by_proxy(),
            profile.expect_unsupported,
            "{}",
            profile.name
        );
        // The negotiated mask is the supported intersection plus the
        // forced PLUGIN_AUTH bit — nothing else appears.
        let expected = CapabilityFlags::from_bits_retain(
            profile.capabilities.bits() & SUPPORTED_SERVER_CAPABILITIES.bits(),
        )
        .union(CapabilityFlags::PLUGIN_AUTH);
        assert_eq!(negotiation.negotiated(), expected, "{}", profile.name);

        // The routing gate is only reachable through the successful
        // negotiation and carries the endpoints unchanged.
        let routing = negotiation.routing_handshake(&response, endpoints());
        assert_eq!(routing.username(), b"app_user", "{}", profile.name);
        assert_eq!(routing.database(), profile.database, "{}", profile.name);
        assert_eq!(routing.zstd_level(), profile.zstd_level, "{}", profile.name);
        assert_eq!(
            routing.has_attributes(),
            profile.attributes,
            "{}",
            profile.name
        );
        assert_eq!(routing.collation(), 0x21, "{}", profile.name);
        assert_eq!(
            routing.negotiated(),
            negotiation.negotiated(),
            "{}",
            profile.name
        );
        assert_eq!(routing.endpoints(), endpoints(), "{}", profile.name);
    }
}

/// A TLS driver that drops `SSL` from the second packet (a known driver
/// quirk Go tolerates): the `SSLRequest` mask wins.
#[test]
fn tls_driver_with_dropped_ssl_bit() {
    let ssl_caps = CapabilityFlags::from_bits_retain(
        BASE_41 | CapabilityFlags::PLUGIN_AUTH.bits() | CapabilityFlags::SSL.bits(),
    );
    // A 32-byte SSLRequest: capability, max packet, collation, 23 filler.
    let mut ssl_request = Vec::new();
    ssl_request.extend_from_slice(&ssl_caps.bits().to_le_bytes());
    ssl_request.extend_from_slice(&(1_u32 << 24).to_le_bytes());
    ssl_request.push(0x21);
    ssl_request.extend_from_slice(&[0; 23]);
    let parsed = match decode_client_handshake(&ssl_request) {
        Ok(ClientHandshake::SslRequest(request)) => request,
        other => unreachable!("unexpected decode {other:?}"),
    };
    assert_eq!(parsed.capabilities, ssl_caps);

    // The follow-up response omits SSL; trust-first restores it.
    let response_caps = ssl_caps.without(CapabilityFlags::SSL);
    let reconciliation = reconcile_tls_capabilities(parsed.capabilities, response_caps);
    assert_eq!(reconciliation.trusted, ssl_caps);
    assert_eq!(reconciliation.mismatched, CapabilityFlags::SSL);
    let negotiation =
        match negotiate_frontend(reconciliation.trusted, SUPPORTED_SERVER_CAPABILITIES) {
            Ok(negotiation) => negotiation,
            Err(error) => unreachable!("negotiation failed: {error}"),
        };
    assert!(negotiation.negotiated().contains(CapabilityFlags::SSL));
}

/// Truncated packets never panic: every prefix of every profile (and of
/// the `SSLRequest`) decodes to a typed error or, at most, a full-length
/// success.
#[test]
fn truncated_handshakes_never_panic() {
    let mut vectors: Vec<(String, Vec<u8>)> = profiles()
        .iter()
        .map(|profile| (profile.name.to_owned(), encode_profile(profile)))
        .collect();
    let ssl_caps = CapabilityFlags::from_bits_retain(BASE_41 | CapabilityFlags::SSL.bits());
    let mut ssl_request = Vec::new();
    ssl_request.extend_from_slice(&ssl_caps.bits().to_le_bytes());
    ssl_request.extend_from_slice(&(1_u32 << 24).to_le_bytes());
    ssl_request.push(0x21);
    ssl_request.extend_from_slice(&[0; 23]);
    vectors.push(("ssl-request".to_owned(), ssl_request));

    for (name, bytes) in &vectors {
        for cut in 0..bytes.len() {
            let prefix = &bytes[..cut];
            // The 32-byte minimum gate rejects short prefixes up front.
            if cut < MIN_CLIENT_HANDSHAKE_LEN {
                assert!(check_min_client_handshake(cut).is_err(), "{name}@{cut}");
            }
            // The decoder itself must return a typed result on any prefix.
            match decode_client_handshake(prefix) {
                Ok(_) => assert_eq!(
                    cut,
                    bytes.len(),
                    "{name}@{cut}: a strict prefix must not decode"
                ),
                Err(error) => {
                    let _ = error.to_string();
                }
            }
        }
        // The complete vector decodes.
        assert!(decode_client_handshake(bytes).is_ok(), "{name}");
    }
}
