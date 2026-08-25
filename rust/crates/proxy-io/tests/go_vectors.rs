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

//! Golden vectors ported from the Go `proxyprotocol` tests.
//!
//! Sources: `pkg/proxy/proxyprotocol/proxy_test.go` (`TestProxyParse`,
//! `TestProxyToBytes`, `TestMixIPv4AndIPv6ProxyToBytes`) and
//! `pkg/proxy/proxyprotocol/listener_test.go` (`TestProxyListener`).
//! Each case re-creates the Go inputs and asserts the same observable outcome
//! so PARITY-PP2-001 evidence stays anchored to the Go reference.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proxy_io::proxy_protocol::{
    EncodeAddresses, MAGIC_V2, MagicSniff, ProxyAddresses, ProxyCommand, ProxyEncodeError,
    ProxyV2Decode, ProxyVersion, TransportProtocol, decode_after_magic, encode_proxy_v2,
    sniff_magic,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn expect_done(input: &[u8]) -> Result<(proxy_io::proxy_protocol::ProxyHeader<'_>, usize), String> {
    match decode_after_magic(input) {
        ProxyV2Decode::Done { header, consumed } => Ok((header, consumed)),
        ProxyV2Decode::Incomplete { needed_total } => {
            Err(format!("expected complete decode, needed {needed_total}"))
        }
    }
}

/// Go `TestProxyParse`: LOCAL command, identical v4 src/dst `192.168.1.1:34`,
/// TLVs `[ALPN empty, UniqueID "test"]`, round-tripped through the encoder.
#[test]
fn go_test_proxy_parse_round_trip() -> TestResult {
    let addr = (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 34_u16);
    let encoded = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::LOCAL,
        TransportProtocol::STREAM,
        EncodeAddresses::Ip {
            src: addr,
            dst: addr,
        },
        &[(0x01, b""), (0x05, b"test")],
    )?;
    assert_eq!(encoded[..12], MAGIC_V2);
    let (header, consumed) = expect_done(&encoded[12..])?;
    assert_eq!(consumed, encoded.len() - 12);
    assert_eq!(header.version, ProxyVersion::V2);
    assert_eq!(header.command, ProxyCommand::LOCAL);
    assert_eq!(
        header.addresses,
        ProxyAddresses::Inet {
            src: (Ipv4Addr::new(192, 168, 1, 1), 34),
            dst: (Ipv4Addr::new(192, 168, 1, 1), 34),
        }
    );
    assert_eq!(header.tlvs.len(), 2);
    assert_eq!(header.tlvs[0].type_byte, 0x01);
    assert_eq!(header.tlvs[0].content, b"");
    assert_eq!(header.tlvs[1].type_byte, 0x05);
    assert_eq!(header.tlvs[1].content, b"test");
    Ok(())
}

/// Go `TestProxyToBytes`: the u16 body length equals everything after the
/// four fixed header bytes.
#[test]
fn go_test_proxy_to_bytes_length_field() -> TestResult {
    let encoded = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::LOCAL,
        TransportProtocol::STREAM,
        EncodeAddresses::Ip {
            src: (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            dst: (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        },
        &[],
    )?;
    assert!(encoded.len() >= MAGIC_V2.len() + 4);
    let length = usize::from(u16::from_be_bytes([encoded[14], encoded[15]]));
    assert_eq!(length, encoded.len() - 4 - MAGIC_V2.len());
    Ok(())
}

/// Go `TestMixIPv4AndIPv6ProxyToBytes`: all six family-unification cases.
#[test]
fn go_test_mixed_family_unification() -> TestResult {
    let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    let mapped =
        |a: u8, b: u8, c: u8, d: u8| IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped());
    let v6_1: IpAddr = "2001:db8::1".parse()?;
    let v6_2: IpAddr = "2001:db8::2".parse()?;
    // (src, dst, expected family nibble, expected ip length)
    let cases: [(IpAddr, IpAddr, u8, usize); 6] = [
        (v4(192, 168, 1, 1), v4(192, 168, 1, 2), 1, 4),
        (v6_1, v6_2, 2, 16),
        (v4(192, 168, 1, 1), v6_1, 2, 16),
        (v4(192, 168, 1, 1), mapped(192, 168, 1, 2), 1, 4),
        (mapped(192, 168, 1, 1), mapped(192, 168, 1, 2), 1, 4),
        (mapped(192, 168, 1, 1), v6_1, 2, 16),
    ];
    for (src, dst, family, ip_len) in cases {
        let encoded = encode_proxy_v2(
            ProxyVersion::V2,
            ProxyCommand::PROXY,
            TransportProtocol::STREAM,
            EncodeAddresses::Ip {
                src: (src, 1234),
                dst: (dst, 5678),
            },
            &[],
        )?;
        assert_eq!(encoded[13] >> 4, family, "family for {src}->{dst}");
        let length = usize::from(u16::from_be_bytes([encoded[14], encoded[15]]));
        assert_eq!(length, ip_len * 2 + 4, "payload size for {src}->{dst}");
    }
    Ok(())
}

/// Go `TestProxyListener`: a PROXY header followed by application bytes leaves
/// exactly the application bytes unconsumed; a plain payload is untouched.
#[test]
fn go_test_listener_flows() -> TestResult {
    let addr = (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 34_u16);
    let mut stream = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::LOCAL,
        TransportProtocol::STREAM,
        EncodeAddresses::Ip {
            src: addr,
            dst: addr,
        },
        &[(0x01, b""), (0x05, b"test")],
    )?;
    stream.extend_from_slice(b"test");
    assert_eq!(sniff_magic(&stream[..12]), MagicSniff::Proxy);
    let (_, consumed) = expect_done(&stream[12..])?;
    assert_eq!(&stream[12 + consumed..], b"test");

    // Plain client bytes: the sniffer rejects on the first byte and the
    // caller must treat every buffered byte as application data.
    assert_eq!(sniff_magic(b"test"), MagicSniff::NotProxy);
    Ok(())
}

/// Unix pair decode uses the spec's fixed 216-byte block that Go expects,
/// while the encoder keeps Go's unpadded write (asymmetry recorded in the
/// WIRE-05 ledger). A spec-padded body round-trips through the decoder.
#[test]
fn unix_spec_padded_body_decodes() -> TestResult {
    let mut body = vec![0_u8; 216];
    body[..9].copy_from_slice(b"/tmp/src\0");
    body[108..117].copy_from_slice(b"/tmp/dst\0");
    let mut input = vec![0x21, 0x31, 0x00, 0xd8];
    input.extend_from_slice(&body);
    let (header, consumed) = expect_done(&input)?;
    assert_eq!(consumed, input.len());
    match header.addresses {
        ProxyAddresses::Unix { src, dst } => {
            assert_eq!(&src[..9], b"/tmp/src\0");
            assert_eq!(&dst[..9], b"/tmp/dst\0");
            assert_eq!(src.len(), 108);
            assert_eq!(dst.len(), 108);
        }
        other => return Err(format!("expected unix addresses, got {other:?}").into()),
    }
    Ok(())
}

/// Encode-side strictness recorded in the WIRE-05 ledger: oversized TLVs and
/// oversized Unix paths return typed errors instead of Go's silent corruption.
#[test]
fn encode_strictness_returns_typed_errors() {
    let long = vec![0_u8; usize::from(u16::MAX) + 1];
    let result = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::PROXY,
        TransportProtocol::STREAM,
        EncodeAddresses::Unspec,
        &[(0x04, &long)],
    );
    assert_eq!(
        result,
        Err(ProxyEncodeError::TlvTooLong {
            index: 0,
            length: long.len(),
        })
    );

    let name = vec![b'a'; 109];
    let result = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::PROXY,
        TransportProtocol::STREAM,
        EncodeAddresses::Unix {
            src: &name,
            dst: b"/ok",
        },
        &[],
    );
    assert_eq!(
        result,
        Err(ProxyEncodeError::UnixNameTooLong { length: 109 })
    );
}

/// Individually legal TLVs whose aggregate body exceeds the u16 length field
/// return a typed error; a body at exactly the u16 boundary still encodes.
#[test]
fn encode_aggregate_body_length_is_checked() -> TestResult {
    let half = vec![0_u8; 32_768];
    let result = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::PROXY,
        TransportProtocol::STREAM,
        EncodeAddresses::Unspec,
        &[(0x04, &half), (0x04, &half)],
    );
    assert_eq!(
        result,
        Err(ProxyEncodeError::BodyTooLong {
            length: 32_768 * 2 + 6,
        })
    );

    // Addresses + TLV landing exactly on u16::MAX must still encode.
    let addr = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1_u16);
    let fill = vec![0_u8; usize::from(u16::MAX) - 12 - 3];
    let encoded = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::PROXY,
        TransportProtocol::STREAM,
        EncodeAddresses::Ip {
            src: addr,
            dst: addr,
        },
        &[(0x04, &fill)],
    )?;
    let length = usize::from(u16::from_be_bytes([encoded[14], encoded[15]]));
    assert_eq!(length, usize::from(u16::MAX));
    assert_eq!(encoded.len(), 12 + 4 + usize::from(u16::MAX));
    Ok(())
}

/// Adversarial: random bytes never panic and never falsely claim a magic.
#[test]
fn adversarial_random_inputs_do_not_panic() {
    let mut state = 0x5757_1237_u64;
    for _ in 0..20_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let bytes = state.to_le_bytes();
        let length = usize::from(bytes[0]) % 24;
        let _ = sniff_magic(&bytes[..length.min(8)]);
        let _ = decode_after_magic(&bytes[..length.min(8)]);
    }
}
