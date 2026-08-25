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

//! Sans-I/O PROXY protocol v2 codecs matching Go `TiProxy` observable behavior.
//!
//! The Go reference is `pkg/proxy/proxyprotocol/{definition,proxy,listener}.go`
//! and the sniffing integration in `pkg/proxy/net/proxy.go`. Decoding is
//! deliberately as tolerant as Go: no field value is rejected, a short address
//! body yields no addresses, and leftover bytes are scanned as TLVs exactly the
//! way Go's parser does. Intentional encode-side strictness differences are
//! recorded in the parity manifest's WIRE-05 decision ledger.

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The 12-byte PROXY protocol v2 signature.
pub const MAGIC_V2: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// Bytes in the fixed header that follows the magic.
pub const FIXED_HEADER_LEN: usize = 4;

/// Fixed on-wire length of one PROXY v2 Unix address pair.
pub const UNIX_ADDRESS_PAIR_LEN: usize = 216;

/// Maximum Unix socket path bytes representable in a spec address block.
pub const UNIX_NAME_MAX: usize = 108;

/// PROXY protocol version nibble, wrapped without rejecting unknown values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyVersion(u8);

impl ProxyVersion {
    /// Version 2, the only value Go `TiProxy` emits.
    pub const V2: Self = Self(2);

    /// Wraps a raw version nibble.
    #[must_use]
    pub const fn from_nibble(value: u8) -> Self {
        Self(value & 0x0f)
    }

    /// Returns the raw version nibble.
    #[must_use]
    pub const fn as_nibble(self) -> u8 {
        self.0
    }
}

/// PROXY protocol command nibble, wrapped without rejecting unknown values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyCommand(u8);

impl ProxyCommand {
    /// The LOCAL command.
    pub const LOCAL: Self = Self(0);
    /// The PROXY command.
    pub const PROXY: Self = Self(1);

    /// Wraps a raw command nibble.
    #[must_use]
    pub const fn from_nibble(value: u8) -> Self {
        Self(value & 0x0f)
    }

    /// Returns the raw command nibble.
    #[must_use]
    pub const fn as_nibble(self) -> u8 {
        self.0
    }
}

/// PROXY protocol address-family nibble, preserved verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressFamily(u8);

impl AddressFamily {
    /// `AF_UNSPEC`.
    pub const UNSPEC: Self = Self(0);
    /// `AF_INET`.
    pub const INET: Self = Self(1);
    /// `AF_INET6`.
    pub const INET6: Self = Self(2);
    /// `AF_UNIX`.
    pub const UNIX: Self = Self(3);

    /// Wraps a raw family nibble.
    #[must_use]
    pub const fn from_nibble(value: u8) -> Self {
        Self(value & 0x0f)
    }

    /// Returns the raw family nibble.
    #[must_use]
    pub const fn as_nibble(self) -> u8 {
        self.0
    }
}

/// PROXY protocol transport nibble, preserved verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportProtocol(u8);

impl TransportProtocol {
    /// Unspecified transport.
    pub const UNSPEC: Self = Self(0);
    /// `SOCK_STREAM`.
    pub const STREAM: Self = Self(1);
    /// `SOCK_DGRAM`.
    pub const DGRAM: Self = Self(2);

    /// Wraps a raw transport nibble.
    #[must_use]
    pub const fn from_nibble(value: u8) -> Self {
        Self(value & 0x0f)
    }

    /// Returns the raw transport nibble.
    #[must_use]
    pub const fn as_nibble(self) -> u8 {
        self.0
    }
}

/// One decoded TLV borrowing its content from the input body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyTlv<'a> {
    /// Raw TLV type byte.
    pub type_byte: u8,
    /// Borrowed TLV content. Truncated declarations are clamped like Go.
    pub content: &'a [u8],
}

/// Decoded address information.
///
/// `None` reproduces Go's tolerant short-body and unknown-family handling: the
/// header parses, no addresses are populated, and the remaining body is still
/// scanned for TLVs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyAddresses<'a> {
    /// No address information was recovered.
    None,
    /// An IPv4 source/destination pair with ports.
    Inet {
        /// Source address and port.
        src: (Ipv4Addr, u16),
        /// Destination address and port.
        dst: (Ipv4Addr, u16),
    },
    /// An IPv6 source/destination pair with ports.
    Inet6 {
        /// Source address and port.
        src: (Ipv6Addr, u16),
        /// Destination address and port.
        dst: (Ipv6Addr, u16),
    },
    /// A Unix socket pair borrowing the fixed 108-byte path blocks.
    Unix {
        /// Source path block, NUL padding included.
        src: &'a [u8],
        /// Destination path block, NUL padding included.
        dst: &'a [u8],
    },
}

/// A decoded PROXY v2 header. Variable fields borrow the caller's buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeader<'a> {
    /// Raw version nibble.
    pub version: ProxyVersion,
    /// Raw command nibble.
    pub command: ProxyCommand,
    /// Raw address-family nibble.
    pub address_family: AddressFamily,
    /// Raw transport nibble.
    pub transport: TransportProtocol,
    /// Recovered address information.
    pub addresses: ProxyAddresses<'a>,
    /// TLVs scanned from the body remainder, Go-tolerantly.
    pub tlvs: Vec<ProxyTlv<'a>>,
}

/// Result of decoding the bytes that follow a confirmed magic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyV2Decode<'a> {
    /// More bytes are required; `needed_total` counts from the byte after the
    /// magic, so callers can size their next read exactly.
    Incomplete {
        /// Total post-magic bytes required before decoding can finish.
        needed_total: usize,
    },
    /// A complete header was decoded.
    Done {
        /// The decoded header.
        header: ProxyHeader<'a>,
        /// Post-magic bytes consumed by the header.
        consumed: usize,
    },
}

/// Decodes a PROXY v2 header from the bytes that follow the 12-byte magic.
///
/// Mirrors Go `ParseProxyV2`: no value validation, tolerant short address
/// bodies, clamped TLV lengths, and silently dropped sub-3-byte TLV tails.
/// When the address body is shorter than its family requires, Go leaves the
/// body cursor unadvanced, so address bytes are rescanned as TLVs; this
/// deliberate bug-for-bug behavior is kept and covered by tests.
#[must_use]
pub fn decode_after_magic(input: &[u8]) -> ProxyV2Decode<'_> {
    if input.len() < FIXED_HEADER_LEN {
        return ProxyV2Decode::Incomplete {
            needed_total: FIXED_HEADER_LEN,
        };
    }
    let version = ProxyVersion::from_nibble(input[0] >> 4);
    let command = ProxyCommand::from_nibble(input[0]);
    let address_family = AddressFamily::from_nibble(input[1] >> 4);
    let transport = TransportProtocol::from_nibble(input[1]);
    let body_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
    let total = FIXED_HEADER_LEN + body_length;
    if input.len() < total {
        return ProxyV2Decode::Incomplete {
            needed_total: total,
        };
    }
    let body = &input[FIXED_HEADER_LEN..total];

    let (addresses, tlv_bytes) = decode_addresses(address_family, transport, body);
    let tlvs = decode_tlvs(tlv_bytes);
    ProxyV2Decode::Done {
        header: ProxyHeader {
            version,
            command,
            address_family,
            transport,
            addresses,
            tlvs,
        },
        consumed: total,
    }
}

/// Splits the body into recovered addresses and the bytes Go would scan as TLVs.
///
/// Go's inner `switch network` populates addresses only for STREAM/DGRAM; an
/// unknown transport with a known family still advances past the address block
/// (unlike the short-body case, which leaves the cursor unadvanced).
fn decode_addresses(
    family: AddressFamily,
    transport: TransportProtocol,
    body: &[u8],
) -> (ProxyAddresses<'_>, &[u8]) {
    let known_transport =
        transport == TransportProtocol::STREAM || transport == TransportProtocol::DGRAM;
    match family {
        AddressFamily::INET | AddressFamily::INET6 => {
            let ip_len = if family == AddressFamily::INET { 4 } else { 16 };
            let need = ip_len * 2 + 4;
            if body.len() < need {
                // Go breaks without advancing the cursor: the short address
                // body is rescanned as TLV bytes.
                return (ProxyAddresses::None, body);
            }
            if !known_transport {
                return (ProxyAddresses::None, &body[need..]);
            }
            let src_port = u16::from_be_bytes([body[2 * ip_len], body[2 * ip_len + 1]]);
            let dst_port = u16::from_be_bytes([body[2 * ip_len + 2], body[2 * ip_len + 3]]);
            let addresses = if family == AddressFamily::INET {
                ProxyAddresses::Inet {
                    src: (ipv4_from(&body[..4]), src_port),
                    dst: (ipv4_from(&body[4..8]), dst_port),
                }
            } else {
                ProxyAddresses::Inet6 {
                    src: (ipv6_from(&body[..16]), src_port),
                    dst: (ipv6_from(&body[16..32]), dst_port),
                }
            };
            (addresses, &body[need..])
        }
        AddressFamily::UNIX => {
            if body.len() < UNIX_ADDRESS_PAIR_LEN {
                // Same Go behavior as the short INET body above.
                return (ProxyAddresses::None, body);
            }
            if !known_transport {
                return (ProxyAddresses::None, &body[UNIX_ADDRESS_PAIR_LEN..]);
            }
            (
                ProxyAddresses::Unix {
                    src: &body[..UNIX_NAME_MAX],
                    dst: &body[UNIX_NAME_MAX..UNIX_ADDRESS_PAIR_LEN],
                },
                &body[UNIX_ADDRESS_PAIR_LEN..],
            )
        }
        // Go's default branch skips the whole body, so no TLVs are scanned.
        _ => (ProxyAddresses::None, &body[body.len()..]),
    }
}

fn ipv4_from(bytes: &[u8]) -> Ipv4Addr {
    let mut octets = [0_u8; 4];
    octets.copy_from_slice(bytes);
    Ipv4Addr::from(octets)
}

fn ipv6_from(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets)
}

/// Scans TLVs with Go's tolerance: clamp truncated declarations, drop tails.
fn decode_tlvs(mut body: &[u8]) -> Vec<ProxyTlv<'_>> {
    let mut tlvs = Vec::new();
    while body.len() >= 3 {
        let declared = usize::from(u16::from_be_bytes([body[1], body[2]]));
        let available = body.len() - 3;
        let length = declared.min(available);
        tlvs.push(ProxyTlv {
            type_byte: body[0],
            content: &body[3..3 + length],
        });
        body = &body[3 + length..];
    }
    tlvs
}

/// Progress of matching the 12-byte magic against a growing prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicSniff {
    /// The prefix matches the magic so far but is not yet complete.
    NeedMore {
        /// Bytes of the magic already matched.
        matched: usize,
    },
    /// The prefix diverges from the magic: all buffered bytes are application
    /// data and none may be consumed, matching Go's fallback behavior.
    NotProxy,
    /// The full magic matched; decoding may consume it and continue.
    Proxy,
}

/// Incrementally matches the v2 magic, mirroring both Go integrations.
///
/// `pkg/proxy/net/proxy.go` first probes four bytes and then the full magic;
/// `pkg/proxy/proxyprotocol/listener.go` buffers up to twelve bytes while the
/// prefix keeps matching. Both reduce to this pure comparison: feed whatever
/// prefix has been buffered and act on the verdict.
#[must_use]
pub fn sniff_magic(prefix: &[u8]) -> MagicSniff {
    let compare = prefix.len().min(MAGIC_V2.len());
    if prefix[..compare] != MAGIC_V2[..compare] {
        return MagicSniff::NotProxy;
    }
    if prefix.len() >= MAGIC_V2.len() {
        return MagicSniff::Proxy;
    }
    MagicSniff::NeedMore { matched: compare }
}

/// Address input for encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeAddresses<'a> {
    /// Emit no address body, matching Go's unhandled-`net.Addr` fallthrough.
    Unspec,
    /// An IP pair; the family is unified exactly like Go's `unifyIPFamily`.
    Ip {
        /// Source IP and port.
        src: (std::net::IpAddr, u16),
        /// Destination IP and port.
        dst: (std::net::IpAddr, u16),
    },
    /// Unix socket paths, written unpadded exactly like Go's `ToBytes`.
    Unix {
        /// Source path bytes.
        src: &'a [u8],
        /// Destination path bytes.
        dst: &'a [u8],
    },
}

/// Typed encode failures.
///
/// Go silently truncates a TLV length above `u16::MAX` and writes Unix names
/// its own parser cannot round-trip; both are rejected here per the parity
/// manifest's WIRE-05 decision ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyEncodeError {
    /// A TLV content length does not fit the two-byte length field.
    TlvTooLong {
        /// Index of the offending TLV.
        index: usize,
        /// Supplied content length.
        length: usize,
    },
    /// A Unix path exceeds the 108-byte spec block Go's parser expects.
    UnixNameTooLong {
        /// Supplied path length.
        length: usize,
    },
    /// The aggregate body (addresses plus TLVs) exceeds the u16 length field.
    BodyTooLong {
        /// Computed body length.
        length: usize,
    },
}

impl fmt::Display for ProxyEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TlvTooLong { index, length } => write!(
                f,
                "PROXY v2 TLV #{index} content length {length} exceeds the u16 length field"
            ),
            Self::UnixNameTooLong { length } => write!(
                f,
                "PROXY v2 unix path length {length} exceeds the {UNIX_NAME_MAX}-byte block"
            ),
            Self::BodyTooLong { length } => write!(
                f,
                "PROXY v2 body length {length} exceeds the u16 length field"
            ),
        }
    }
}

impl std::error::Error for ProxyEncodeError {}

/// Encodes a complete PROXY v2 header, magic included.
///
/// Matches Go `Proxy.ToBytes` byte-for-byte for canonical inputs: IPv4 pairs
/// stay four bytes, any IPv6 or mixed pair widens both sides to sixteen bytes
/// via v4-mapped conversion, ports are big-endian, the u16 body length covers
/// addresses plus TLVs, and Unix paths are written unpadded (Go's own
/// asymmetry with its 216-byte parser, kept deliberately and documented).
///
/// # Errors
///
/// Returns a typed error for a TLV above `u16::MAX` bytes, a Unix path above
/// 108 bytes, or an aggregate body (addresses plus TLVs) above the u16 length
/// field, instead of Go's silent corruption at each of those points.
pub fn encode_proxy_v2(
    version: ProxyVersion,
    command: ProxyCommand,
    transport: TransportProtocol,
    addresses: EncodeAddresses<'_>,
    tlvs: &[(u8, &[u8])],
) -> Result<Vec<u8>, ProxyEncodeError> {
    let mut output = Vec::with_capacity(64);
    output.extend_from_slice(&MAGIC_V2);
    output.push((version.as_nibble() << 4) | (command.as_nibble() & 0x0f));
    // The family/transport byte and length are back-filled after the body.
    output.push(0);
    output.extend_from_slice(&[0, 0]);

    let family = match addresses {
        EncodeAddresses::Unspec => AddressFamily::UNSPEC,
        EncodeAddresses::Ip { src, dst } => match unify_ip_family(src.0, dst.0) {
            UnifiedIpPair::V4(src_ip, dst_ip) => {
                output.extend_from_slice(&src_ip.octets());
                output.extend_from_slice(&dst_ip.octets());
                output.extend_from_slice(&src.1.to_be_bytes());
                output.extend_from_slice(&dst.1.to_be_bytes());
                AddressFamily::INET
            }
            UnifiedIpPair::V6(src_ip, dst_ip) => {
                output.extend_from_slice(&src_ip.octets());
                output.extend_from_slice(&dst_ip.octets());
                output.extend_from_slice(&src.1.to_be_bytes());
                output.extend_from_slice(&dst.1.to_be_bytes());
                AddressFamily::INET6
            }
        },
        EncodeAddresses::Unix { src, dst } => {
            for name in [src, dst] {
                if name.len() > UNIX_NAME_MAX {
                    return Err(ProxyEncodeError::UnixNameTooLong { length: name.len() });
                }
            }
            output.extend_from_slice(src);
            output.extend_from_slice(dst);
            AddressFamily::UNIX
        }
    };

    for (index, (type_byte, content)) in tlvs.iter().enumerate() {
        let Ok(length) = u16::try_from(content.len()) else {
            return Err(ProxyEncodeError::TlvTooLong {
                index,
                length: content.len(),
            });
        };
        output.push(*type_byte);
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(content);
    }

    let body_length = output.len() - MAGIC_V2.len() - FIXED_HEADER_LEN;
    // Individually legal TLVs can still overflow the aggregate u16 body
    // length; reject instead of writing a header that lies about its body.
    let Ok(body_length) = u16::try_from(body_length) else {
        return Err(ProxyEncodeError::BodyTooLong {
            length: body_length,
        });
    };
    output[MAGIC_V2.len() + 1] = (family.as_nibble() << 4) | (transport.as_nibble() & 0x0f);
    let length_bytes = body_length.to_be_bytes();
    output[MAGIC_V2.len() + 2] = length_bytes[0];
    output[MAGIC_V2.len() + 3] = length_bytes[1];
    Ok(output)
}

/// The result of Go's `unifyIPFamily`.
enum UnifiedIpPair {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

/// Both v4 (including v4-mapped v6) stay v4; otherwise both widen to v6.
fn unify_ip_family(src: std::net::IpAddr, dst: std::net::IpAddr) -> UnifiedIpPair {
    let src4 = as_v4(src);
    let dst4 = as_v4(dst);
    match (src4, dst4) {
        (Some(s), Some(d)) => UnifiedIpPair::V4(s, d),
        _ => UnifiedIpPair::V6(as_v6(src), as_v6(dst)),
    }
}

/// Go `net.IP.To4`: a real IPv4 address or a `::ffff:a.b.c.d` mapped one.
fn as_v4(ip: std::net::IpAddr) -> Option<Ipv4Addr> {
    match ip {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Go `net.IP.To16` for an address already known to need widening.
fn as_v6(ip: std::net::IpAddr) -> Ipv6Addr {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn expect_done(input: &[u8]) -> Result<(ProxyHeader<'_>, usize), Box<dyn std::error::Error>> {
        match decode_after_magic(input) {
            ProxyV2Decode::Done { header, consumed } => Ok((header, consumed)),
            ProxyV2Decode::Incomplete { needed_total } => {
                Err(format!("expected complete decode, needed {needed_total}").into())
            }
        }
    }

    #[test]
    fn sniff_progression_and_divergence() {
        for length in 0..MAGIC_V2.len() {
            assert_eq!(
                sniff_magic(&MAGIC_V2[..length]),
                MagicSniff::NeedMore { matched: length }
            );
        }
        assert_eq!(sniff_magic(&MAGIC_V2), MagicSniff::Proxy);
        assert_eq!(sniff_magic(b"test"), MagicSniff::NotProxy);
        // First byte of a MySQL greeting (protocol 10) diverges immediately.
        assert_eq!(sniff_magic(&[10]), MagicSniff::NotProxy);
        // A diverging byte after a matching prefix is application data.
        let mut nearly = MAGIC_V2;
        nearly[11] = 0x00;
        assert_eq!(sniff_magic(&nearly), MagicSniff::NotProxy);
    }

    #[test]
    fn incomplete_inputs_report_exact_need() {
        assert_eq!(
            decode_after_magic(&[]),
            ProxyV2Decode::Incomplete { needed_total: 4 }
        );
        // Declared 300-byte body: need 4 + 300 in total.
        let header = [0x21, 0x11, 0x01, 0x2c];
        assert_eq!(
            decode_after_magic(&header),
            ProxyV2Decode::Incomplete { needed_total: 304 }
        );
    }

    #[test]
    fn short_inet_body_rescans_address_bytes_as_tlvs_like_go() -> TestResult {
        // INET declared, but the 8-byte body is short of the 12 bytes needed.
        // Go leaves the cursor unadvanced, so the body is scanned as TLVs.
        let mut input = vec![0x21, 0x11, 0x00, 0x08];
        input.extend_from_slice(&[0x05, 0x00, 0x02, 0xaa, 0xbb, 0x09, 0x00, 0x00]);
        let (header, consumed) = expect_done(&input)?;
        assert_eq!(consumed, 12);
        assert_eq!(header.addresses, ProxyAddresses::None);
        assert_eq!(header.tlvs.len(), 2);
        assert_eq!(header.tlvs[0].type_byte, 0x05);
        assert_eq!(header.tlvs[0].content, &[0xaa, 0xbb]);
        assert_eq!(header.tlvs[1].type_byte, 0x09);
        assert_eq!(header.tlvs[1].content, &[] as &[u8]);
        Ok(())
    }

    #[test]
    fn known_family_unknown_transport_skips_addresses_but_scans_tlvs_like_go() -> TestResult {
        // Go's inner network switch leaves Src/DstAddress nil for an unknown
        // transport but still advances past the address block, so trailing
        // bytes are scanned as TLVs.
        let mut input = vec![0x21, 0x13, 0x00, 0x10];
        input.extend_from_slice(&[0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x02]);
        input.extend_from_slice(&[0x00, 0x22, 0x16, 0x2e]);
        input.extend_from_slice(&[0x04, 0x00, 0x01, 0xaa]);
        let (header, _) = expect_done(&input)?;
        assert_eq!(header.transport, TransportProtocol::from_nibble(3));
        assert_eq!(header.addresses, ProxyAddresses::None);
        assert_eq!(header.tlvs.len(), 1);
        assert_eq!(header.tlvs[0].type_byte, 0x04);
        assert_eq!(header.tlvs[0].content, &[0xaa]);
        Ok(())
    }

    #[test]
    fn unknown_family_skips_body_without_tlvs_like_go() -> TestResult {
        let mut input = vec![0x21, 0xf1, 0x00, 0x06];
        input.extend_from_slice(&[0x01, 0x00, 0x01, 0xaa, 0xbb, 0xcc]);
        let (header, _) = expect_done(&input)?;
        assert_eq!(header.addresses, ProxyAddresses::None);
        assert!(header.tlvs.is_empty());
        Ok(())
    }

    #[test]
    fn oversized_tlv_declaration_is_clamped_like_go() -> TestResult {
        let mut input = vec![0x21, 0x11, 0x00, 0x05];
        input.extend_from_slice(&[0x01, 0xff, 0xff, 0x61, 0x62]);
        let (header, _) = expect_done(&input)?;
        assert_eq!(header.tlvs.len(), 1);
        assert_eq!(header.tlvs[0].content, b"ab");
        Ok(())
    }

    #[test]
    fn property_ip_round_trips_via_go_layout() -> TestResult {
        let mut state = 0x5050_3241_u64;
        for _ in 0..2_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let bytes = state.to_le_bytes();
            let src = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let dst = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            let src_port = u16::from_le_bytes([bytes[0], bytes[5]]);
            let dst_port = u16::from_le_bytes([bytes[2], bytes[7]]);
            let encoded = encode_proxy_v2(
                ProxyVersion::V2,
                ProxyCommand::PROXY,
                TransportProtocol::STREAM,
                EncodeAddresses::Ip {
                    src: (src.into(), src_port),
                    dst: (dst.into(), dst_port),
                },
                &[],
            )?;
            assert_eq!(sniff_magic(&encoded[..12]), MagicSniff::Proxy);
            let (header, consumed) = expect_done(&encoded[12..])?;
            assert_eq!(consumed, encoded.len() - 12);
            assert_eq!(
                header.addresses,
                ProxyAddresses::Inet {
                    src: (src, src_port),
                    dst: (dst, dst_port),
                }
            );
        }
        Ok(())
    }
}
