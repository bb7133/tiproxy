use anyhow::{bail, Result};

use crate::mysql_packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialHandshakeV10 {
    pub protocol_version: u8,
    pub server_version: String,
    pub connection_id: u32,
}

pub fn parse_initial_handshake(packet: &Packet) -> Result<InitialHandshakeV10> {
    if !packet.is_handshake_v10() {
        bail!("not a mysql handshake v10 packet");
    }
    let payload = &packet.payload;
    if payload.len() < 1 + 1 + 4 {
        bail!("handshake payload too short: {}", payload.len());
    }

    let protocol_version = payload[0];
    let mut idx = 1;
    let Some(end) = payload[idx..].iter().position(|b| *b == 0) else {
        bail!("server version not null-terminated");
    };
    let version_end = idx + end;
    let server_version = String::from_utf8(payload[idx..version_end].to_vec())?;
    idx = version_end + 1;

    if payload.len() < idx + 4 {
        bail!("missing connection id");
    }
    let connection_id = u32::from_le_bytes([
        payload[idx],
        payload[idx + 1],
        payload[idx + 2],
        payload[idx + 3],
    ]);

    Ok(InitialHandshakeV10 {
        protocol_version,
        server_version,
        connection_id,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_initial_handshake;
    use crate::mysql_packet::{Packet, PacketHeader};

    #[test]
    fn parse_basic_initial_handshake() {
        let payload = vec![
            0x0a,
            b'8', b'.', b'0', b'.', b'3', b'6', 0x00,
            0x2a, 0x00, 0x00, 0x00,
        ];
        let packet = Packet {
            header: PacketHeader { payload_len: payload.len() as u32, sequence_id: 0 },
            payload,
        };

        let hs = parse_initial_handshake(&packet).unwrap();
        assert_eq!(hs.protocol_version, 0x0a);
        assert_eq!(hs.server_version, "8.0.36");
        assert_eq!(hs.connection_id, 42);
    }
}
