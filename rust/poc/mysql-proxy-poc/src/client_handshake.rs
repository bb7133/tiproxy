use anyhow::{bail, Result};

use crate::mysql_packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshakeResponse41 {
    pub capability_flags: u32,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: String,
}

pub fn parse_handshake_response_41(packet: &Packet) -> Result<ClientHandshakeResponse41> {
    let payload = &packet.payload;
    if payload.len() < 4 + 4 + 1 + 23 + 1 {
        bail!("handshake response payload too short: {}", payload.len());
    }

    let capability_flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let max_packet_size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let character_set = payload[8];

    let mut idx = 4 + 4 + 1 + 23;
    let Some(end) = payload[idx..].iter().position(|b| *b == 0) else {
        bail!("username not null-terminated");
    };
    let username = String::from_utf8(payload[idx..idx + end].to_vec())?;
    idx += end + 1;

    if payload.len() <= idx {
        bail!("missing auth response length");
    }

    Ok(ClientHandshakeResponse41 {
        capability_flags,
        max_packet_size,
        character_set,
        username,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_handshake_response_41;
    use crate::mysql_packet::{Packet, PacketHeader};

    #[test]
    fn parse_basic_handshake_response_41() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        payload.extend_from_slice(&1024u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0u8; 23]);
        payload.extend_from_slice(b"root");
        payload.push(0);
        payload.push(0);

        let packet = Packet {
            header: PacketHeader { payload_len: payload.len() as u32, sequence_id: 1 },
            payload,
        };

        let hs = parse_handshake_response_41(&packet).unwrap();
        assert_eq!(hs.capability_flags, 1);
        assert_eq!(hs.max_packet_size, 1024);
        assert_eq!(hs.character_set, 45);
        assert_eq!(hs.username, "root");
    }
}
