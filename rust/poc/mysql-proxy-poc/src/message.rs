use anyhow::{bail, Result};

use crate::mysql_packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    Ok,
    Err { code: u16 },
    Eof,
    ResultSetHeader { column_count: u64 },
    Other,
}

fn read_lenenc_int(buf: &[u8]) -> Result<u64> {
    if buf.is_empty() {
        bail!("empty payload");
    }
    let first = buf[0];
    match first {
        0xfc => {
            if buf.len() < 3 { bail!("truncated 0xfc lenenc"); }
            Ok(u16::from_le_bytes([buf[1], buf[2]]) as u64)
        }
        0xfd => {
            if buf.len() < 4 { bail!("truncated 0xfd lenenc"); }
            Ok((buf[1] as u64) | ((buf[2] as u64) << 8) | ((buf[3] as u64) << 16))
        }
        0xfe => {
            if buf.len() < 9 { bail!("truncated 0xfe lenenc"); }
            Ok(u64::from_le_bytes(buf[1..9].try_into().unwrap()))
        }
        0xfb => bail!("NULL length-encoded integer unsupported as resultset header"),
        v => Ok(v as u64),
    }
}

pub fn classify_server_packet(packet: &Packet) -> Result<ServerMessage> {
    let payload = &packet.payload;
    if payload.is_empty() {
        bail!("empty packet payload");
    }

    match payload[0] {
        0x00 => Ok(ServerMessage::Ok),
        0xff => {
            if payload.len() < 3 {
                bail!("ERR packet too short");
            }
            let code = u16::from_le_bytes([payload[1], payload[2]]);
            Ok(ServerMessage::Err { code })
        }
        0xfe if payload.len() < 9 => Ok(ServerMessage::Eof),
        _ => Ok(ServerMessage::ResultSetHeader {
            column_count: read_lenenc_int(payload)?,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_server_packet, ServerMessage};
    use crate::mysql_packet::{Packet, PacketHeader};

    #[test]
    fn classify_ok_packet() {
        let p = Packet { header: PacketHeader { payload_len: 7, sequence_id: 2 }, payload: vec![0x00, 0, 0, 2, 0, 0, 0] };
        assert_eq!(classify_server_packet(&p).unwrap(), ServerMessage::Ok);
    }

    #[test]
    fn classify_err_packet() {
        let p = Packet { header: PacketHeader { payload_len: 3, sequence_id: 2 }, payload: vec![0xff, 0x15, 0x04] };
        assert_eq!(classify_server_packet(&p).unwrap(), ServerMessage::Err { code: 0x0415 });
    }

    #[test]
    fn classify_resultset_header() {
        let p = Packet { header: PacketHeader { payload_len: 1, sequence_id: 1 }, payload: vec![0x01] };
        assert_eq!(classify_server_packet(&p).unwrap(), ServerMessage::ResultSetHeader { column_count: 1 });
    }
}
