use anyhow::{bail, Result};

use crate::mysql_packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextResultSetSummary {
    pub column_count: u64,
    pub row_values: Vec<Vec<u8>>,
}

fn read_lenenc_int(buf: &[u8], idx: &mut usize) -> Result<u64> {
    if *idx >= buf.len() {
        bail!("lenenc int out of bounds");
    }
    let first = buf[*idx];
    *idx += 1;
    match first {
        0xfc => {
            if *idx + 2 > buf.len() { bail!("lenenc 0xfc truncated"); }
            let v = u16::from_le_bytes([buf[*idx], buf[*idx + 1]]) as u64;
            *idx += 2;
            Ok(v)
        }
        0xfd => {
            if *idx + 3 > buf.len() { bail!("lenenc 0xfd truncated"); }
            let v = (buf[*idx] as u64) | ((buf[*idx + 1] as u64) << 8) | ((buf[*idx + 2] as u64) << 16);
            *idx += 3;
            Ok(v)
        }
        0xfe => {
            if *idx + 8 > buf.len() { bail!("lenenc 0xfe truncated"); }
            let v = u64::from_le_bytes(buf[*idx..*idx + 8].try_into().unwrap());
            *idx += 8;
            Ok(v)
        }
        0xfb => bail!("NULL length-encoded integer not supported here"),
        v => Ok(v as u64),
    }
}

fn read_lenenc_str(buf: &[u8], idx: &mut usize) -> Result<Vec<u8>> {
    let len = read_lenenc_int(buf, idx)? as usize;
    if *idx + len > buf.len() {
        bail!("lenenc string truncated");
    }
    let out = buf[*idx..*idx + len].to_vec();
    *idx += len;
    Ok(out)
}

pub fn parse_select_1_resultset(packets: &[Packet]) -> Result<TextResultSetSummary> {
    if packets.len() < 5 {
        bail!("not enough packets for minimal text resultset: {}", packets.len());
    }
    let mut idx = 0usize;
    let mut pidx = 0usize;
    let column_count = read_lenenc_int(&packets[pidx].payload, &mut idx)?;
    pidx += 1;

    // Skip column definitions.
    for _ in 0..column_count {
        pidx += 1;
        if pidx > packets.len() {
            bail!("missing column definition packet");
        }
    }

    // Skip EOF/OK after columns.
    pidx += 1;
    if pidx >= packets.len() {
        bail!("missing row packet");
    }

    let row_packet = &packets[pidx];
    let mut ridx = 0usize;
    let mut row_values = Vec::new();
    for _ in 0..column_count {
        row_values.push(read_lenenc_str(&row_packet.payload, &mut ridx)?);
    }

    Ok(TextResultSetSummary { column_count, row_values })
}

#[cfg(test)]
mod tests {
    use super::parse_select_1_resultset;
    use crate::mysql_packet::{Packet, PacketHeader};

    #[test]
    fn parse_single_row_select_1_shape() {
        let packets = vec![
            Packet { header: PacketHeader { payload_len: 1, sequence_id: 1 }, payload: vec![0x01] },
            Packet { header: PacketHeader { payload_len: 1, sequence_id: 2 }, payload: vec![0x03] },
            Packet { header: PacketHeader { payload_len: 1, sequence_id: 3 }, payload: vec![0xfe] },
            Packet { header: PacketHeader { payload_len: 2, sequence_id: 4 }, payload: vec![0x01, b'1'] },
            Packet { header: PacketHeader { payload_len: 1, sequence_id: 5 }, payload: vec![0xfe] },
        ];
        let rs = parse_select_1_resultset(&packets).unwrap();
        assert_eq!(rs.column_count, 1);
        assert_eq!(rs.row_values, vec![b"1".to_vec()]);
    }
}
