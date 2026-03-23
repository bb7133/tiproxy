use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub payload_len: u32,
    pub sequence_id: u8,
}

impl PacketHeader {
    pub const LEN: usize = 4;

    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LEN {
            bail!("buffer too short for mysql packet header: {}", buf.len());
        }
        let payload_len = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16);
        let sequence_id = buf[3];
        Ok(Self {
            payload_len,
            sequence_id,
        })
    }

    pub fn encode(self) -> [u8; 4] {
        [
            (self.payload_len & 0xff) as u8,
            ((self.payload_len >> 8) & 0xff) as u8,
            ((self.payload_len >> 16) & 0xff) as u8,
            self.sequence_id,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::PacketHeader;

    #[test]
    fn parses_header() {
        let hdr = PacketHeader::parse(&[0x01, 0x02, 0x03, 0x09]).unwrap();
        assert_eq!(hdr.payload_len, 0x030201);
        assert_eq!(hdr.sequence_id, 0x09);
    }

    #[test]
    fn encodes_header() {
        let hdr = PacketHeader {
            payload_len: 0x00ab12,
            sequence_id: 7,
        };
        assert_eq!(hdr.encode(), [0x12, 0xab, 0x00, 0x07]);
    }
}
