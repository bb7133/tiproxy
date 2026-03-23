use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
        Ok(Self { payload_len, sequence_id })
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl Packet {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut header_buf = [0u8; PacketHeader::LEN];
        reader.read_exact(&mut header_buf).await?;
        let header = PacketHeader::parse(&header_buf)?;
        let mut payload = vec![0u8; header.payload_len as usize];
        reader.read_exact(&mut payload).await?;
        Ok(Self { header, payload })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.header.encode()).await?;
        writer.write_all(&self.payload).await?;
        writer.flush().await?;
        Ok(())
    }

    pub fn is_handshake_v10(&self) -> bool {
        self.header.sequence_id == 0 && self.payload.first().copied() == Some(0x0a)
    }
}

#[cfg(test)]
mod tests {
    use super::{Packet, PacketHeader};

    #[test]
    fn parses_header() {
        let hdr = PacketHeader::parse(&[0x01, 0x02, 0x03, 0x09]).unwrap();
        assert_eq!(hdr.payload_len, 0x030201);
        assert_eq!(hdr.sequence_id, 0x09);
    }

    #[test]
    fn encodes_header() {
        let hdr = PacketHeader { payload_len: 0x00ab12, sequence_id: 7 };
        assert_eq!(hdr.encode(), [0x12, 0xab, 0x00, 0x07]);
    }

    #[test]
    fn detects_handshake_v10() {
        let pkt = Packet {
            header: PacketHeader { payload_len: 5, sequence_id: 0 },
            payload: vec![0x0a, b'8', b'.', b'0', 0x00],
        };
        assert!(pkt.is_handshake_v10());
    }
}
