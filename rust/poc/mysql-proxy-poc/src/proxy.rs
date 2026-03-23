use anyhow::Result;
use tokio::net::TcpStream;
use tracing::debug;

use crate::mysql_packet::Packet;

pub async fn forward_mysql_packets(frontend: TcpStream, backend: TcpStream) -> Result<()> {
    let (mut fr, mut fw) = frontend.into_split();
    let (mut br, mut bw) = backend.into_split();

    let client_to_backend = tokio::spawn(async move {
        loop {
            let packet = Packet::read_from(&mut fr).await?;
            debug!(seq = packet.header.sequence_id, len = packet.header.payload_len, dir = "client->backend", "packet");
            packet.write_to(&mut bw).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let backend_to_client = tokio::spawn(async move {
        loop {
            let packet = Packet::read_from(&mut br).await?;
            if packet.is_handshake_v10() {
                debug!(len = packet.header.payload_len, "detected initial mysql handshake packet");
            }
            debug!(seq = packet.header.sequence_id, len = packet.header.payload_len, dir = "backend->client", "packet");
            packet.write_to(&mut fw).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let (a, b) = tokio::join!(client_to_backend, backend_to_client);
    let _ = a??;
    let _ = b??;
    Ok(())
}
