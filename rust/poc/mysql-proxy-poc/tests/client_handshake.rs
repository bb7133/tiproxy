use mysql_proxy_poc::client_handshake::parse_handshake_response_41;
use mysql_proxy_poc::mysql_packet::{Packet, PacketHeader};

#[test]
fn parse_client_handshake_response_smoke() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&5u32.to_le_bytes());
    payload.extend_from_slice(&4096u32.to_le_bytes());
    payload.push(33);
    payload.extend_from_slice(&[0u8; 23]);
    payload.extend_from_slice(b"bb7133");
    payload.push(0);
    payload.push(0);

    let packet = Packet {
        header: PacketHeader { payload_len: payload.len() as u32, sequence_id: 1 },
        payload,
    };
    let hs = parse_handshake_response_41(&packet).unwrap();
    assert_eq!(hs.username, "bb7133");
    assert_eq!(hs.max_packet_size, 4096);
}
