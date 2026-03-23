use mysql_proxy_poc::handshake::parse_initial_handshake;
use mysql_proxy_poc::mysql_packet::{Packet, PacketHeader};

#[test]
fn parse_initial_handshake_smoke() {
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
    assert_eq!(hs.server_version, "8.0.36");
    assert_eq!(hs.connection_id, 42);
}
