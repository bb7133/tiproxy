use mysql_proxy_poc::mysql_packet::{Packet, PacketHeader};

#[test]
fn roundtrip_packet_header() {
    let hdr = PacketHeader { payload_len: 42, sequence_id: 3 };
    let raw = hdr.encode();
    let parsed = PacketHeader::parse(&raw).unwrap();
    assert_eq!(parsed, hdr);
}

#[test]
fn handshake_detection() {
    let pkt = Packet {
        header: PacketHeader { payload_len: 5, sequence_id: 0 },
        payload: vec![0x0a, b'8', b'.', b'0', 0x00],
    };
    assert!(pkt.is_handshake_v10());
}
