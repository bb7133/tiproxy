use mysql_proxy_poc::mysql_packet::PacketHeader;

#[test]
fn roundtrip_packet_header() {
    let hdr = PacketHeader {
        payload_len: 42,
        sequence_id: 3,
    };
    let raw = hdr.encode();
    let parsed = PacketHeader::parse(&raw).unwrap();
    assert_eq!(parsed, hdr);
}
