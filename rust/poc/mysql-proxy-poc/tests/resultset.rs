use mysql_proxy_poc::mysql_packet::{Packet, PacketHeader};
use mysql_proxy_poc::resultset::parse_select_1_resultset;

#[test]
fn resultset_smoke() {
    let packets = vec![
        Packet { header: PacketHeader { payload_len: 1, sequence_id: 1 }, payload: vec![0x01] },
        Packet { header: PacketHeader { payload_len: 1, sequence_id: 2 }, payload: vec![0x03] },
        Packet { header: PacketHeader { payload_len: 1, sequence_id: 3 }, payload: vec![0xfe] },
        Packet { header: PacketHeader { payload_len: 2, sequence_id: 4 }, payload: vec![0x01, b'1'] },
        Packet { header: PacketHeader { payload_len: 1, sequence_id: 5 }, payload: vec![0xfe] },
    ];
    let rs = parse_select_1_resultset(&packets).unwrap();
    assert_eq!(rs.column_count, 1);
    assert_eq!(rs.row_values[0], b"1");
}
