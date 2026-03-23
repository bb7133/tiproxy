use mysql_proxy_poc::mysql_packet::{Packet, PacketHeader};
use mysql_proxy_poc::resultset::parse_select_1_resultset;

#[test]
fn parse_real_select1_capture() {
    let packets = vec![
        Packet { header: PacketHeader { payload_len: 1, sequence_id: 1 }, payload: vec![0x01] },
        Packet { header: PacketHeader { payload_len: 23, sequence_id: 2 }, payload: hex::decode("036465660000000131000c3f0001000000088100000000").unwrap() },
        Packet { header: PacketHeader { payload_len: 5, sequence_id: 3 }, payload: hex::decode("fe00000200").unwrap() },
        Packet { header: PacketHeader { payload_len: 2, sequence_id: 4 }, payload: hex::decode("0131").unwrap() },
        Packet { header: PacketHeader { payload_len: 5, sequence_id: 5 }, payload: hex::decode("fe00000200").unwrap() },
    ];
    let rs = parse_select_1_resultset(&packets).unwrap();
    assert_eq!(rs.column_count, 1);
    assert_eq!(rs.row_values, vec![b"1".to_vec()]);
}
