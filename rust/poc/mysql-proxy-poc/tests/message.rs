use mysql_proxy_poc::message::{classify_server_packet, ServerMessage};
use mysql_proxy_poc::mysql_packet::{Packet, PacketHeader};

#[test]
fn classify_real_select1_header_packet() {
    let p = Packet { header: PacketHeader { payload_len: 1, sequence_id: 1 }, payload: vec![0x01] };
    assert_eq!(classify_server_packet(&p).unwrap(), ServerMessage::ResultSetHeader { column_count: 1 });
}
