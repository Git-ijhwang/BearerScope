use crate::ip::port::*;
use crate::types::*;

pub fn parse_tcp_simple(tcp: &[u8], packet: &mut PacketSummary) -> u16
{
    if tcp.len() < 4 {
        eprintln!("TCP header too short ({} bytes)", tcp.len());
        return 0;
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

    packet.src_port = src_port;
    packet.dst_port = dst_port;
    packet.l4_type = "TCP".to_string();

    dst_port
}

/// Parse a TCP segment into `tcp`. Returns the destination port (0 when the
/// segment is too short to hold a TCP header).
pub fn parse_single_tcp(tcp_buf: &[u8], tcp: & mut TcpInfo) -> u16
{
    if tcp_buf.len() < TCP_HDR_LEN {
        eprintln!("TCP header too short ({} bytes)", tcp_buf.len());
        return 0;
    }

    let src_port = u16::from_be_bytes([tcp_buf[0], tcp_buf[1]]);
    let dst_port = u16::from_be_bytes([tcp_buf[2], tcp_buf[3]]);

    let seq_num = u32::from_be_bytes([tcp_buf[4], tcp_buf[5], tcp_buf[6], tcp_buf[7]]);
    let ack_num = u32::from_be_bytes([tcp_buf[8], tcp_buf[9], tcp_buf[10], tcp_buf[11]]);

    // Data offset: header length in 32-bit words, 5..15 (20..60 bytes) with options.
    // A bad value or a truncated capture is clamped to what is there.
    let data_offset = ((tcp_buf[12] >> 4) as usize * 4).clamp(TCP_HDR_LEN, tcp_buf.len());
    let flags = tcp_buf[13];

    let win_size = u16::from_be_bytes([tcp_buf[14], tcp_buf[15]]);
    let chksum   = u16::from_be_bytes([tcp_buf[16], tcp_buf[17]]);
    let urgent   = u16::from_be_bytes([tcp_buf[18], tcp_buf[19]]);

    tcp.src_port        = src_port;
    tcp.str_src_port    = port_to_str(src_port).unwrap_or_default();
    tcp.dst_port        = dst_port;
    tcp.str_dst_port    = port_to_str(dst_port).unwrap_or_default();
    tcp.seq             = seq_num;
    tcp.ack             = ack_num;
    tcp.flags           = flags;
    tcp.window          = win_size;
    tcp.header_sz       = data_offset as u8;
    tcp.checksum        = chksum;
    tcp.urgent          = urgent;
    tcp.raw.extend_from_slice(&tcp_buf[..TCP_HDR_LEN]);
    tcp.options.extend_from_slice(&tcp_buf[TCP_HDR_LEN..data_offset]);
    tcp.payload = (data_offset < tcp_buf.len()).then(|| tcp_buf[data_offset..].to_vec());

    dst_port
}


#[cfg(test)]
mod tests {
    use super::*;

    /// SYN with 12 bytes of options (MSS, SACK permitted, window scale) and 3 bytes of data
    fn syn_with_options() -> Vec<u8> {
        let mut b = vec![
            0xC0, 0x01, 0x00, 0x50,             // 49153 -> 80
            0x00, 0x00, 0x00, 0x64,             // seq 100
            0x00, 0x00, 0x00, 0x00,             // ack 0
            0x80, 0x02,                         // data offset 8 words (32 bytes), SYN
            0xFA, 0xF0,                         // window 64240
            0x12, 0x34,                         // checksum
            0x00, 0x07,                         // urgent pointer 7
        ];
        b.extend([0x02, 0x04, 0x05, 0xB4, 0x04, 0x02, 0x01, 0x03, 0x03, 0x07, 0x01, 0x01]);
        b.extend(b"abc");
        b
    }

    #[test]
    fn options_and_data_are_split_at_the_data_offset() {
        let mut tcp = TcpInfo::new();
        assert_eq!(parse_single_tcp(&syn_with_options(), &mut tcp), 80);
        assert_eq!(tcp.header_sz, 32);
        assert_eq!(tcp.raw.len(), 20);
        assert_eq!(tcp.options.len(), 12);
        assert_eq!(tcp.payload.as_deref(), Some(&b"abc"[..]));
        assert_eq!(tcp.urgent, 7);
        assert_eq!(tcp.window, 64240);
        assert_eq!(tcp.flags, 0x02);
    }

    #[test]
    fn no_payload_when_the_segment_ends_with_the_header() {
        let mut tcp = TcpInfo::new();
        parse_single_tcp(&syn_with_options()[..32], &mut tcp);
        assert!(tcp.payload.is_none());
    }

    #[test]
    fn short_or_truncated_segments_do_not_panic() {
        let mut tcp = TcpInfo::new();
        assert_eq!(parse_single_tcp(&[0u8; 10], &mut tcp), 0);
        // data offset says 32 bytes, capture holds 24: options are what is there
        let mut tcp = TcpInfo::new();
        parse_single_tcp(&syn_with_options()[..24], &mut tcp);
        assert_eq!((tcp.header_sz, tcp.options.len()), (24, 4));
        let mut s = PacketSummary::new();
        assert_eq!(parse_tcp_simple(&[0u8; 2], &mut s), 0);
    }
}
