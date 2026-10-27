use crate::types::*;

pub const ICMP_ECHO_REPLY: u8     = 0;
pub const ICMP_ECHO_REQUEST: u8     = 8;


/// ICMP (v4) message name, RFC 792
pub fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        5 => "Redirect",
        8 => "Echo Request",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        _ => "ICMP",
    }
}

pub fn parse_icmp_simple(icmp: &[u8], packet: &mut PacketSummary)
    -> u16
{
    packet.src_port = 0;
    packet.dst_port = 0;
    packet.description = icmp.first().map(|t| icmp_type_name(*t)).unwrap_or("ICMP").to_string();
    packet.l4_type = "ICMP".to_string();

    0
}
/*
    let icmp_type = u8::from_be_bytes([icmp[0]]);

    let mut desc = String::new();
    if icmp_type == ICMP_ECHO_REQ {
        desc = "Echo Request".to_string();
    }
    else if icmp_type == ICMP_ECHO_RSP {
        desc = "Echo Response".to_string();
    }

    packet.src_port = 0;
    packet.dst_port = 0;
    packet.description = desc;
    packet.l4_type = "ICMP".to_string();

    0
}
*/


pub fn parse_single_icmp(icmp_buf: &[u8], icmp: &mut IcmpInfo)
    -> u16
{
   // Type, code, checksum and the 4-byte rest-of-header; a truncated capture may be shorter
    if icmp_buf.len() < 8 {
        icmp.raw.extend_from_slice(icmp_buf);
        return 0;
    }
    let mut offset: usize = 0;

    let icmp_type = icmp_buf[offset];
    offset += 1;

    let code = icmp_buf[offset];
    offset += 1;

    let checksum = u16::from_be_bytes([icmp_buf[offset], icmp_buf[offset + 1]]);
    offset += 2;

    let id = u16::from_be_bytes([icmp_buf[offset], icmp_buf[offset + 1]]);
    offset += 2;

    let seq = u16::from_be_bytes([icmp_buf[offset], icmp_buf[offset + 1]]);
    offset += 2;

    icmp.icmp_type  = icmp_type;
    icmp.code       = code;
    icmp.checksum   = checksum;
    icmp.id         = id;
    icmp.seq        = seq;
    icmp.raw.extend_from_slice(&icmp_buf[0..offset]);
    icmp.payload = Some(icmp_buf[offset..].to_vec());

    0
}
