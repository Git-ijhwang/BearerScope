use std::ops::ControlFlow;
use std::path::Path;

use pcap_file::DataLink;

use crate::capture::{for_each_packet, RawPacket};

use crate::ip::{self, ipv4::*, ipv6::*, port::{self, *}};
use crate::l4::{tcp::*, udp::*, icmp::*};
use crate::gtp::{gtp::*, gtp_ie::*};
use crate::pfcp::{pfcp::*, pfcp_ie::*};
use crate::types::*;

const NEXT_HDR_IPV4: usize = 0x0800;
const NEXT_HDR_IPV6: usize = 0x86dd;






pub fn parse_ethernet(data: &[u8]) -> usize
{
    // let mut ethertype_str = String::from("N/A");
    let mut offset = 0;

    let src_mac = format!("Src Mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
    data[offset+0], data[offset+1], data[offset+2],
    data[offset+3], data[offset+4], data[offset+5]);

    offset += 6;

    let dst_mac = format!("Dst Mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
    data[offset+0], data[offset+1], data[offset+2],
    data[offset+3], data[offset+4], data[offset+5]);

    offset += 6;

    let next_type = u16::from_be_bytes([data[offset], data[offset+1]]) as usize;

    next_type
}

pub fn parse_sll2(data: &[u8]) -> usize
{
    if data.len() < 20 {
        return 0;
    }

    let protocol = u16::from_be_bytes([
        data[0],
        data[1]
    ]);

    match protocol {
        0x0800 => NEXT_HDR_IPV4,
        0x86DD => NEXT_HDR_IPV6,
        _ => 0,
    }
}


fn parse_l3( next_type: usize, ip_hdr: &[u8],
                    parsed_packet: &mut PacketDetail)
    -> (usize, usize)
{
    let mut ip= IpInfo::new();
    let mut ip6= Ip6Info::new();

    match next_type {
        PROTO_TYPE_IPINIP | NEXT_HDR_IPV4 => {
            let next_hdr_type = parse_ipv4(
                ip_hdr, &mut ip);
            parsed_packet.l3.push(Layer3Info::IP(ip));
            (next_hdr_type, IP_HDR_LEN)
        },

        NEXT_HDR_IPV6 => {
            let next_hdr_type = parse_ipv6(
                ip_hdr, &mut ip6);
            parsed_packet.l3.push(Layer3Info::IP6(ip6));
            (next_hdr_type, IP6_HDR_LEN)
        },

        _ =>  (0,0)
    }
}


fn parse_l4( next_type: usize,
                    data_buf: &[u8],
                    parsed_packet: &mut PacketDetail)
    -> (u16, usize)
{
    match next_type {
        PROTO_TYPE_TCP =>  {
            let mut tcp = TcpInfo::new();
            let result= parse_single_tcp( data_buf , &mut tcp);
            // The application layer starts after the options too
            let hdr_len = (tcp.header_sz as usize).max(TCP_HDR_LEN);

            parsed_packet.l4 = Layer4Info::TCP(tcp);
            (result, hdr_len)
        },

        PROTO_TYPE_UDP => {
            let mut udp = UdpInfo::new();
            let result = parse_single_udp( data_buf, &mut udp);

            parsed_packet.l4 = Layer4Info::UDP(udp);
            (result, UDP_HDR_LEN)
        },

        PROTO_TYPE_ICMP => {
            let mut icmp = IcmpInfo::new();
            let result = parse_single_icmp(data_buf, &mut icmp);

            parsed_packet.l4 = Layer4Info::ICMP(icmp);
            (result, ICMP_HDR_LEN)
        },

        _ =>  (0, 0)

    }

}

fn parse_app(port_number: u16,
    data_buf: &[u8],
    parsed_packet: &mut PacketDetail)
{
    match port_number {
        L4_PORT_GTPV2 => {
            let (rest, mut gtpinfo) =
                parse_gtpc_detail(data_buf)
                    .map_err( |e| format!("GTP-C parse error: {:?}", e)).unwrap();

            let result = match parse_all_ies(rest) {

                Ok(v) => v,
                Err(_) => {
                    // return Err(format!("Parse All failed: {}", e));
                    Vec::new()
                }
            };

            gtpinfo.ies = result;
            parsed_packet.app = AppLayerInfo::GTP(gtpinfo);
        },

        L4_PORT_PFCP => {
            let (rest, mut pfcpinfo) =
                parse_pfcp_detail(data_buf)
                    .map_err( |e| format!("PFCP parse error: {:?}", e)).unwrap();

            let result = match parse_all_pfcp_ies(rest) {
                Ok(v) => v,
                Err(_) => Vec::new(),
            };
            pfcpinfo.ies = result;
            parsed_packet.app = AppLayerInfo::PFCP(pfcpinfo);
        },

        _ => {
        },
    };
}


/// L2 링크 타입에 따라 (다음 헤더 타입, L2 헤더 길이)를 돌려준다.
/// 지원하지 않는 링크 타입이면 None.
fn parse_l2(packet: &RawPacket) -> Option<(usize, usize)>
{
    match packet.linktype {
        DataLink::ETHERNET if packet.data.len() >= MIN_ETH_HDR_LEN =>
            Some((parse_ethernet(packet.data), MIN_ETH_HDR_LEN)),
        DataLink::LINUX_SLL2 =>
            Some((parse_sll2(packet.data), 20)),
        _ => None,
    }
}


/// 패킷 하나를 L2부터 애플리케이션 계층까지 상세 파싱한다.
fn parse_packet_detail(packet: &RawPacket) -> Result<PacketDetail, String>
{
    let mut offset: usize = 0;
    let mut parsed_packet = PacketDetail::new();

    // --- Parse Layer 2 ---
    let (mut next_type, l2_len) = parse_l2(packet)
        .ok_or_else(|| format!("unsupported link type: {:?}", packet.linktype))?;
    offset += l2_len;

    // --- Parse Layer 3 (IPv4, IPinIP or IPv6) ---
    loop {
        let (np, l3_hdr_len) =
            parse_l3(next_type, &packet.data[offset..], &mut parsed_packet);

        offset += l3_hdr_len;
        next_type = np;

        if next_type != PROTO_TYPE_IPINIP {
            break;
        }
    }

    // --- Parse Layer 4 ---
    let (port_number, l4_hdr_len) =
        parse_l4(next_type, &packet.data[offset..], &mut parsed_packet);

    offset += l4_hdr_len;

    // --- Parse Application Layer ---
    parse_app(port_number, &packet.data[offset..], &mut parsed_packet);

    Ok(parsed_packet)
}


/// `id`번째 패킷(1부터 시작)을 상세 파싱한다.
pub fn parse_single_packet(path: &Path, id: usize)
    -> Result<ParsedDetail, String>
{
    let mut idx: usize = 1;
    let mut result: Option<Result<PacketDetail, String>> = None;

    for_each_packet(path, |packet| {
        if idx == id {
            result = Some(parse_packet_detail(&packet));
            return ControlFlow::Break(());
        }
        idx += 1;
        ControlFlow::Continue(())
    })?;

    let packet = result.ok_or_else(|| "Packet not found".to_string())??;

    Ok(ParsedDetail {
        id,
        packet,
    })
}


/// 패킷 목록 화면용 요약 파싱. 요약 대상이 아니면 None.
fn summarize_packet(idx: usize, packet: &RawPacket) -> Option<PacketSummary>
{
    let mut hdr_len = 0;
    let tot_len = packet.orig_len as usize;

    let mut parsed_packet : PacketSummary = PacketSummary::new();
    parsed_packet.id = idx;

    // --- Parse Layer 2 ---
    let (next_type, l2_len) = parse_l2(packet)?;
    hdr_len += l2_len;

    // --- Parse Layer 3 ---
    let next_type= match next_type {
        //IPv4
        NEXT_HDR_IPV4 => {
            if packet.data.len() < hdr_len + IP_HDR_LEN {
                return None;
            }
            parse_ipv4_simple(&packet.data[hdr_len..], &mut parsed_packet)
        },

        //IPv6
        NEXT_HDR_IPV6 => {
            if packet.data.len() < hdr_len + IP6_HDR_LEN {
                return None;
            }
            parse_ipv6_simple(&packet.data[hdr_len..], &mut parsed_packet)
        }

        _ => return None,
    };

    if next_type == 0 {
        return None;
    }

    // TODO: IPv6(40바이트)와 IPv4 옵션(IHL)을 반영하지 않음 — 기존 동작 유지, 이후 수정
    hdr_len += IP_HDR_LEN;

    // --- Parse Layer 4 ---
    let (port_number, l4_hdr_len) =
        match next_type {
            PROTO_TYPE_TCP   => {
                ( parse_tcp_simple ( &packet.data[hdr_len..], &mut parsed_packet), TCP_HDR_LEN)
            },

            PROTO_TYPE_UDP   => {
                ( parse_udp_simple ( &packet.data[hdr_len..], &mut parsed_packet), UDP_HDR_LEN)
            },

            PROTO_TYPE_ICMP   => {
                ( parse_icmp_simple ( &packet.data[hdr_len..], &mut parsed_packet), ICMP_HDR_LEN)
            },

            _ => return Some(parsed_packet),
        };

    if port_number == 0 || l4_hdr_len == 0 {
        return Some(parsed_packet);
    }

    hdr_len += l4_hdr_len;

    parsed_packet.length = tot_len - hdr_len;

    // --- Parse Application Layer ---
    match port_number {
        L4_PORT_GTPV2   => {
            parsed_packet.protocol = "GTP2-C".to_string();
            let _ = parse_gtpc (
                    &packet.data[hdr_len..],
                    &mut parsed_packet);
        },

        L4_PORT_PFCP => {
            parsed_packet.protocol = "PFCP".to_string();
            let _ = parse_pfcp( &packet.data[hdr_len..],
            &mut parsed_packet);
        },

        _ => {
        },
    };

    Some(parsed_packet)
}


/// 캡처 파일 전체를 요약 파싱한다 (패킷 목록 화면용).
pub fn simple_parse_pcap(path: &Path)
    -> Result<ParsedResult, String>
{
    let mut idx: usize = 1;
    let mut packets: Vec<PacketSummary> = Vec::new();

    for_each_packet(path, |packet| {
        if let Some(summary) = summarize_packet(idx, &packet) {
            packets.push(summary);
        }
        idx += 1;
        ControlFlow::Continue(())
    })?;

    Ok(ParsedResult {
        file: path.to_string_lossy().to_string(),
        total_packets: packets.len(),
        packets,
    })
}
