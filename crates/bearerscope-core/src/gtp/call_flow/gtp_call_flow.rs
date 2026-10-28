use std::net::Ipv4Addr;
use std::vec;
use serde::{Serialize, Deserialize};
use std::ops::ControlFlow;
use std::path::Path;
use std::collections::HashMap;

use crate::ip::{ipv4::*, port::*};
use crate::l4::udp::*;
use crate::gtp::{gtp::*, gtp_ie::*, gtpv2_types::*};
use crate::types::*;
use crate::parse_pcap::*;
use super::gtp_context::*;

#[cfg(feature = "mock")]
use super::call_flow_test::*;


#[derive(Serialize, Debug, Clone)]
pub struct Ip5Tuple {
    pub protocol: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}
impl Ip5Tuple{
    pub fn new() -> Self {
        Ip5Tuple {
            protocol: 0,
            src_addr: Ipv4Addr::new(0, 0, 0, 0),
            dst_addr: Ipv4Addr::new(0, 0, 0, 0),
            src_port: 0,
            dst_port: 0,
        }
    }
}

#[derive(Serialize, Debug)]
struct OwnedPacket {
    idx: i32,
    data: Vec<u8>,
    ies: Vec<GtpIe>,
}

fn load_pcap(path: &Path) -> Result<Vec<OwnedPacket>, String> {
    let mut idx: i32 = 1;
    let mut packets = Vec::new();

    // TODO: 아래 분석 코드는 Ethernet(14바이트) + IPv4(20바이트) 고정 오프셋을 가정한다.
    //       Linux SLL2 캡처나 IPv6 시그널링에서는 오프셋이 어긋난다 — 이후 수정.
    crate::capture::for_each_packet(path, |pkt| {
        packets.push(
            OwnedPacket {
                idx,
                data: pkt.data.to_vec(),
                ies: Vec::new()
            }
        );
        idx += 1;
        ControlFlow::Continue(())
    })?;

    Ok(packets)
}



fn
extract_imsi( ies: Vec<GtpIe>)
-> String
{
    let t = find_ie_imsi(&ies);
    let imsi = match t {
        Ok(imsi_value) => {
            imsi_value
        },
        Err(e) => {
            return "".to_string();
        }
    };

    return imsi;
}

fn extract_bearer_ctx(ies: Vec<GtpIe>)
-> Result<Vec<Bearer>, String>
{
    let mut bearer_list = Vec::new();

    let ret = find_ie_bearer_ctx(&ies.clone());
    let bearer_ctxs = match ret {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("Not exist BEARER CONTEXT IE").to_string());
        }
    };

    for bearer_ctx in bearer_ctxs {
        let mut bearer = Bearer::new();

        let ret = find_ie_ebi_in_bearer_ctx(&bearer_ctx.clone());
        let ebi = match ret {
            Ok(v) => v,
            Err(e) =>  0,
            
        };
        bearer.ebi = ebi;

        let ret = find_ie_fteid(&bearer_ctx.clone());
        let fteid = match ret {
            Ok(v) => v,
            Err (e) => vec![],
            
        };
        // bearer.fteid_list = fteid_list;
        if !fteid.is_empty() {
            bearer.fteid_list = Some(fteid);
        }
        if bearer.ebi>=5 || bearer.fteid_list.iter().len()> 0 {
            bearer_list.push(bearer);
        }
    }

    Ok(bearer_list)
}


pub fn check_gtp(packet: &OwnedPacket)
-> bool
{
    let mut offset: usize = MIN_ETH_HDR_LEN;
    let mut next_type = 0;

    if packet.data.len() >= MIN_ETH_HDR_LEN {
        next_type = parse_ethernet(&packet.data);
    }
    if next_type != 0x0800 {
        return false
    }

    // --- Parse Layer 3 ---
    let next_proto = get_next_proto(&packet.data[offset..]);
    if next_proto != PROTO_TYPE_UDP {
        return false;
    }

    offset += IP_HDR_LEN;
    let (src_port, dst_port) = get_udp_port(&packet.data[offset..]);
    if src_port != L4_PORT_GTPV2 && dst_port != L4_PORT_GTPV2 {
        return false;
    }

    true
}



fn filtered_as_gtp(vec_packets: Vec<OwnedPacket>)
->Result<Vec<OwnedPacket>, String>
{
    let mut filtered_packets = Vec::new();

    for pkt in vec_packets.into_iter() {

        if check_gtp(&pkt) {
            filtered_packets.push(pkt);
        }
    }
    if filtered_packets.is_empty() {
        return Err("No GTP packets in pcap file".to_string());
    }

    Ok(filtered_packets)
}

// ------------------------------------------------------------------ message selection
//
// A UE's GTP-C messages are found the way the nodes themselves find them:
//
//  * a request belongs to the UE if it carries the UE's IMSI (Create Session
//    Request, also for a second PDN connection), or if its header TEID is one
//    the UE's peers handed out in a Sender F-TEID (every later request on S11
//    and S5/S8, including network-initiated Create/Update/Delete Bearer);
//  * a Create Session Request with TEID 0 and no IMSI belongs to the UE when
//    the sender is still answering a Create Session Request for it (the S5/S8
//    leg an SGW opens while the S11 request is in progress);
//  * a response belongs to the UE if it answers one of those requests:
//    same sequence number, from the node the request went to.
//
// Control-plane F-TEIDs in any selected message are learned as they appear,
// so the S11 and S5/S8 tunnels of every PDN connection are followed.

struct GtpMsg {
    pkt: OwnedPacket,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    msg_type: u8,
    teid: u32,
    seq: u32,
    imsi: String,
}

fn parse_gtp_msg(mut pkt: OwnedPacket) -> Option<GtpMsg>
{
    let offset = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let gtp = pkt.data.get(offset..)?;
    let (_, hdr) = get_gtp_header(gtp).ok()?;
    let ies = gtp.get(get_gtp_hdr_len(gtp)..).map(|b| parse_all_ies(b).unwrap_or_default()).unwrap_or_default();
    let (src, dst) = get_ip_addr(&pkt.data[MIN_ETH_HDR_LEN..]);
    let imsi = extract_imsi(ies.clone());
    pkt.ies = ies;
    Some(GtpMsg {
        src,
        dst,
        msg_type: hdr.msg_type,
        teid: hdr.teid.unwrap_or(0),
        seq: hdr.seq,
        imsi,
        pkt,
    })
}

/// (address, TEID) of every F-TEID at the top level of a message: the sender's
/// and, in responses, the peer's control-plane endpoints
fn control_fteids(ies: &[GtpIe]) -> Vec<(Ipv4Addr, u32)>
{
    ies.iter().filter_map(|ie| match &ie.ie_value {
        IeValue::FTeid(f) if ie.ie_type == GTPV2C_IE_FTEID && f.teid != 0 =>
            f.ipv4.as_deref().and_then(|a| a.parse().ok()).map(|a| (a, f.teid)),
        _ => None,
    }).collect()
}

/// Indexes into `msgs` of every message of the UE with this IMSI, in capture order
fn track_ue(msgs: &[GtpMsg], imsi: &str) -> Vec<usize>
{
    use std::collections::HashSet;

    // TEIDs the UE's nodes expect in the header of messages sent to them
    let mut teids: HashSet<(Ipv4Addr, u32)> = HashSet::new();
    // Requests waiting for their response: (requester, responder, sequence)
    let mut pending: HashSet<(Ipv4Addr, Ipv4Addr, u32)> = HashSet::new();
    // Nodes in the middle of a Create Session for the UE: they may open the next leg
    let mut creating: HashSet<Ipv4Addr> = HashSet::new();
    let mut selected = Vec::new();

    for (i, m) in msgs.iter().enumerate() {
        let is_response = pending.remove(&(m.dst, m.src, m.seq));

        let belongs = is_response
            || (!imsi.is_empty() && m.imsi == imsi)
            || (m.teid != 0 && teids.contains(&(m.dst, m.teid)))
            || (m.msg_type == GTPV2C_CREATE_SESSION_REQ && m.teid == 0 && m.imsi.is_empty()
                && creating.contains(&m.src));
        if !belongs {
            continue;
        }

        selected.push(i);
        teids.extend(control_fteids(&m.pkt.ies));

        if is_response {
            if m.msg_type == GTPV2C_CREATE_SESSION_RSP {
                creating.remove(&m.src);
            }
        } else {
            pending.insert((m.src, m.dst, m.seq));
            if m.msg_type == GTPV2C_CREATE_SESSION_REQ {
                creating.insert(m.dst);
            }
        }
    }
    selected
}

/// The GTP-C messages of the UE that packet `id` belongs to.
/// Works from any message of the session, not only a Create Session Request.
fn select_session(gtp_packets: Vec<OwnedPacket>, id: usize) -> Result<Vec<OwnedPacket>, String>
{
    let msgs: Vec<GtpMsg> = gtp_packets.into_iter().filter_map(parse_gtp_msg).collect();
    let start = msgs.iter().position(|m| m.pkt.idx as usize == id)
        .ok_or_else(|| format!("Packet {id} is not a GTPv2-C message"))?;

    // The start packet's IMSI, or else every UE seen in the capture
    let candidates: Vec<String> = if !msgs[start].imsi.is_empty() {
        vec![msgs[start].imsi.clone()]
    } else {
        let mut seen = Vec::new();
        for m in &msgs {
            if !m.imsi.is_empty() && !seen.contains(&m.imsi) {
                seen.push(m.imsi.clone());
            }
        }
        seen
    };

    let chosen = candidates.iter()
        .map(|imsi| track_ue(&msgs, imsi))
        .find(|sel| sel.contains(&start))
        .ok_or_else(|| format!("Couldn't tell which UE packet {id} belongs to (no Create Session Request for it in the capture)"))?;

    let mut keep = chosen.into_iter().peekable();
    let mut out = Vec::new();
    for (i, m) in msgs.into_iter().enumerate() {
        if keep.peek() == Some(&i) {
            keep.next();
            out.push(m.pkt);
        }
    }
    Ok(out)
}


fn
make_data( flow_packets: Vec<OwnedPacket>)
-> Result<Vec<CallFlow>, String>
{
    let mut call_flow= Vec::new();

    for pkt in flow_packets {
        let mut offset: usize = 0;
        let mut cf = CallFlow::new();

        cf.id = pkt.idx as usize;

        offset += MIN_ETH_HDR_LEN;

        let (src_addr, dst_addr) = get_ip_addr(&pkt.data[offset..]);

        cf.src_addr.push_str(&src_addr.to_string());
        cf.dst_addr.push_str(&dst_addr.to_string());

        offset += IP_HDR_LEN + UDP_HDR_LEN;

        let (_, message) = get_msg_type_from_gtpc (&pkt.data[offset..]).map_err(|e| format!("Error: {:?}", e))?;

        cf.message.push_str(&message);

        let ret = extract_bearer_ctx(pkt.ies.clone());
        cf.bearer = match ret {
            Ok(v) => {
                Some(v)
            },
            Err(e) => {
                eprintln!("{}", e);
                None
            }
        };

        let ret = find_ie_ebi(&pkt.ies.clone());
        cf.ebi = match ret {
            Ok(v) => Some(v),
            Err(e) => {
                format!("Not Exist EBI IE ").to_string();
                None
            }
        };

        call_flow.push(cf);
    }

    return Ok(call_flow);
}


fn
make_snapshot(mut call_flows: Vec<CallFlow>) -> Vec<CallFlow>
{
    let mut state: HashMap<String, NodeState> = HashMap::new();

    for cf in call_flows.iter_mut() {
        // 기존에 정의한 state 업데이트 로직 호출
        update_global_state(cf , &mut state);
        
        // 해당 시점의 상태를 스냅샷으로 저장
        cf.snapshot = state.clone();
    }
    call_flows
}


pub fn
make_call_flow (path: &Path, id: usize)
-> Result<Vec<CallFlow>, String>
{
    //1. convert whole packets of pcap to vec
    let vec_packets = load_pcap(path)?;
    if id == 0 || id > vec_packets.len() {
        return Err("Packet not found".to_string());
    }

    //2. This Callflow Feature can analyze only GTP messages
    let gtp_packets = filtered_as_gtp(vec_packets)?;

    //3. Every GTP-C message of the UE that packet `id` belongs to
    let packets = select_session(gtp_packets, id)?;

    //4. Make Call Flow raw data
#[cfg(not(feature = "mock"))]
    let mut call_flow = make_data( packets)?;

    //5. Only for Mock Test
#[cfg(feature = "mock")]
    let mut call_flow = make_mock_callflow();


    let callflow_snapshot = make_snapshot(call_flow);

    return Ok(callflow_snapshot)
}