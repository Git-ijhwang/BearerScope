use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::ControlFlow;
use std::path::Path;
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::{Block, PcapNgReader};

const PCAPNG_MAGIC: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

pub struct RawPacket<'a> {
    pub timestamp: Duration,
    pub linktype: DataLink,
    pub orig_len: u32,
    pub data: &'a [u8],
}

fn read_pcap<F> (reader: BufReader<File>, f: &mut F) 
    -> Result<(), String>
where
    F: FnMut(RawPacket) -> ControlFlow<()>,
{
    let mut pcap = PcapReader::new(reader).map_err(|e| format!("invalid pcap: {e}"))?;

    let linktype = pcap.header().datalink;

    // while let Some(pkt) = pcap.next_packet() {
    while let Some(pkt) = pcap.next_packet() {
        // let pkt = pkt.map_err(|e| format!("correupted pcap packet: {e}"))?;
        let pkt = pkt.map_err(|e| format!("corrupted pcap packet: {e}"))?;

        let raw = RawPacket {
            timestamp: pkt.timestamp,
            linktype,
            orig_len: pkt.orig_len,

            data: &pkt.data,
        };
        if f(raw).is_break() {
            break;
        }
    }
    Ok(())
}

fn read_pcapng<F> (reader: BufReader<File>, f: &mut F) 
    -> Result<(), String>
where
    F: FnMut(RawPacket) -> ControlFlow<()>,
{
    let mut pcapng = PcapNgReader::new(reader).map_err(|e| format!("invalid pcapng: {e}"))?;

    let mut interfaces: Vec<DataLink> = Vec::new();
        while let Some(block) = pcapng.next_block() {
        let block = block.map_err(|e| format!("corrupted pcapng block: {e}"))?;
 
        let flow = match block {
            Block::SectionHeader(_) => {
                interfaces.clear();
                continue;
            }
            Block::InterfaceDescription(idb) => {
                interfaces.push(idb.linktype);
                continue;
            }
            Block::EnhancedPacket(epb) => {
                let Some(&linktype) = interfaces.get(epb.interface_id as usize) else {
                    return Err(format!("packet refers to unknown interface {}", epb.interface_id));
                };
                f(RawPacket {
                    timestamp: epb.timestamp,
                    linktype,
                    orig_len: epb.original_len,
                    data: &epb.data,
                })
            }
            Block::SimplePacket(spb) => {
                // Simple Packet Block은 항상 첫 번째 인터페이스에 속하고 타임스탬프가 없다
                let Some(&linktype) = interfaces.first() else {
                    return Err("simple packet before any interface description".into());
                };
                f(RawPacket {
                    timestamp: Duration::ZERO,
                    linktype,
                    orig_len: spb.original_len,
                    data: &spb.data,
                })
            }
            // 통계, 이름 해석 등 패킷이 아닌 블록은 건너뛴다
            _ => continue,
        };
 
        if flow.is_break() {
            break;
        }
    }
    Ok(())
}

pub fn for_each_packet<F>(path: &Path, mut f: F) -> Result< (), String >
where
    F: FnMut(RawPacket) -> ControlFlow<()>,
{
    let file = File::open(path).map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);

    let is_pcapng = reader
        .fill_buf()
        .map(|buf| buf.starts_with(&PCAPNG_MAGIC))
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    if is_pcapng {
        read_pcapng(reader, &mut f)
    } else {
        read_pcap(reader, &mut f)
    }
}