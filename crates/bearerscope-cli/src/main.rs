//! BearerScope CLI — pcap을 분석해서 JSON으로 출력한다.
//!
//! 예시:
//!   bearerscope summary  capture.pcap
//!   bearerscope packet   capture.pcap 12
//!   bearerscope callflow capture.pcap 12 --pretty > flow.json

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use serde::Serialize;

use bearerscope_core::gtp::call_flow::gtp_call_flow::make_call_flow;
use bearerscope_core::parse_pcap::{parse_single_packet, simple_parse_pcap};

#[derive(Parser)]
#[command(name = "bearerscope", version, about = "GTPv2-C / PFCP bearer & session analyzer")]
struct Cli {
    /// JSON을 사람이 읽기 좋게 들여쓰기해서 출력
    #[arg(long, global = true)]
    pretty: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 전체 패킷 요약 목록 (패킷 목록 화면용 데이터)
    Summary {
        /// pcap 또는 pcapng 파일
        pcap: PathBuf,
    },
    /// 패킷 하나의 상세 파싱 결과 (L3/L4/GTP/PFCP IE)
    Packet {
        pcap: PathBuf,
        /// 패킷 번호 (Wireshark와 같이 1부터 시작)
        id: usize,
    },
    /// 선택한 GTP 메시지가 속한 세션의 콜플로우와 bearer 상태 스냅샷
    Callflow {
        pcap: PathBuf,
        /// 기준이 되는 GTP 메시지의 패킷 번호
        id: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 코어는 아직 Result<_, String>을 쓰므로 anyhow 에러로 감싼다
    match cli.command {
        Command::Summary { pcap } => {
            let result = simple_parse_pcap(&pcap).map_err(|e| anyhow!(e))?;
            print_json(&result, cli.pretty)
        }
        Command::Packet { pcap, id } => {
            check_id(id)?;
            let result = parse_single_packet(&pcap, id).map_err(|e| anyhow!(e))?;
            print_json(&result, cli.pretty)
        }
        Command::Callflow { pcap, id } => {
            check_id(id)?;
            let result = make_call_flow(&pcap, id).map_err(|e| anyhow!(e))?;
            print_json(&result, cli.pretty)
        }
    }
}

/// 패킷 번호는 1부터 시작한다 (0이면 코어에서 id-1 언더플로가 난다)
fn check_id(id: usize) -> Result<()> {
    if id == 0 {
        return Err(anyhow!("packet id starts at 1"));
    }
    Ok(())
}

fn print_json<T: Serialize>(value: &T, pretty: bool) -> Result<()> {
    let json = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };

    // `| head` 처럼 출력을 받는 쪽이 먼저 닫혀도 에러로 취급하지 않는다
    match writeln!(io::stdout().lock(), "{json}") {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}