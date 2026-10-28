//! 골든 테스트: 검증된 pcap의 분석 결과를 저장해 두고, 코드를 고친 뒤에도
//! 결과가 그대로인지 비교한다.
//!
//! 기대값 갱신 (의도적으로 출력을 바꿨을 때만):
//!   UPDATE_GOLDEN=1 cargo test -p bearerscope-core --test golden

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use bearerscope_core::gtp::call_flow::gtp_call_flow::make_call_flow;
use bearerscope_core::parse_pcap::simple_parse_pcap;

/// 워크스페이스 루트의 tests/fixtures
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// 결과를 JSON으로 바꿔 `<이름>.json`과 비교한다.
/// JSON Value끼리 비교하므로 HashMap의 키 순서가 달라도 같다고 판단한다.
fn check_golden<T: Serialize>(name: &str, actual: &T) {
    let path = fixtures().join(format!("{name}.json"));
    let actual = serde_json::to_value(actual).unwrap();

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&actual).unwrap() + "\n").unwrap();
        return;
    }

    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (UPDATE_GOLDEN=1로 먼저 생성)", path.display())),
    )
    .unwrap();

    assert!(actual == expected, "{name}: 결과가 골든 파일과 다릅니다 ({})", path.display());
}

const GTP_PROCEDURE: &str = "gtp_procedure.pcap";

#[test]
fn gtp_procedure_summary() {
    let mut result = simple_parse_pcap(&fixtures().join(GTP_PROCEDURE)).unwrap();
    result.file = GTP_PROCEDURE.into(); // 절대 경로는 PC마다 다르므로 고정
    check_golden("gtp_procedure.summary", &result);
}

#[test]
fn gtp_procedure_callflow_from_first_create_session() {
    let flow = make_call_flow(&fixtures().join(GTP_PROCEDURE), 1).unwrap();
    check_golden("gtp_procedure.callflow.1", &flow);
}

// ---------------------------------------------------------------- one UE, two PDNs, dedicated bearers
// tests/fixtures/multi_bearer.pcap comes from tests/fixtures/gen_multi_bearer.py: the
// pcap_web_parser mock call flow as real GTPv2-C. Attach (LBI 5), network-initiated
// Create Bearer (EBI 9, 10, 11), a second PDN (LBI 7), Delete Bearer 10, Delete Session LBI 7.

const MULTI_BEARER: &str = "multi_bearer.pcap";

/// EBIs per LBI on each node after the last message
fn final_bearers(flow: &[bearerscope_core::gtp::call_flow::gtp_context::CallFlow])
    -> std::collections::BTreeMap<String, std::collections::BTreeMap<u8, Vec<u8>>>
{
    flow.last().unwrap().snapshot.iter()
        .map(|(node, st)| {
            let pdns = st.sessions.iter()
                .map(|(lbi, list)| {
                    let mut ebis: Vec<u8> = list.iter().map(|d| d.ebi).collect();
                    ebis.sort();
                    (*lbi, ebis)
                })
                .collect();
            (node.clone(), pdns)
        })
        .collect()
}

#[test]
fn multi_bearer_follows_every_message_from_any_start() {
    let path = fixtures().join(MULTI_BEARER);
    for start in [1, 7, 11, 17, 24] {
        let flow = make_call_flow(&path, start).unwrap();
        let ids: Vec<usize> = flow.iter().map(|m| m.id).collect();
        assert_eq!(ids, (1..=24).collect::<Vec<_>>(), "call flow from packet {start}");
    }
}

#[test]
fn multi_bearer_keeps_the_first_pdn_after_deleting_the_second() {
    let flow = make_call_flow(&fixtures().join(MULTI_BEARER), 1).unwrap();
    for (node, pdns) in final_bearers(&flow) {
        assert_eq!(pdns.into_iter().collect::<Vec<_>>(), vec![(5, vec![5, 9, 11])], "node {node}");
    }
    check_golden("multi_bearer.callflow.1", &flow);
}

#[test]
fn multi_bearer_keeps_new_bearers_apart_before_their_ebi_is_assigned() {
    let flow = make_call_flow(&fixtures().join(MULTI_BEARER), 1).unwrap();
    // Packet 8: SGW -> MME Create Bearer Request, three bearer contexts with EBI 0
    let step = flow.iter().find(|m| m.id == 8).unwrap();
    for (node, st) in &step.snapshot {
        let mut keys: Vec<u32> = st.sessions[&5].iter()
            .filter(|d| d.ebi == 0)
            .filter_map(|d| d.pending_key)
            .collect();
        keys.sort();
        assert_eq!(keys, [345, 346, 347], "pending bearers on {node}");
    }
}

#[test]
fn multi_bearer_shows_the_bearer_from_the_first_create_session_request() {
    let flow = make_call_flow(&fixtures().join(MULTI_BEARER), 1).unwrap();
    // Packet 1: MME -> SGW Create Session Request with EBI 5 and no F-TEID of the MME yet
    let step = &flow[0];
    for node in ["10.10.2.72", "10.10.1.71"] {
        let ebis: Vec<u8> = step.snapshot[node].sessions[&5].iter().map(|d| d.ebi).collect();
        assert_eq!(ebis, [5], "EBI 5 on {node} after packet 1");
        assert!(step.snapshot[node].sessions[&5][0].pending, "EBI 5 on {node} is being set up");
    }
}
