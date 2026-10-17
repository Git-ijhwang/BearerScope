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
