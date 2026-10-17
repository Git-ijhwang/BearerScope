/*
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while building tauri application");
}
*/

use std::path::PathBuf;

use bearerscope_core::gtp::call_flow::gtp_call_flow::make_call_flow;
use bearerscope_core::gtp::call_flow::gtp_context::CallFlow;
use bearerscope_core::parse_pcap::{parse_single_packet, simple_parse_pcap};
use bearerscope_core::types::{ParsedDetail, ParsedResult};

/// 동기 명령은 UI 스레드에서 돌아 큰 pcap에서 창이 멈추므로 별도 스레드에서 실행
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("analysis task failed: {e}"))?
}

#[tauri::command]   // 기존 POST /api/parse
async fn parse_summary(path: PathBuf) -> Result<ParsedResult, String> {
    run_blocking(move || simple_parse_pcap(&path)).await
}

#[tauri::command]   // 기존 GET /api/packet_detail
async fn packet_detail(path: PathBuf, id: usize) -> Result<ParsedDetail, String> {
    if id == 0 { return Err("packet id starts at 1".into()); }
    run_blocking(move || parse_single_packet(&path, id)).await
}

#[tauri::command]   // 기존 POST /api/gtp/callflow
async fn call_flow(path: PathBuf, id: usize) -> Result<Vec<CallFlow>, String> {
    if id == 0 { return Err("packet id starts at 1".into()); }
    run_blocking(move || make_call_flow(&path, id)).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![parse_summary, packet_detail, call_flow])
        .run(tauri::generate_context!())
        .expect("error while running BearerScope");
}