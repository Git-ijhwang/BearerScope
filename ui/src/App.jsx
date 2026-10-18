import React, { useState, useRef } from "react";
import {Modal, Button} from "react-bootstrap";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";
import PacketTable from "./PacketTable"
import CallFlowView from "./components/callflow/CallFlowView"


function App() {
  // 웹 버전의 File 객체 + 서버 캐시 키(fileId) 대신, 로컬 파일 경로 하나로 충분하다
  const [pcapPath, setPcapPath] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [collapsed, setCollapsed] = useState(null);

  const [callFlowData, setCallFlowData] = useState(null);
  const [showCallFlow, setShowCallFlow] = useState(false);
  const [flowError, setFlowError] = useState(null);

  const [flowKey, setFlowKey] = useState(0);
  const flowRequestRef = useRef(0);

  const resetAll = () => {
    setPcapPath(null);
    setResult(null);
    setCallFlowData(null);
    setShowCallFlow(false);
    // 서버 임시 파일 정리(/api/cleanup)는 더 이상 필요 없다
  };

  // 파일 대화상자로 pcap을 고르고 바로 분석한다 (기존: 파일 선택 → Upload & Parse 두 단계)
  const openAndParse = async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: "Packet capture", extensions: ["pcap", "pcapng", "cap"] }],
    });
    if (!path) return; // 취소

    setPcapPath(path);
    setLoading(true);
    setResult(null);
    setShowCallFlow(false);

    try {
      // Rust: parse_summary(path) -> ParsedResult { file, total_packets, packets }
      const summary = await invoke("parse_summary", { path });
      setResult(summary);
    } catch (err) {
      console.error(err);
      setResult({ error: String(err) });
    } finally {
      setLoading(false);
    }
  };

  const fetchCallFlow = async (packetId) => {
    const requestId = ++flowRequestRef.current;

    setFlowError(null);
    setCallFlowData(null);
    setShowCallFlow(false);

    try {
      // Rust: call_flow(path, id) -> Vec<CallFlow>
      const data = await invoke("call_flow", { path: pcapPath, id: packetId });
      if (requestId !== flowRequestRef.current) return;
      setCallFlowData(data);
      setShowCallFlow(true);
      setFlowKey((k) => k + 1);
    }
    catch (err) {
      if (requestId !== flowRequestRef.current) return;
      console.error(err);
      setFlowError(`Failed to load call flow: ${err}`);
      setShowCallFlow(false);
    }
  };


  const handleBackFromCallFlow = () => {
    
    flowRequestRef.current++;
    setShowCallFlow(false);
    setCallFlowData(null);
  };


  return (
    <div className="container mt-4">
      <div className="fileopen-card card shadow p-4 ">

        <button type="button"
            className= "btn btn-sm btn-outline-secondary position-absolute"
          style={{top:"12px", right:"12px", margin:"12px"}}
            onClick={() => setCollapsed(c => !c)}
            aria-label="toggle collapse"
            >
          <i className={`bi ${collapsed ? "bi-chevron-down" : "bi-chevron-up"}`} />
        </button>

        <h1 className={`mb-3 parser-title
          ${collapsed ? "collapsed" : ""}`}>pcap file Parser </h1>

        {/* 🔽 Collapsible Area */}
        <div className={`collapse-wrapper ${collapsed ? "collapsed" : ""}`} >

          <div className="mb-3 text-muted small">
            {pcapPath ?? "No capture loaded"}
          </div>

          <div>
            <button
                className="btn btn-primary me-3"
                onClick={openAndParse}
                disabled={loading} >

              {loading ? "Parsing..." : "Open pcap…"}
            </button>

            <button
              className="btn btn-secondary "
              onClick={ resetAll }
              disabled={loading || !pcapPath}
            >
              Reset
            </button>

          </div>
        </div>
      </div>

      <div className="packetlist-card card shadow p-4">
        {result?.error && <div className="alert alert-danger">{result.error}</div>}
        {flowError && <div className="alert alert-warning">{flowError}</div>}
        {result?.packets && (

          <div className="viewport">
            <div className={`slider ${showCallFlow ? "shift" : ""}`}>

              {/* Table Panel */}
              <div className="panel table-panel">
                <PacketTable packets={result.packets} pcapPath={pcapPath}
                    onCallFlow={fetchCallFlow}
                    showCallFlow={showCallFlow} />
              </div>

              <div className="panel callflow-panel">
                { CallFlowView && (
                  < CallFlowView 
                    key={flowKey}
                    data={callFlowData}
                    loading={!callFlowData}
                    onBack={handleBackFromCallFlow} />
                )}
              </div>
            </div>
          </div>
        )}

        <Modal show={selectedPacket !== null} onHide={() => setSelectedPacket(null)} centered size="lg">
          <Modal.Header closeButton>
            <Modal.Title>Packet Detail (ID: {selectedPacket?.id}) </Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {selectedPacket ? (
              <div>
                {Object.entries(selectedPacket).map(([key, value]) => (
                  <p key={key}>
                    <strong>{key}</strong>: {String(value)}
                  </p>
                ))}
              </div>
            ) : null
            }
          </Modal.Body>

          <Modal.Footer>
            <Button variant="secondary"
              onClick={() => setSelectedPacket(null)}>
              Close
            </Button>
          </Modal.Footer>
        </Modal>

      </div>
    </div>
  );
}

export default App;

