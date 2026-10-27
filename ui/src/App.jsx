import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";

import icon from "./assets/bearerscope-icon.svg";
import PacketList from "./components/packets/PacketList";
import PacketInspector from "./components/packets/PacketInspector";
import CallFlowView from "./components/callflow/CallFlowView";
import { openPacketWindow } from "./components/packets/openPacketWindow";


const CAPTURE_EXTENSIONS = ["pcap", "pcapng", "cap"];
const isMac = navigator.userAgent.includes("Mac");
const fileName = (p) => p?.split(/[\\/]/).pop();

export default function App() {
  const [pcapPath, setPcapPath] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Packet list
  const [filterText, setFilterText] = useState("");
  const [proto, setProto] = useState("all");
  const [selectedId, setSelectedId] = useState(null);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [details, setDetails] = useState({}); // id -> ParsedDetail | { error }
  const filterRef = useRef(null);

  // Call flow
  const [flow, setFlow] = useState(null); // { start, data, loading }
  const flowRequestRef = useRef(0);

  // ---------------------------------------------------------------- loading

  const loadCapture = useCallback(async (path) => {
    setPcapPath(path);
    setLoading(true);
    setError(null);
    setSummary(null);
    setSelectedId(null);
    setInspectorOpen(false);
    setDetails({});
    setFlow(null);
    setFilterText("");
    setProto("all");
    try {
      setSummary(await invoke("parse_summary", { path }));
    } catch (err) {
      setError(`Couldn't read ${fileName(path)}: ${err}`);
      setPcapPath(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const chooseCapture = useCallback(async () => {
    const path = await open({
      multiple: false,
      filters: [{ name: "Packet capture", extensions: CAPTURE_EXTENSIONS }],
    });
    if (path) loadCapture(path);
  }, [loadCapture]);

  // Dropping a capture file anywhere on the window opens it
  const [dragOver, setDragOver] = useState(false);
  useEffect(() => {
    let unlisten;
    getCurrentWebview().onDragDropEvent(({ payload }) => {
      if (payload.type === "enter" || payload.type === "over") setDragOver(true);
      else if (payload.type === "leave") setDragOver(false);
      else if (payload.type === "drop") {
        setDragOver(false);
        const path = payload.paths?.find((p) => CAPTURE_EXTENSIONS.includes(p.split(".").pop().toLowerCase()));
        if (path) loadCapture(path);
        else setError("Drop a .pcap, .pcapng or .cap file to open it.");
      }
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, [loadCapture]);

  // ---------------------------------------------------------------- details

  const selectPacket = useCallback((id) => {
    setSelectedId(id);
    setInspectorOpen(true);
  }, []);

  useEffect(() => {
    if (!inspectorOpen || selectedId == null || details[selectedId]) return;
    let stale = false;
    invoke("packet_detail", { path: pcapPath, id: selectedId })
      .then((d) => !stale && setDetails((m) => ({ ...m, [selectedId]: d })))
      .catch((e) => !stale && setDetails((m) => ({ ...m, [selectedId]: { error: String(e) } })));
    return () => { stale = true; };
  }, [inspectorOpen, selectedId, pcapPath, details]);

  const popOut = useCallback((pkt) => {
    openPacketWindow(pcapPath, pkt)
      .catch((e) => setError(`Couldn't open packet ${pkt.id} in a new window: ${e}`));
  }, [pcapPath]);

  // ---------------------------------------------------------------- call flow

  const openFlow = useCallback(async (id) => {
    const requestId = ++flowRequestRef.current;
    setFlow({ start: id, data: null, loading: true });
    try {
      const data = await invoke("call_flow", { path: pcapPath, id });
      if (requestId !== flowRequestRef.current) return;
      setFlow({ start: id, data, loading: false });
    } catch (err) {
      if (requestId !== flowRequestRef.current) return;
      setFlow(null);
      setError(`Couldn't trace a call flow from packet ${id}: ${err}`);
    }
  }, [pcapPath]);

  const closeFlow = useCallback(() => {
    flowRequestRef.current += 1; // ignore a response that is still on its way
    setFlow(null);
  }, []);

  // ---------------------------------------------------------------- keys

  useEffect(() => {
    const onKey = (e) => {
      const mod = isMac ? e.metaKey : e.ctrlKey;
      if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); chooseCapture(); return; }
      if (flow) return; // the call flow view handles its own keys
      const typing = e.target.closest?.("input, textarea");
      if (e.key === "/" && !typing && summary) { e.preventDefault(); filterRef.current?.focus(); }
      else if (e.key === "Escape" && typing) { e.target.blur(); }
      else if (e.key === "Escape" && inspectorOpen) { setInspectorOpen(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [chooseCapture, flow, summary, inspectorOpen]);

  // ---------------------------------------------------------------- view

  const selected = summary?.packets.find((p) => p.id === selectedId);
  const detail = details[selectedId];

  return (
    <div className="app">
      <header className="toolbar">
        <div className="brand"><img src={icon} alt="" />BearerScope</div>
        {pcapPath && summary && (
          <div className="capture-name" title={pcapPath}>
            <strong>{fileName(pcapPath)}</strong>
            <span>{summary.total_packets} packets</span>
          </div>
        )}
        <div className="toolbar-spacer" />
        <button className="btn-tool" onClick={chooseCapture} disabled={loading}>
          Open capture <kbd>{isMac ? "⌘O" : "Ctrl+O"}</kbd>
        </button>
      </header>

      <main className="workspace">
        {error && (
          <div className="banner" role="alert">
            <span>{error}</span>
            <button onClick={() => setError(null)} aria-label="Dismiss">×</button>
          </div>
        )}

        {!summary ? (
          <div className="empty">
            <div className={`dropzone ${dragOver ? "is-over" : ""}`}>
              <img src={icon} alt="" />
              <h1>{loading ? `Reading ${fileName(pcapPath)}…` : "Open a capture to start"}</h1>
              <p>
                BearerScope decodes GTPv2-C and PFCP signaling and shows how each
                bearer is set up, modified and released.
              </p>
              <button className="btn-primary-solid" onClick={chooseCapture} disabled={loading}>
                {loading ? "Reading…" : "Open capture"}
              </button>
              <p className="hint">Or drop a .pcap or .pcapng file here.</p>
            </div>
          </div>
        ) : flow ? (
          <CallFlowView
            key={`${flow.start}-${flow.loading}`}
            flow={flow.data}
            startPacket={flow.start}
            loading={flow.loading}
            onBack={closeFlow}
          />
        ) : (
          <div className={`packets-view ${inspectorOpen && selected ? "has-inspector" : ""}`}>
            <PacketList
              packets={summary.packets}
              selectedId={selectedId}
              onSelect={selectPacket}
              onOpenFlow={openFlow}
              filterText={filterText}
              onFilterText={setFilterText}
              proto={proto}
              onProto={setProto}
              filterRef={filterRef}
              onOpenWindow={popOut}
            />
            {inspectorOpen && selected && (
              <PacketInspector
                summary={selected}
                detail={detail?.error ? null : detail}
                error={detail?.error}
                loading={!detail}
                onClose={() => setInspectorOpen(false)}
                onPopOut={() => popOut(selected)}
              />
            )}
          </div>
        )}
      </main>
    </div>
  );
}
