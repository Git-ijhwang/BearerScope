import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

export default function App() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function openPcap() {
    const path = await open({ filters: [{ name: "Capture", extensions: ["pcap", "pcapng", "cap"] }] });
    if (!path) return;
    try {
      setError("");
      setResult(await invoke("parse_summary", { path }));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <main style={{ padding: 24, fontFamily: "sans-serif" }}>
      <h1>BearerScope</h1>
      <button onClick={openPcap}>Open pcap…</button>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {result && (
        <>
          <p>{result.file}: {result.total_packets} packets</p>
          <ul>
            {result.packets.slice(0, 10).map((p) => (
              <li key={p.id}>#{p.id} {p.src_ip} → {p.dst_ip} {p.protocol} {p.description}</li>
            ))}
          </ul>
        </>
      )}
    </main>
  );
}