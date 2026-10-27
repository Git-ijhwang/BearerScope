import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import PacketInspector from "./PacketInspector";

/** A packet opened in its own window: the inspector, full size */
export default function PacketWindow({ params }) {
  const path = params.get("path");
  const id = Number(params.get("id"));
  const [summary] = useState(() => {
    try { return JSON.parse(params.get("summary")); } catch { return { id }; }
  });
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    invoke("packet_detail", { path, id })
      .then(setDetail)
      .catch((e) => setError(String(e)));
  }, [path, id]);

  const close = () => getCurrentWindow().close();

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") close(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="packet-window">
      <PacketInspector
        summary={summary}
        detail={detail}
        error={error}
        loading={!detail && !error}
        onClose={close}
      />
    </div>
  );
}