import { useEffect, useRef } from "react";
import Layer3Header from "../headers/Layer3Header";
import Layer4Header from "../headers/Layer4Header";
import GtpHeader from "../headers/gtp/GtpHeader";
import PfcpHeader from "../headers/pfcp/PfcpHeader";
import { protoLabel, splitDescription } from "./packetFormat";

/** One-line summaries shown while a layer is folded away */
function l3Summary(l3) {
  const [kind, h] = Object.entries(l3)[0] || [];
  if (!h) return { title: "Network layer", line: "" };
  const name = kind === "IP6" ? "IPv6" : "IPv4";
  return { title: name, line: `${h.src_addr} → ${h.dst_addr}` };
}

function l4Summary(l4) {
  const [kind, h] = Object.entries(l4 || {})[0] || [];
  if (!h) return { title: "Transport layer", line: "" };
  return { title: kind, line: h.src_port != null ? `${h.src_port} → ${h.dst_port}` : "" };
}

/** A header viewer that can be folded down to one line */
function LayerFold({ title, line, open, children }) {
  return (
    <details className="layer-group" open={open}>
      <summary>
        <span className="layer-group-title">{title}</span>
        <span className="data">{line}</span>
      </summary>
      <div className="layer-group-body">{children}</div>
    </details>
  );
}

export default function PacketInspector({ summary, detail, loading, error, onClose }) {
  const { text } = splitDescription(summary?.description);
  const app = detail?.packet.app;
  const hasApp = Boolean(app?.GTP || app?.PFCP);

  // Start each packet at the top of the pane
  const bodyRef = useRef(null);
  useEffect(() => { bodyRef.current?.scrollTo(0, 0); }, [summary?.id]);

  return (
    <section className="inspector" aria-label="Packet details">
      <header className="inspector-head">
        <div>
          <h2>Packet {summary?.id}{text ? ` · ${text}` : ""}</h2>
          {summary && (
            <div className="sub">
              <span className="data">{summary.src_ip}</span> to <span className="data">{summary.dst_ip}</span>
              {" "}over {protoLabel(summary)}
            </div>
          )}
        </div>
        <button className="close" onClick={onClose} aria-label="Close packet details" title="Close (Esc)">×</button>
      </header>
      {loading && <div className="loading-line" />}

      <div className="inspector-body" ref={bodyRef}>
        {error && <p>Couldn't decode this packet: {error}</p>}
        {detail && (
          <>
            {/* Layers in wire order. When there is a GTPv2-C or PFCP message,
                IP and UDP/TCP start folded so the message is visible right away. */}
            {detail.packet.l3.map((l3, idx) => {
              const { title, line } = l3Summary(l3);
              return (
                <LayerFold key={`${summary?.id}-l3-${idx}`} title={idx > 0 ? `${title} (inner)` : title}
                  line={line} open={!hasApp}>
                  <Layer3Header l3={l3} idx={idx} />
                </LayerFold>
              );
            })}
            {detail.packet.l4 && (
              <LayerFold key={`${summary?.id}-l4`} {...l4Summary(detail.packet.l4)} open={!hasApp}>
                <Layer4Header l4={detail.packet.l4} />
              </LayerFold>
            )}
            {app?.GTP && <GtpHeader gtp={app.GTP} />}
            {app?.PFCP && <PfcpHeader pfcp={app.PFCP} />}
          </>
        )}
      </div>
    </section>
  );
}
