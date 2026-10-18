import Layer3Header from "../headers/Layer3Header";
import Layer4Header from "../headers/Layer4Header";
import GtpHeader from "../headers/gtp/GtpHeader";
import PfcpHeader from "../headers/pfcp/PfcpHeader";
import { protoLabel, splitDescription } from "./packetFormat";

export default function PacketInspector({ summary, detail, loading, error, onClose }) {
  const { text } = splitDescription(summary?.description);

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

      <div className="inspector-body">
        {error && <p>Couldn't decode this packet: {error}</p>}
        {detail && (
          <>
            {detail.packet.l3.map((l3, idx) => (
              <Layer3Header key={idx} l3={l3} idx={idx} />
            ))}
            <Layer4Header l4={detail.packet.l4} />
            {detail.packet.app?.GTP && <GtpHeader gtp={detail.packet.app.GTP} />}
            {detail.packet.app?.PFCP && <PfcpHeader pfcp={detail.packet.app.PFCP} />}
          </>
        )}
      </div>
    </section>
  );
}
