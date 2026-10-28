import { useEffect, useState } from "react";
import CallFlowGraph from "./CallFlowGraph";

export default function CallFlowView({ flow, startPacket, loading, onBack, onOpenPacket }) {
  // Always start before the first message so the bearers build up step by step
  const [step, setStep] = useState(0);
  const total = flow?.length ?? 0;

  useEffect(() => {
    const onKey = (e) => {
      if (e.target.closest?.("input[type=search], textarea")) return;
      if (e.key === "ArrowRight") { e.preventDefault(); setStep((s) => Math.min(total, s + 1)); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); setStep((s) => Math.max(0, s - 1)); }
      else if (e.key === "Home") setStep(0);
      else if (e.key === "End") setStep(total);
      else if (e.key === "Escape") onBack();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [total, onBack]);

  const nodeCount = flow ? new Set(flow.flatMap((m) => [m.src_addr, m.dst_addr])).size : 0;

  return (
    <section className="flow-view" aria-label="Call flow">
      <header className="flow-head">
        <button className="btn-back" onClick={onBack} title="Back to packets (Esc)">‹ Packets</button>
        <div className="flow-title">
          <h2>Call flow from packet {startPacket}</h2>
          <span>{loading ? "Tracing the session…" : `${total} messages between ${nodeCount} nodes`}</span>
        </div>

        {!loading && total > 0 && (
          <div className="stepper">
            <button onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0}
              aria-label="Previous message" title="Previous message (←)">‹</button>
            <input type="range" min={0} max={total} value={step}
              onChange={(e) => setStep(Number(e.target.value))} aria-label="Step" />
            <button onClick={() => setStep((s) => Math.min(total, s + 1))} disabled={step === total}
              aria-label="Next message" title="Next message (→)">›</button>
            <span className="step-label">Step <strong>{step}</strong> of {total}</span>
          </div>
        )}
      </header>
      {loading && <div className="loading-line" />}

      <div className="flow-scroll">
        {!loading && total === 0 && <div className="flow-empty">This session has no GTPv2-C messages to show.</div>}
        {!loading && total > 0 && (
          <CallFlowGraph flow={flow} step={step} onStep={setStep} onOpenPacket={onOpenPacket} />
        ) }
      </div>
    </section>
  );
}
