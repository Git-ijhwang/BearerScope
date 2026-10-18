import { useEffect, useMemo, useRef, useState } from "react";
import { flowNodes, hex, laneNames, tunnelsAt } from "./flowModel";

const ROW_H = 44;
const MARGIN_L = 112;
const MARGIN_R = 72;
const TUNNEL_ROW_H = 58;

const STATE_STYLE = {
  up: { stroke: "var(--tunnel)", fill: "var(--tunnel-soft)", dash: null, text: "Up" },
  pending: { stroke: "var(--signal)", fill: "var(--signal-soft)", dash: "6 4", text: "Being set up" },
  releasing: { stroke: "var(--danger)", fill: "var(--danger-soft)", dash: "6 4", text: "Being released" },
};

function useWidth(ref) {
  const [w, setW] = useState(1000);
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const ro = new ResizeObserver(([e]) => setW(Math.max(760, Math.floor(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return w;
}

function Tunnel({ t, x, y }) {
  const st = STATE_STYLE[t.state];
  const both = t.a && t.b;
  const ax = t.a ? x[t.a.node] : null;
  const bx = t.b ? x[t.b.node] : null;
  // With only one end known, draw a short stub toward where the peer will be
  const x1 = both ? Math.min(ax, bx) : (t.a ? ax : bx - 120);
  const x2 = both ? Math.max(ax, bx) : (t.a ? ax + 120 : bx);
  const mid = (x1 + x2) / 2;
  const h = 14;

  return (
    <g>
      <text className="tunnel-label" x={mid} y={y - 12} textAnchor="middle" fill={st.stroke}>
        {t.iface}{t.state !== "up" ? ` · ${st.text}` : ""}{!both && t.state !== "releasing" ? " · waiting for peer" : ""}
      </text>
      <rect x={x1} y={y - h / 2} width={x2 - x1} height={h} rx={h / 2}
        fill={st.fill} stroke={st.stroke} strokeWidth={2} strokeDasharray={st.dash || undefined} />
      {t.state === "up" && both && (
        <line x1={x1 + 14} x2={x2 - 14} y1={y} y2={y} stroke="var(--signal)" strokeWidth={4}
          strokeLinecap="round" strokeDasharray="0.1 18" />
      )}
      {t.a && <text className="tunnel-teid" x={ax + (both && ax > bx ? -10 : 10)} y={y + 22}
        textAnchor={both && ax > bx ? "end" : "start"}>{hex(t.a.teid)}</text>}
      {t.b && <text className="tunnel-teid" x={bx + (both && bx > ax ? -10 : 10)} y={y + 22}
        textAnchor={both && bx > ax ? "end" : "start"}>{hex(t.b.teid)}</text>}
    </g>
  );
}

export default function CallFlowGraph({ flow, step, onStep }) {
  const wrapRef = useRef(null);
  const width = useWidth(wrapRef);

  const nodes = useMemo(() => flowNodes(flow), [flow]);
  const names = useMemo(() => laneNames(flow, nodes), [flow, nodes]);
  const x = useMemo(() => {
    const span = nodes.length > 1 ? (width - MARGIN_L - MARGIN_R) / (nodes.length - 1) : 0;
    return Object.fromEntries(nodes.map((n, i) => [n, MARGIN_L + i * span]));
  }, [nodes, width]);

  const snapshot = step > 0 ? flow[step - 1].snapshot : null;
  const previous = step > 1 ? flow[step - 2].snapshot : null;
  const tunnels = useMemo(() => tunnelsAt(snapshot, previous), [snapshot, previous]);
  const ebis = [...new Set(tunnels.map((t) => t.ebi))];

  const headH = 64;
  const stripH = Math.max(1, ebis.length) * TUNNEL_ROW_H + 18;
  const ladderH = flow.length * ROW_H + 28;

  // Bring the current message into view while stepping
  const currentRef = useRef(null);
  useEffect(() => { currentRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [step]);

  return (
    <div className="flow-canvas" ref={wrapRef}>
      <div className="flow-sticky">
        <svg width={width} height={headH + stripH} role="img"
          aria-label={`Bearer state after step ${step}`}>
          {nodes.map((n) => (
            <g key={n} className="lane-head">
              <text className="role" x={x[n]} y={28} textAnchor="middle">{names[n] || "Node"}</text>
              <text className="addr" x={x[n]} y={46} textAnchor="middle">{n}</text>
              <line x1={x[n]} x2={x[n]} y1={56} y2={headH + stripH} stroke="var(--rule)" />
            </g>
          ))}

          {ebis.length === 0 ? (
            <text x={width / 2} y={headH + 30} textAnchor="middle" fill="var(--ink-3)" fontSize={13}>
              {step === 0 ? "Step through the messages to watch bearers being set up" : "No bearers at this point"}
            </text>
          ) : ebis.map((ebi, row) => {
            const y = headH + 30 + row * TUNNEL_ROW_H;
            return (
              <g key={ebi}>
                <text x={16} y={y + 4} fontSize={12.5} fontWeight={600} fill="var(--ink)">EBI {ebi}</text>
                {tunnels.filter((t) => t.ebi === ebi).map((t) => (
                  <Tunnel key={`${t.ebi}-${t.iface}`} t={t} x={x} y={y} />
                ))}
              </g>
            );
          })}
        </svg>
      </div>

      <svg width={width} height={ladderH} role="list" aria-label="Signaling messages">
        <defs>
          {[["past", "var(--ink-2)"], ["current", "var(--signal)"], ["future", "#c9d2dc"]].map(([k, c]) => (
            <marker key={k} id={`arrow-${k}`} markerWidth="10" markerHeight="8" refX="9" refY="4"
              orient="auto" markerUnits="userSpaceOnUse">
              <path d="M0 0 L10 4 L0 8 z" fill={c} />
            </marker>
          ))}
        </defs>

        {nodes.map((n) => (
          <line key={n} x1={x[n]} x2={x[n]} y1={0} y2={ladderH} stroke="var(--rule)" />
        ))}

        {flow.map((m, i) => {
          const k = i + 1;
          const phase = k < step ? "past" : k === step ? "current" : "future";
          const y = 30 + i * ROW_H;
          const sx = x[m.src_addr];
          const dx = x[m.dst_addr];
          const dir = dx > sx ? 1 : -1;
          const color = phase === "current" ? "var(--signal)" : phase === "past" ? "var(--ink-2)" : "#c9d2dc";
          return (
            <g key={m.id} className={`msg-row ${phase}`} role="listitem"
              ref={phase === "current" ? currentRef : null}
              onClick={() => onStep(k)}>
              <rect className="hit" x={0} y={y - 26} width={width} height={ROW_H} fill="transparent" />
              <text className="no" x={16} y={y + 4}>#{m.id}</text>
              <text className="msg" x={(sx + dx) / 2} y={y - 8} textAnchor="middle">{m.message}</text>
              <line x1={sx} x2={dx - dir * 3} y1={y} y2={y} stroke={color}
                strokeWidth={phase === "current" ? 2.5 : 1.5} markerEnd={`url(#arrow-${phase})`} />
              <circle cx={sx} cy={y} r={3} fill={color} />
            </g>
          );
        })}
      </svg>
    </div>
  );
}
