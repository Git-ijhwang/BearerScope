import { useEffect, useMemo, useRef, useState } from "react";
import { bearersAt, flowNodes, hex, laneNames, tunnelsAt } from "./flowModel";

const ROW_H = 44;
const MARGIN_L = 206;   // room for the PDN / EBI column
const MARGIN_R = 72;
const TUNNEL_ROW_H = 58;
const GROUP_GAP = 14;    // space between PDN connections
const GROUP_X = 10;
const GROUP_W = 160;

const STATE_STYLE = {
  up: { stroke: "var(--tunnel)", dash: null, text: "Up" },
  pending: { stroke: "var(--signal)", dash: "6 4", text: "Being set up" },
  releasing: { stroke: "var(--danger)", dash: "6 4", text: "Being released" },
};

// Tunnel end: a box with TEID and IP next to the node that owns it
const BOX_W = 150;
const BOX_H = 38;
const BOX_GAP = 6;     // between the node's lane and its box
const STUB = 140;      // line toward a peer that isn't known yet (long enough for its label)

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

/** TEID and transport address of one tunnel end, in a box beside its node */
function Endpoint({ ep, x, y, inward, color }) {
  // inward: +1 when the tunnel runs to the right of this node, -1 to the left
  const bx = inward > 0 ? x + BOX_GAP : x - BOX_GAP - BOX_W;
  return (
    <g>
      <circle cx={x} cy={y} r={3.5} fill={color} />
      <rect className="tunnel-box" x={bx} y={y - BOX_H / 2} width={BOX_W} height={BOX_H} rx={6} stroke={color} />
      <text className="tunnel-teid" x={bx + 10} y={y - 3}>
        <tspan className="tunnel-key">TEID </tspan>{hex(ep.teid)}
      </text>
      <text className="tunnel-teid" x={bx + 10} y={y + 13}>
        <tspan className="tunnel-key">IP </tspan>{ep.ip}
      </text>
    </g>
  );
}

/**
 * One GTP-U tunnel: a line between the two end boxes. The line's colour and
 * dash carry the state (up, being set up, being released).
 */
function Tunnel({ t, x, y, peerX }) {
  const st = STATE_STYLE[t.state];
  const both = t.a && t.b;
  const ax = t.a ? x[t.a.node] : null;
  const bx = t.b ? x[t.b.node] : null;

  let left, right, x1, x2;
  if (both) {
    [left, right] = ax <= bx ? [t.a, t.b] : [t.b, t.a];
    x1 = x[left.node] + BOX_GAP + BOX_W;
    x2 = x[right.node] - BOX_GAP - BOX_W;
  } else if (t.a) {
    left = t.a;
    x1 = ax + BOX_GAP + BOX_W;
    // Up to the peer's empty box if it is waiting there, else a short stub
    x2 = peerX != null ? peerX - BOX_GAP - BOX_W : x1 + STUB;
  } else {
    right = t.b;
    x2 = bx - BOX_GAP - BOX_W;
    x1 = peerX != null ? peerX + BOX_GAP + BOX_W : x2 - STUB;
  }
  // A dotted stub already says the peer isn't known, so the label stays short
  const label = `${t.iface}${t.state !== "up" ? ` · ${st.text}` : ""}`;

  return (
    <g>
      <line x1={x1} x2={x2} y1={y} y2={y} stroke={st.stroke} strokeWidth={2}
        strokeDasharray={st.dash || (both ? undefined : "3 4")} />
      <text className="tunnel-label" x={(x1 + x2) / 2} y={y - 7} textAnchor="middle" fill={st.stroke}>{label}</text>
      {left && <Endpoint ep={left} x={x[left.node]} y={y} inward={1} color={st.stroke} />}
      {right && <Endpoint ep={right} x={x[right.node]} y={y} inward={-1} color={st.stroke} />}
    </g>
  );
}

/**
 * Where a tunnel end will appear: the node holds the bearer but has no
 * TEID for this side yet (e.g. the MME before Modify Bearer brings the eNB's)
 */
function PendingEnd({ x, y, inward, state }) {
  const st = STATE_STYLE[state] || STATE_STYLE.pending;
  const bx = inward > 0 ? x + BOX_GAP : x - BOX_GAP - BOX_W;
  return (
    <g>
      <title>Bearer context on this node; its TEID for this side isn't known yet</title>
      <circle cx={x} cy={y} r={3.5} fill="var(--surface)" stroke={st.stroke} strokeWidth={1.5} />
      <rect className="tunnel-box is-pending" x={bx} y={y - BOX_H / 2} width={BOX_W} height={BOX_H} rx={6}
        stroke={st.stroke} strokeDasharray="4 3" />
      <text className="tunnel-teid is-pending" x={bx + 10} y={y - 3}>
        <tspan className="tunnel-key">TEID </tspan>pending
      </text>
      <text className="tunnel-teid is-pending" x={bx + 10} y={y + 13}>
        <tspan className="tunnel-key">IP </tspan>—
      </text>
    </g>
  );
}

export default function CallFlowGraph({ flow, step, onStep, onOpenPacket }) {
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
  // Bearers grouped by PDN connection (LBI): default bearer first, then
  // dedicated bearers by EBI, then new bearers still waiting for their EBI.
  // Rows come from the bearers, so a bearer shows before it has any tunnel.
  const bearers = useMemo(() => bearersAt(snapshot), [snapshot]);
  const groups = useMemo(() => {
    const byLbi = new Map();
    bearers.forEach((b) => {
      if (!byLbi.has(b.lbi)) byLbi.set(b.lbi, []);
      byLbi.get(b.lbi).push(b);
    });
    const rank = (lbi, ebi) => (ebi === lbi ? 0 : ebi ? ebi : 1000);
    return [...byLbi.entries()]
      .sort(([a], [b]) => a - b)
      .map(([lbi, rows]) => ({
        lbi,
        rows: rows.sort((a, b) => rank(lbi, a.ebi) - rank(lbi, b.ebi) || a.row.localeCompare(b.row)),
      }));
  }, [bearers]);
  const rowCount = groups.reduce((n, g) => n + g.rows.length, 0);

  const headH = 64;
  const stripH = Math.max(1, rowCount) * TUNNEL_ROW_H + Math.max(0, groups.length - 1) * GROUP_GAP + 18;
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

          {rowCount === 0 ? (
            <text x={width / 2} y={headH + 30} textAnchor="middle" fill="var(--ink-3)" fontSize={13}>
              {step === 0 ? "Step through the messages to watch bearers being set up" : "No bearers at this point"}
            </text>
          ) : (() => {
            let top = headH + 4;
            return groups.map((g) => {
              const groupTop = top;
              const groupH = g.rows.length * TUNNEL_ROW_H - 6;
              top += g.rows.length * TUNNEL_ROW_H + GROUP_GAP;
              return (
                <g key={g.lbi} className="pdn-group">
                  {/* Faint band behind the PDN's tunnels, so the rows read as one group */}
                  <rect className="pdn-band" x={GROUP_X + GROUP_W} y={groupTop} width={width - GROUP_X - GROUP_W - 8}
                    height={groupH} rx={6} />
                  <rect className="pdn-box" x={GROUP_X} y={groupTop} width={GROUP_W} height={groupH} rx={10} />
                  <text className="pdn-caption" x={GROUP_X + 14} y={groupTop + groupH / 2 - 6}>PDN</text>
                  <text className="pdn-lbi" x={GROUP_X + 14} y={groupTop + groupH / 2 + 12}>LBI {g.lbi}</text>
                  <line className="pdn-divider" x1={GROUP_X + 68} x2={GROUP_X + 68}
                    y1={groupTop + 10} y2={groupTop + groupH - 10} />

                  {g.rows.map(({ row, ebi, holders }, i) => {
                    const y = groupTop + TUNNEL_ROW_H / 2 - 3 + i * TUNNEL_ROW_H;
                    const rowTunnels = tunnels.filter((t) => t.row === row);
                    // Tunnel ends already drawn, as "node|side" (R: tunnel runs right of the node)
                    const drawn = new Set();
                    rowTunnels.forEach((t) => {
                      const ends = [t.a, t.b].filter(Boolean);
                      if (ends.length === 2) {
                        const [l, r] = x[ends[0].node] <= x[ends[1].node] ? ends : [ends[1], ends[0]];
                        drawn.add(`${l.node}|R`); drawn.add(`${r.node}|L`);
                      } else if (t.a) drawn.add(`${t.a.node}|R`);
                      else drawn.add(`${t.b.node}|L`);
                    });
                    // Every node holding the bearer gets a box on each side a tunnel will
                    // run to (first lane: right, last lane: left, middle lanes: both)
                    const pending = [];
                    holders.forEach((h) => {
                      const i = nodes.indexOf(h.node);
                      if (i < 0) return;
                      if (drawn.has(`${h.node}|R`) || drawn.has(`${h.node}|L`)) return;
                      if (i < nodes.length - 1) pending.push({ ...h, side: "R" });
                      if (i > 0) pending.push({ ...h, side: "L" });
                    });
                    const pendingAt = new Set(pending.map((p) => `${p.node}|${p.side}`));
                    // For a half tunnel, the lane its missing end belongs to
                    const peerOf = (t) => {
                      if (t.a && t.b) return null;
                      const end = t.a || t.b;
                      const i = nodes.indexOf(end.node) + (t.a ? 1 : -1);
                      const peer = nodes[i];
                      return peer && pendingAt.has(`${peer}|${t.a ? "L" : "R"}`) ? x[peer] : null;
                    };
                    return (
                      <g key={row}>
                        {pending.map((p) => (
                          <PendingEnd key={`${p.node}|${p.side}`} x={x[p.node]} y={y}
                            inward={p.side === "R" ? 1 : -1} state={p.state} />
                        ))}
                        <text className="ebi-name" x={GROUP_X + 80} y={y - 2}>{ebi ? `EBI ${ebi}` : "New bearer"}</text>
                        <text className="ebi-kind" x={GROUP_X + 80} y={y + 13}>
                          {ebi === g.lbi ? "default" : ebi ? "dedicated" : "EBI pending"}
                        </text>
                        {rowTunnels.map((t) => (
                          <Tunnel key={`${t.row}-${t.iface}`} t={t} x={x} y={y} peerX={peerOf(t)} />
                        ))}
                      </g>
                    );
                  })}
                </g>
              );
            });
          })()}
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
              onClick={() => { onStep(k); onOpenPacket?.(m.id); }}>
              <title>{`#${m.id} ${m.message} — click to open the packet`}</title>
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
