// Turns the core's call flow output (one entry per message, each with a
// snapshot of every node's bearer state) into things we can draw.

const ROLE_NAMES = { Access: "MME", RELAY: "SGW", Core: "PGW" };

/** Nodes in order of first appearance, which matches how ladders are drawn. */
export function flowNodes(flow) {
  const seen = [];
  flow.forEach((m) => {
    if (!seen.includes(m.src_addr)) seen.push(m.src_addr);
    if (!seen.includes(m.dst_addr)) seen.push(m.dst_addr);
  });
  return seen;
}

/**
 * Network function name per node, from the last role the core could work out
 * (the role is only known once the node's tunnels are known).
 */
export function laneNames(flow, nodes) {
  const names = {};
  nodes.forEach((n) => { names[n] = null; });
  flow.forEach((m) => {
    Object.entries(m.snapshot || {}).forEach(([ip, st]) => {
      if (ROLE_NAMES[st.role]) names[ip] = ROLE_NAMES[st.role];
    });
  });
  return names;
}

const ENDPOINTS = [
  { iface: "S1-U", side: "a", key: "s1u_enb" },
  { iface: "S1-U", side: "b", key: "s1u_sgw" },
  { iface: "S5/S8", side: "a", key: "s5s8_sgw" },
  { iface: "S5/S8", side: "b", key: "s5s8_pgw" },
];

function bearerState(detail) {
  if (detail.delete_pending) return "releasing";
  if (detail.pending) return "pending";
  return detail.active ? "up" : "pending";
}

const STATE_RANK = { up: 0, pending: 1, releasing: 2 };

/**
 * Tunnels (one per EBI and interface) as they stand after a message.
 * Each end is attached to the node that owns that F-TEID.
 */
export function tunnelsAt(snapshot, previous = null) {
  const byKey = new Map();
  Object.entries(snapshot || {}).forEach(([node, st]) => {
    Object.entries(st.sessions || {}).forEach(([lbi, list]) => {
      (list || []).forEach((detail) => {
        ENDPOINTS.forEach(({ iface, side, key }) => {
          const ep = detail.tunnels?.[key];
          if (!ep) return;
          // A bearer created with EBI 0 (Create Bearer Request) is matched across
          // nodes by its pending key until, and after, the MME assigns the EBI
          const row = detail.pending_key != null ? `k${detail.pending_key}` : `e${detail.ebi}`;
          const id = `${row}|${iface}`;
          const t = byKey.get(id) || { row, ebi: 0, lbi: Number(lbi), iface, a: null, b: null, state: "up", ends: [] };

          if (detail.ebi) t.ebi = detail.ebi;
          t[side] = { node, teid: ep.teid, ip: ep.ip };
          // const s = bearerState(detail);
          t.ends.push(bearerState(detail));
          // if (STATE_RANK[s] > STATE_RANK[t.state]) t.state = s;
          byKey.set(id, t);
        });
      });
    });
  });
  const tunnels = [...byKey.values()];

  tunnels.forEach((t) => {
    const ends = t.ends;
    delete t.ends;
    if (ends.every((s) => s === "releasing")) { t.state = "releasing"; return; }
    t.state = ends.filter((s) => s !== "releasing")
      .reduce((m, s) => (STATE_RANK[s] > STATE_RANK[m] ? s : m), "up");
  });

  // The core tracks "pending" per bearer, not per tunnel. A tunnel whose two
  // ends were already in place before this message, with the same TEIDs, is
  // not the one being changed, so show it as up.
  if (previous) {
    const before = new Map(tunnelsAt(previous).map((t) => [`${t.row}|${t.iface}`, t]));
    tunnels.forEach((t) => {
      const p = before.get(`${t.row}|${t.iface}`);
      const same = (e1, e2) => e1 && e2 && e1.teid === e2.teid && e1.node === e2.node;
      if (t.state === "pending" && p && same(p.a, t.a) && same(p.b, t.b)) t.state = "up";
    });
  }
  return tunnels.sort((x, y) => x.lbi - y.lbi || x.row.localeCompare(y.row) || x.iface.localeCompare(y.iface));
}

/**
 * Every bearer the nodes hold after a message, tunnels or not: one row per
 * bearer, with the nodes that have it and the state on each.
 * A bearer exists on a node before any of its GTP-U endpoints is known
 * (the MME's EBI in Create Session Request, a PGW receiving a request).
 */
export function bearersAt(snapshot) {
  const rows = new Map();
  Object.entries(snapshot || {}).forEach(([node, st]) => {
    Object.entries(st.sessions || {}).forEach(([lbi, list]) => {
      (list || []).forEach((detail) => {
        const row = detail.pending_key != null ? `k${detail.pending_key}` : `e${detail.ebi}`;
        const r = rows.get(row) || { row, ebi: 0, lbi: Number(lbi), holders: [] };
        if (detail.ebi) r.ebi = detail.ebi;
        r.holders.push({ node, state: bearerState(detail) });
        rows.set(row, r);
      });
    });
  });
  return [...rows.values()];
}

export const hex = (n) => `0x${Number(n).toString(16).toUpperCase().padStart(8, "0")}`;
