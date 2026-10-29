// Small helpers shared by the packet list and inspector.

/** Protocol family used for colour and the protocol chips. */
export function protoFamily(pkt) {
  if (pkt.protocol === "GTP2-C") return "gtp";
  if (pkt.protocol === "PFCP") return "pfcp";
  return "other";
}

/** Display name: the core reports "GTP2-C"; the protocol is called GTPv2-C. */
export function protoLabel(pkt) {
  if (pkt.protocol === "GTP2-C") return "GTPv2-C";
  return pkt.protocol || pkt.l4_type || "—";
}

/** "Create Session Request [32]" → { text: "Create Session Request", code: "32" } */
export function splitDescription(desc = "") {
  const m = desc.match(/^(.*?)\s*\[(\d+)\]\s*$/);
  return m ? { text: m[1], code: m[2] } : { text: desc, code: null };
}

/** Call flow analysis currently starts from a Create Session Request. */
// GTPv2-C messages that are not about a UE session: Echo Request/Response,
// Version Not Supported Indication
const GTPC_NODE_MESSAGES = new Set([1, 2, 3]);

/** A Create Session Request: where a PDN connection starts */
export function startsSession(pkt) {
  return pkt.protocol === "GTP2-C" && /\[32\]\s*$/.test(pkt.description || "");
}

/** The call flow can start from any GTPv2-C message of a UE's session */
export function canOpenFlow(pkt) {
  if (pkt.protocol !== "GTP2-C") return false;
  const code = Number(/\[(\d+)\]\s*$/.exec(pkt.description || "")?.[1]);
  return !GTPC_NODE_MESSAGES.has(code);
}

export const PROTO_FILTERS = [
  { id: "all", label: "All" },
  { id: "gtp", label: "GTPv2-C" },
  { id: "pfcp", label: "PFCP" },
  { id: "other", label: "Other" },
];

/**
 * Free-text filter: every space-separated term must appear somewhere in the
 * packet's number, addresses, ports, protocol or message name.
 */
export function filterPackets(packets, text, proto) {
  const terms = text.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return packets.filter((pkt) => {
    if (proto !== "all" && protoFamily(pkt) !== proto) return false;
    if (terms.length === 0) return true;
    const hay = [
      `#${pkt.id}`, pkt.src_ip, pkt.dst_ip,
      pkt.src_port || "", pkt.dst_port || "",
      protoLabel(pkt), pkt.l4_type, pkt.description,
    ].join(" ").toLowerCase();
    return terms.every((t) => hay.includes(t));
  });
}
