// Field-level decoding for GTPv2-C (3GPP TS 29.274) and PFCP (TS 29.244) IEs
// that the core hands over as plain bytes or bare integers.
//
// decodeIeFields(proto, ieType, raw, ieLength) returns a list of
// [label, value] pairs, or null when the IE type isn't known here (the
// caller then falls back to its existing rendering).

// ------------------------------------------------------------------ helpers

const hex = (n, w = 2) => `0x${Number(n).toString(16).toUpperCase().padStart(w, "0")}`;
const hexBytes = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(" ");
const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1];
const u32 = (b, o = 0) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
const u40 = (b, o = 0) => b[o] * 2 ** 32 + u32(b, o + 1);
const ipv4 = (b, o = 0) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
const ipv6 = (b, o = 0) => {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(u16(b, o + i).toString(16));
  // collapse the longest run of zero groups
  const s = parts.join(":");
  const runs = s.match(/(^|:)0(:0)+(:|$)/g);
  if (!runs) return s;
  const longest = runs.reduce((a, r) => (r.length > a.length ? r : a));
  return s.replace(longest, "::");
};
const named = (table, v) => (table[v] ? `${table[v]} (${v})` : `${v}`);
const flagList = (byte, names) =>
  names.map((n, bit) => (n && byte & (1 << bit) ? n : null)).filter(Boolean);
const kbps = (n) => (n >= 1000 ? `${(n / 1000).toLocaleString()} Mbps` : `${n} kbps`);

/** DNS-style labels (length-prefixed), used by APN, FQDN, Network Instance */
function labels(b, o = 0) {
  const out = [];
  let i = o;
  while (i < b.length) {
    const n = b[i];
    if (n === 0 || i + 1 + n > b.length) break;
    out.push(String.fromCharCode(...b.slice(i + 1, i + 1 + n)));
    i += 1 + n;
  }
  // Not label-encoded after all: treat as plain text
  if (i !== b.length || out.length === 0) return String.fromCharCode(...b.slice(o));
  return out.join(".");
}

/** BCD digits, low nibble first (TS 29.274 8.3); 0xF is filler */
function tbcd(b) {
  let s = "";
  for (const x of b) {
    if ((x & 0x0f) !== 0x0f) s += (x & 0x0f).toString(16);
    if (x >> 4 !== 0x0f) s += (x >> 4).toString(16);
  }
  return s;
}

/** MCC/MNC as encoded in 3 octets (TS 24.008 10.5.1.13) */
function plmn(b, o = 0) {
  const d = (x) => (x === 0x0f ? "" : x.toString(16));
  const mcc = d(b[o] & 0x0f) + d(b[o] >> 4) + d(b[o + 1] & 0x0f);
  const mnc = d(b[o + 2] & 0x0f) + d(b[o + 2] >> 4) + d(b[o + 1] >> 4);
  return `MCC ${mcc} / MNC ${mnc}`;
}

// ------------------------------------------------------------------ GTPv2-C tables

const GTP_CAUSE = {
  2: "Local Detach", 3: "Complete Detach", 4: "RAT changed from 3GPP to Non-3GPP",
  5: "ISR deactivation", 6: "Error Indication received", 7: "IMSI Detach Only",
  8: "Reactivation Requested", 9: "PDN reconnection to this APN disallowed",
  10: "Access changed from Non-3GPP to 3GPP", 11: "PDN connection inactivity timer expires",
  12: "PGW not responding", 13: "Network Failure", 14: "QoS parameter mismatch",
  15: "EPS to 5GS Mobility",
  16: "Request accepted", 17: "Request accepted partially",
  18: "New PDN type due to network preference", 19: "New PDN type due to single address bearer only",
  64: "Context Not Found", 65: "Invalid Message Format", 66: "Version not supported by next peer",
  67: "Invalid length", 68: "Service not supported", 69: "Mandatory IE incorrect",
  70: "Mandatory IE missing", 72: "System failure", 73: "No resources available",
  74: "Semantic error in the TFT operation", 75: "Syntactic error in the TFT operation",
  76: "Semantic errors in packet filter(s)", 77: "Syntactic errors in packet filter(s)",
  78: "Missing or unknown APN", 80: "GRE key not found", 81: "Relocation failure",
  82: "Denied in RAT", 83: "Preferred PDN type not supported",
  84: "All dynamic addresses are occupied", 85: "UE context without TFT already activated",
  86: "Protocol type not supported", 87: "UE not responding", 88: "UE refuses",
  89: "Service denied", 90: "Unable to page UE", 91: "No memory available",
  92: "User authentication failed", 93: "APN access denied - no subscription",
  94: "Request rejected (reason not specified)", 95: "P-TMSI Signature mismatch",
  96: "IMSI/IMEI not known", 97: "Semantic error in the TAD operation",
  98: "Syntactic error in the TAD operation", 100: "Remote peer not responding",
  101: "Collision with network initiated request", 102: "Unable to page UE due to Suspension",
  103: "Conditional IE missing",
  104: "APN Restriction type incompatible with currently active PDN connection",
  105: "Invalid overall length of the triggered response message and a piggybacked initial message",
  106: "Data forwarding not supported", 107: "Invalid reply from remote peer",
  108: "Fallback to GTPv1", 109: "Invalid peer",
  110: "Temporarily rejected due to handover/TAU/RAU procedure in progress",
  111: "Modifications not limited to S1-U bearers", 112: "Request rejected for a PMIPv6 reason",
  113: "APN Congestion", 114: "Bearer handling not supported", 115: "UE already re-attached",
  116: "Multiple PDN connections for a given APN not allowed",
  117: "Target access restricted for the subscriber",
  119: "MME/SGSN refuses due to VPLMN Policy", 120: "GTP-C Entity Congestion",
  121: "Late Overlapping Request", 122: "Timed out Request",
  123: "UE is temporarily not reachable due to power saving",
  124: "Relocation failure due to NAS message redirection",
  125: "UE not authorised by OCS or external AAA Server",
  126: "Multiple accesses to a PDN connection not allowed",
  127: "Request rejected due to UE capability", 128: "S1-U Path Failure",
  129: "5GC not allowed",
};

const RAT_TYPE = {
  1: "UTRAN", 2: "GERAN", 3: "WLAN", 4: "GAN", 5: "HSPA Evolution", 6: "EUTRAN",
  7: "Virtual", 8: "EUTRAN-NB-IoT", 9: "LTE-M", 10: "NR",
};

const PDN_TYPE = { 1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "Non-IP", 5: "Ethernet" };

const APN_RESTRICTION = {
  0: "No existing contexts or restriction", 1: "Public-1", 2: "Public-2", 3: "Private-1", 4: "Private-2",
};

const SELECTION_MODE = {
  0: "MS or network provided APN, subscription verified",
  1: "MS provided APN, subscription not verified",
  2: "Network provided APN, subscription not verified",
  3: "Network provided APN, subscription not verified",
};

const NODE_TYPE = { 0: "MME", 1: "SGSN" };

const TIMER_UNIT = { 0: "2 s", 1: "1 min", 2: "10 min", 3: "1 h", 4: "10 h", 7: "infinite" };

// Indication flags, bit 1 first (TS 29.274 8.12)
const INDICATION_OCTETS = [
  ["SGWCI", "ISRAI", "ISRSI", "OI", "DFI", "HI", "DTF", "DAF"],
  ["MSV", "SI", "PT", "P", "CRSI", "CFSI", "UIMSI", "SQCI"],
  ["CCRSI", "ISRAU", "MBMDT", "S4AF", "S6AF", "SRNI", "PBIC", "RetLoc"],
  ["CPSR", "CLII", "CSFBI", "PPSI", "PPON/PPEI", "PPOF", "ARRL", "CPRAI"],
];

// Protocol configuration options container IDs (TS 24.008 10.5.6.3)
const PCO_ID = {
  0x0001: "P-CSCF IPv6 Address", 0x0002: "IM CN Subsystem Signaling Flag",
  0x0003: "DNS Server IPv6 Address", 0x0004: "Policy Control rejection code",
  0x0005: "MS Support of Network Requested Bearer Control indicator",
  0x0007: "DSMIPv6 Home Agent Address", 0x0008: "DSMIPv6 Home Network Prefix",
  0x000a: "IP address allocation via NAS signalling", 0x000b: "IPv4 address allocation via DHCPv4",
  0x000c: "P-CSCF IPv4 Address", 0x000d: "DNS Server IPv4 Address",
  0x000e: "MSISDN", 0x0010: "IPv4 Link MTU", 0x0011: "MS support of Local address in TFT indicator",
  0x0012: "P-CSCF Re-selection support", 0x0016: "APN rate control support",
  0x0017: "3GPP PS data off UE status", 0x001b: "S-NSSAI", 0x0023: "QoS rules with the length of two octets support",
  0x8021: "IPCP", 0xc021: "LCP", 0xc023: "PAP", 0xc223: "CHAP",
};

function pcoFields(v) {
  const out = [["Configuration protocol", (v[0] & 0x07) === 0 ? "PPP with IP PDP type" : hex(v[0] & 0x07)]];
  let i = 1;
  while (i + 3 <= v.length) {
    const id = u16(v, i);
    const len = v[i + 2];
    const c = v.slice(i + 3, i + 3 + len);
    let shown = len ? hexBytes(c) : "(empty)";
    if ((id === 0x000d || id === 0x000c) && len === 4) shown = ipv4(c);
    else if ((id === 0x0003 || id === 0x0001) && len === 16) shown = ipv6(c);
    else if (id === 0x0010 && len === 2) shown = `${u16(c)} bytes`;
    else if (id === 0x8021 && len >= 4) {
      // IPCP options: 0x81 primary DNS, 0x83 secondary DNS
      const opts = [];
      for (let j = 4; j + 2 <= c.length; j += c[j + 1] || c.length) {
        const name = { 0x03: "IP", 0x81: "Primary DNS", 0x83: "Secondary DNS" }[c[j]];
        if (name && c[j + 1] === 6) opts.push(`${name} ${ipv4(c, j + 2)}`);
      }
      if (opts.length) shown = opts.join(", ");
    }
    out.push([PCO_ID[id] ? `${PCO_ID[id]} (${hex(id, 4)})` : hex(id, 4), shown]);
    i += 3 + len;
  }
  return out;
}

function uePaa(v) {
  const type = v[0] & 0x07;
  const out = [["PDN type", named(PDN_TYPE, type)]];
  if (type === 1 && v.length >= 5) out.push(["IPv4 address", ipv4(v, 1)]);
  if (type === 2 && v.length >= 18) out.push(["IPv6 prefix", `${ipv6(v, 2)}/${v[1]}`]);
  if (type === 3 && v.length >= 22) {
    out.push(["IPv6 prefix", `${ipv6(v, 2)}/${v[1]}`]);
    out.push(["IPv4 address", ipv4(v, 18)]);
  }
  return out;
}

function fqCsid(v) {
  const nodeType = v[0] >> 4;
  const count = v[0] & 0x0f;
  let o = 1;
  const out = [];
  if (nodeType === 0) { out.push(["Node ID", ipv4(v, o)]); o += 4; }
  else if (nodeType === 1) { out.push(["Node ID", ipv6(v, o)]); o += 16; }
  else { out.push(["Node ID", `${hex(u32(v, o), 8)} (MCC/MNC based)`]); o += 4; }
  const csids = [];
  for (let k = 0; k < count && o + 2 <= v.length; k += 1, o += 2) csids.push(u16(v, o));
  out.push(["CSIDs", csids.join(", ") || "none"]);
  return out;
}

function ueTimeZone(v) {
  const b = v[0];
  const quarters = (b & 0x07) * 10 + (b >> 4);
  const sign = b & 0x08 ? "-" : "+";
  const h = Math.floor(quarters / 4);
  const m = (quarters % 4) * 15;
  const dst = { 0: "No adjustment", 1: "+1 hour", 2: "+2 hours" }[v[1] & 0x03] ?? hex(v[1]);
  return [["Time zone", `UTC${sign}${h}:${String(m).padStart(2, "0")}`], ["Daylight saving", dst]];
}

/** User Location Info (TS 29.274 8.21): flags, then each present identity in a fixed order */
function uliFields(v) {
  const f = v[0];
  const out = [];
  let o = 1;
  if (f & 0x01) { out.push(["CGI", `${plmn(v, o)}, LAC ${u16(v, o + 3)}, CI ${u16(v, o + 5)}`]); o += 7; }
  if (f & 0x02) { out.push(["SAI", `${plmn(v, o)}, LAC ${u16(v, o + 3)}, SAC ${u16(v, o + 5)}`]); o += 7; }
  if (f & 0x04) { out.push(["RAI", `${plmn(v, o)}, LAC ${u16(v, o + 3)}, RAC ${v[o + 5]}`]); o += 7; }
  if (f & 0x08) { out.push(["TAI", `${plmn(v, o)}, TAC ${u16(v, o + 3)}`]); o += 5; }
  if (f & 0x10) {
    const eci = u32(v, o + 3) & 0x0fffffff;
    out.push(["ECGI", `${plmn(v, o)}, ECI ${eci} (eNB ${eci >>> 8}, cell ${eci & 0xff})`]);
    o += 7;
  }
  if (f & 0x20) { out.push(["LAI", `${plmn(v, o)}, LAC ${u16(v, o + 3)}`]); o += 5; }
  if (f & 0x40) { out.push(["Macro eNB ID", `${plmn(v, o)}, ${((v[o + 3] & 0x0f) << 16) | u16(v, o + 4)}`]); o += 6; }
  if (f & 0x80) out.push(["Extended macro eNB ID", `${plmn(v, o)}`]);
  return out;
}

function gtpFields(type, v) {
  switch (type) {
    case 2: { // Cause
      const out = [["Cause", named(GTP_CAUSE, v[0])]];
      if (v.length > 1) {
        const f = flagList(v[1], ["CS (originated by remote node)", "BCE (bearer context error)", "PCE (PDN connection error)"]);
        if (f.length) out.push(["Flags", f.join(", ")]);
      }
      if (v.length >= 6) out.push(["Offending IE", `type ${v[2]}, length ${u16(v, 3)}, instance ${v[5] & 0x0f}`]);
      return out;
    }
    case 3: return [["Restart counter", v[0]]];
    case 77: { // Indication
      const set = [];
      INDICATION_OCTETS.forEach((names, i) => { if (i < v.length) set.push(...flagList(v[i], names)); });
      const out = [["Flags set", set.length ? set.join(", ") : "none"]];
      if (v.length > INDICATION_OCTETS.length) out.push(["Other octets", hexBytes(v.slice(INDICATION_OCTETS.length))]);
      return out;
    }
    case 78: case 163: case 197: return pcoFields(v); // PCO, APCO, ePCO
    case 79: return uePaa(v);
    case 82: return [["RAT type", named(RAT_TYPE, v[0])]];
    case 81: // Flow QoS
      return [["QCI", v[0]], ["MBR UL", kbps(u40(v, 1))], ["MBR DL", kbps(u40(v, 6))],
        ["GBR UL", kbps(u40(v, 11))], ["GBR DL", kbps(u40(v, 16))]];
    case 92: return [["Delay", `${v[0] * 50} ms`]];
    case 94: return [["Charging ID", `${u32(v)} (${hex(u32(v), 8)})`]];
    case 95: { // Charging Characteristics (TS 32.251 A.4)
      const cc = u16(v);
      const profile = { 0x0800: "Normal", 0x0400: "Prepaid", 0x0200: "Flat rate", 0x0100: "Hot billing" };
      const p = Object.keys(profile).filter((k) => cc & Number(k)).map((k) => profile[k]);
      return [["Value", hex(cc, 4)], ["Profile", p.join(", ") || "-"]];
    }
    case 97: { // Bearer Flags
      const f = flagList(v[0], ["PPC (prohibit payload compression)", "VB (voice bearer)", "Vind (vSRVCC)", "ASI (activity status)"]);
      return [["Flags", f.join(", ") || "none"]];
    }
    case 99: return [["PDN type", named(PDN_TYPE, v[0] & 0x07)]];
    case 100: return [["Procedure transaction ID", v[0]]];
    case 114: return ueTimeZone(v);
    case 126: return [["Port", u16(v)]];
    case 127: return [["APN restriction", named(APN_RESTRICTION, v[0])]];
    case 128: return [["Selection mode", named(SELECTION_MODE, v[0] & 0x03)]];
    case 132: return fqCsid(v);
    case 135: return [["Node type", named(NODE_TYPE, v[0])]];
    case 136: return [["FQDN", labels(v)]];
    case 155: { // ARP
      return [["Priority level", (v[0] >> 2) & 0x0f],
        ["Pre-emption capability", v[0] & 0x40 ? "Disabled" : "Enabled"],
        ["Pre-emption vulnerability", v[0] & 0x01 ? "Disabled" : "Enabled"]];
    }
    case 156: { // EPC Timer
      const unit = v[0] >> 5;
      return [["Timer", unit === 7 ? "Infinite" : `${v[0] & 0x1f} × ${TIMER_UNIT[unit] ?? `unit ${unit}`}`]];
    }
    case 161: return [["APN-AMBR UL", kbps(u32(v))], ["APN-AMBR DL", kbps(u32(v, 4))]]; // Max MBR/APN-AMBR
    case 162: return [["LAPI", v[0] & 0x01 ? "Low access priority" : "Not set"]];
    case 74: // IP Address
      if (v.length === 4) return [["IPv4 address", ipv4(v)]];
      if (v.length === 16) return [["IPv6 address", ipv6(v)]];
      return null;
    case 1: return [["IMSI", tbcd(v)]];
    case 75: return [["MEI", tbcd(v)]];
    case 76: return [["MSISDN", tbcd(v)]];
    case 71: return [["APN", labels(v)]];
    case 72: return [["APN-AMBR UL", kbps(u32(v))], ["APN-AMBR DL", kbps(u32(v, 4))]];
    case 80: // Bearer QoS
      return [
        ["QCI", v[1]],
        ["ARP priority level", (v[0] >> 2) & 0x0f],
        ["Pre-emption capability", v[0] & 0x40 ? "Disabled" : "Enabled"],
        ["Pre-emption vulnerability", v[0] & 0x01 ? "Disabled" : "Enabled"],
        ["MBR UL / DL", `${kbps(u40(v, 2))} / ${kbps(u40(v, 7))}`],
        ["GBR UL / DL", `${kbps(u40(v, 12))} / ${kbps(u40(v, 17))}`],
      ];
    case 83: return [["PLMN", plmn(v)]]; // Serving Network
    case 86: return uliFields(v);
    default: return null;
  }
}

// ------------------------------------------------------------------ PFCP tables

const PFCP_CAUSE = {
  1: "Request accepted", 2: "More Usage Report to send", 64: "Request rejected",
  65: "Session context not found", 66: "Mandatory IE missing", 67: "Conditional IE missing",
  68: "Invalid length", 69: "Mandatory IE incorrect", 70: "Invalid Forwarding Policy",
  71: "Invalid F-TEID allocation option", 72: "No established PFCP Association",
  73: "Rule creation/modification Failure", 74: "PFCP entity in congestion",
  75: "No resources available", 76: "Service not supported", 77: "System failure",
  78: "Redirection Requested", 79: "All dynamic addresses are occupied",
};

const PFCP_INTERFACE = { 0: "Access", 1: "Core", 2: "SGi-LAN/N6-LAN", 3: "CP-function", 4: "5G VN Internal" };

const OUTER_HEADER_REMOVAL = {
  0: "GTP-U/UDP/IPv4", 1: "GTP-U/UDP/IPv6", 2: "UDP/IPv4", 3: "UDP/IPv6", 4: "IPv4", 5: "IPv6",
  6: "GTP-U/UDP/IP", 7: "VLAN S-TAG", 8: "S-TAG and C-TAG",
};

function pfcpFteid(v) {
  const f = v[0];
  if (f & 0x04) { // CH: UP function chooses the TEID
    const out = [["F-TEID", "CHOOSE (allocated by UP function)"]];
    if (f & 0x08 && v.length > 1) out.push(["CHOOSE ID", v[1]]);
    return out;
  }
  const out = [["TEID", hex(u32(v, 1), 8)]];
  let o = 5;
  if (f & 0x01) { out.push(["IPv4 address", ipv4(v, o)]); o += 4; }
  if (f & 0x02) { out.push(["IPv6 address", ipv6(v, o)]); }
  return out;
}

function pfcpUeIp(v) {
  const f = v[0];
  const out = [["Direction", f & 0x04 ? "Destination" : "Source"]];
  let o = 1;
  if (f & 0x02) { out.push(["IPv4 address", ipv4(v, o)]); o += 4; }
  if (f & 0x01) { out.push(["IPv6 address", ipv6(v, o)]); o += 16; }
  if (f & 0x10) out.push(["IPv4", "CHOOSE"]);
  if (f & 0x20) out.push(["IPv6", "CHOOSE"]);
  return out;
}

function pfcpOuterHeaderCreation(v) {
  const d = u16(v);
  const kinds = flagList(v[0], ["GTP-U/UDP/IPv4", "GTP-U/UDP/IPv6", "UDP/IPv4", "UDP/IPv6", "IPv4", "IPv6", "C-TAG", "S-TAG"]);
  const out = [["Description", kinds.join(", ") || hex(d, 4)]];
  let o = 2;
  if (v[0] & 0x03) { out.push(["TEID", hex(u32(v, o), 8)]); o += 4; }
  if (v[0] & 0x15) { out.push(["IPv4 address", ipv4(v, o)]); o += 4; }
  if (v[0] & 0x2a) { out.push(["IPv6 address", ipv6(v, o)]); o += 16; }
  if (v[0] & 0x0c && o + 2 <= v.length) out.push(["Port", u16(v, o)]);
  return out;
}

function pfcpFields(type, v) {
  switch (type) {
    case 19: return [["Cause", named(PFCP_CAUSE, v[0])]];
    case 20: return [["Source interface", named(PFCP_INTERFACE, v[0] & 0x0f)]];
    case 42: return [["Destination interface", named(PFCP_INTERFACE, v[0] & 0x0f)]];
    case 21: return pfcpFteid(v);
    case 22: return [["Network instance", labels(v)]];
    case 23: { // SDF Filter: flow description only
      if (v[0] & 0x01 && v.length >= 4) {
        const len = u16(v, 2);
        return [["Flow description", String.fromCharCode(...v.slice(4, 4 + len))]];
      }
      return null;
    }
    case 24: return [["Application ID", String.fromCharCode(...v)]];
    case 25: return [["Precedence", u32(v)]];
    case 26: {
      const g = { 0: "OPEN", 1: "CLOSED" };
      return [["UL gate", g[(v[0] >> 2) & 0x03] ?? "?"], ["DL gate", g[v[0] & 0x03] ?? "?"]];
    }
    case 27: return [["MBR UL", kbps(u40(v))], ["MBR DL", kbps(u40(v, 5))]];
    case 28: return [["GBR UL", kbps(u40(v))], ["GBR DL", kbps(u40(v, 5))]];
    case 29: return [["QER correlation ID", u32(v)]];
    case 44: { // Apply Action
      const f = flagList(v[0], ["DROP", "FORW", "BUFF", "NOCP", "DUPL", "IPMA", "IPMD", "DFRT"]);
      if (v.length > 1) f.push(...flagList(v[1], ["EDRT", "BDPN", "DDPN"]));
      return [["Action", f.join(", ") || "none"]];
    }
    case 39: { // Report Type
      const f = flagList(v[0], ["DLDR (downlink data)", "USAR (usage)", "ERIR (error indication)", "UPIR (user plane inactivity)", "TMIR", "SESR", "UISR"]);
      return [["Report", f.join(", ") || "none"]];
    }
    case 56: return [["PDR ID", u16(v)]];
    case 57: { // F-SEID
      const out = [["SEID", `0x${u32(v, 1).toString(16).padStart(8, "0")}${u32(v, 5).toString(16).padStart(8, "0")}`.toUpperCase().replace("0X", "0x")]];
      let o = 9;
      if (v[0] & 0x02) { out.push(["IPv4 address", ipv4(v, o)]); o += 4; }
      if (v[0] & 0x01) out.push(["IPv6 address", ipv6(v, o)]);
      return out;
    }
    case 60: { // Node ID
      const t = v[0] & 0x0f;
      if (t === 0) return [["Node ID (IPv4)", ipv4(v, 1)]];
      if (t === 1) return [["Node ID (IPv6)", ipv6(v, 1)]];
      if (t === 2) return [["Node ID (FQDN)", labels(v, 1)]];
      return null;
    }
    case 62: { // Measurement Method
      const f = flagList(v[0], ["DURAT (duration)", "VOLUM (volume)", "EVENT"]);
      return [["Method", f.join(", ") || "none"]];
    }
    case 64: return [["Measurement period", `${u32(v)} s`]];
    case 81: return [["URR ID", u32(v)]];
    case 84: return pfcpOuterHeaderCreation(v);
    case 93: return pfcpUeIp(v);
    case 95: return [["Outer header removal", named(OUTER_HEADER_REMOVAL, v[0])]];
    case 96: { // Recovery Time Stamp: NTP seconds since 1900
      const secs = u32(v);
      const date = new Date((secs - 2208988800) * 1000);
      return [["Recovery time", `${date.toISOString().replace("T", " ").replace(".000Z", " UTC")} (${secs})`]];
    }
    case 106: return [["Activate predefined rules", String.fromCharCode(...v)]];
    case 108: return [["FAR ID", u32(v)]];
    case 109: return [["QER ID", u32(v)]];
    case 113: return [["PDN type", named(PDN_TYPE, v[0] & 0x07)]];
    default: return null;
  }
}

// ------------------------------------------------------------------ values the core already decoded

const FTEID_IFACE = {
  0: "S1-U eNodeB GTP-U", 1: "S1-U SGW GTP-U", 2: "S12 RNC GTP-U", 3: "S12 SGW GTP-U",
  4: "S5/S8 SGW GTP-U", 5: "S5/S8 PGW GTP-U", 6: "S5/S8 SGW GTP-C", 7: "S5/S8 PGW GTP-C",
  8: "S5/S8 SGW PMIPv6", 9: "S5/S8 PGW PMIPv6", 10: "S11 MME GTP-C", 11: "S11/S4 SGW GTP-C",
  12: "S10/N26 MME GTP-C", 13: "S3 MME GTP-C", 14: "S3 SGSN GTP-C", 15: "S4 SGSN GTP-U",
  16: "S4 SGW GTP-U", 17: "S4 SGSN GTP-C", 18: "S16 SGSN GTP-C", 19: "eNodeB GTP-U (DL forwarding)",
  20: "eNodeB GTP-U (UL forwarding)", 21: "RNC GTP-U (data forwarding)", 22: "SGSN GTP-U (data forwarding)",
  23: "SGW/UPF GTP-U (DL forwarding)", 24: "Sm MBMS GW GTP-C", 25: "Sn MBMS GW GTP-C",
  26: "Sm MME GTP-C", 27: "Sn SGSN GTP-C", 28: "SGW GTP-U (UL forwarding)", 29: "Sn SGSN GTP-U",
  30: "S2b ePDG GTP-C", 31: "S2b-U ePDG GTP-U", 32: "S2b PGW GTP-C", 33: "S2b-U PGW GTP-U",
  34: "S2a TWAN GTP-U", 35: "S2a TWAN GTP-C", 36: "S2a PGW GTP-C", 37: "S2a PGW GTP-U",
  38: "S11 MME GTP-U", 39: "S11 SGW GTP-U", 40: "N26 AMF GTP-C", 41: "N19mb UPF GTP-U",
};

const STRING_IE = { 1: "IMSI", 75: "MEI", 76: "MSISDN" };

/** APN text may still carry its DNS length octets ("\binternet\u0007lguplus...") */
function apnText(s) {
  const b = Array.from(s, (c) => c.charCodeAt(0));
  return b.length && b[0] < 0x20 ? labels(b) : s;
}

/**
 * Fields for values the core hands over already decoded (objects and strings).
 * Used when the raw bytes can't be decoded here.
 */
export function valueFields(proto, ieType, kind, d) {
  if (d == null) return null;
  switch (kind) {
    case "Utf8String":
      return [[(proto === "gtp" && STRING_IE[ieType]) || "Value", d]];
    case "Apn":
      return [["APN", apnText(d)]];
    case "Ambr":
      return [["APN-AMBR UL", kbps(d.ul)], ["APN-AMBR DL", kbps(d.dl)]];
    case "BearerQoS":
      return [
        ["QCI", d.qci],
        ["ARP priority level", d.pl],
        ["Pre-emption capability", d.pci ? "Disabled" : "Enabled"],
        ["Pre-emption vulnerability", d.pvi ? "Disabled" : "Enabled"],
        ["MBR UL / DL", `${kbps(d.mbr_ul)} / ${kbps(d.mbr_dl)}`],
        ["GBR UL / DL", `${kbps(d.gbr_ul)} / ${kbps(d.gbr_dl)}`],
      ];
    case "FTeid": {
      const out = [["Interface", named(FTEID_IFACE, d.iface_type)], ["TEID", hex(d.teid, 8)]];
      if (d.ipv4) out.push(["IPv4 address", d.ipv4]);
      if (d.ipv6) out.push(["IPv6 address", d.ipv6]);
      return out;
    }
    case "ServingNetwork":
      return [["PLMN", `MCC ${d.mcc} / MNC ${d.mnc}`]];
    case "UserLocationInfo": {
      const out = [];
      if (d.tai) out.push(["TAI", `MCC ${d.tai.mcc} / MNC ${d.tai.mnc}, TAC ${d.tai.tac}`]);
      if (d.ecgi) out.push(["ECGI", `MCC ${d.ecgi.mcc} / MNC ${d.ecgi.mnc}, ECI ${d.ecgi.eci}`]);
      return out.length ? out : null;
    }
    case "Timer":
      return [["Timer", `${d.value} × unit ${d.unit}`]];
    default:
      return null;
  }
}

// ------------------------------------------------------------------ entry point

/**
 * @param proto    "gtp" or "pfcp"
 * @param ieType   IE type number
 * @param raw      IE bytes as the core sends them (GTPv2 includes the 4-byte
 *                 IE header, PFCP doesn't; both cases are handled)
 * @param ieLength value length from the IE header
 */
export function decodeIeFields(proto, ieType, raw, ieLength) {
  if (!raw || raw.length === 0) return null;
  const v = raw.length === ieLength + 4 ? raw.slice(4) : raw;
  if (v.length === 0) return null;
  try {
    const fields = proto === "pfcp" ? pfcpFields(ieType, v) : gtpFields(ieType, v);
    return fields && fields.length ? fields : null;
  } catch {
    return null; // malformed IE: let the caller show the raw value
  }
}
