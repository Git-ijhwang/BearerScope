import React, { useState, useId } from "react";
import "./UdpHeader.css";
import HexDump from "./common/HexDump";
import BitGridHeader from "./common/BitGridHeader";

// RFC 9293 3.1: control bits in octet 13, most significant first
const FLAGS = [
  { bit: 0x80, short: "C", name: "CWR" },
  { bit: 0x40, short: "E", name: "ECE" },
  { bit: 0x20, short: "U", name: "URG" },
  { bit: 0x10, short: "A", name: "ACK" },
  { bit: 0x08, short: "P", name: "PSH" },
  { bit: 0x04, short: "R", name: "RST" },
  { bit: 0x02, short: "S", name: "SYN" },
  { bit: 0x01, short: "F", name: "FIN" },
];

const hex4 = (n) => (n != null ? `0x${n.toString(16).toUpperCase().padStart(4, "0")}` : "-");
const flagNames = (flags) => FLAGS.filter((f) => flags & f.bit).map((f) => f.name).join(" ") || "none";
const port = (num, name) => (name ? `${name} [${num}]` : `${num}`);

export default function TcpHeader({ tcp }) {
  const [viewMode, setViewMode] = useState("decoded");
  const switchId = useId(); // unique per card, so each label toggles its own switch

  if (!tcp) return null;

  const optionsLen = tcp.options?.length ?? 0;
  const payloadLen = tcp.payload?.length ?? 0;
  const headerLen = tcp.header_sz || 20;

  return (
    <div className="card mb-3">
      <div className="card-header udp-card-header d-flex justify-content-between align-items-center">
        <div className="d-flex align-items-center">
          <span className="protocol-badge">L4</span>
          <strong className="protocol-title">TCP Header</strong>
        </div>
        <div className="form-check form-switch d-inline-flex align-items-center ms-3" style={{ fontSize: "14px" }}>
          <label className="form-check-label me-5" htmlFor={switchId}>
            {viewMode === "raw" ? "Raw" : "Decoded"}
          </label>
          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id={switchId}
            checked={viewMode === "raw"}
            onChange={() => setViewMode(viewMode === "raw" ? "decoded" : "raw")}
          />
        </div>
      </div>

      <div className="card-body udp-card-body">
        {viewMode === "raw" ? (
          <div className="raw-layout">
            <div className="raw-layout-fields">
              <table className="table table-bordered table-sm udp-table" style={{ fontSize: "14px" }}>
                <tbody>
                  <tr>
                    <th colSpan="2" style={{ textAlign: "center" }}><b>TCP Header</b></th>
                  </tr>
                  <tr><th>Source Port</th><td>{port(tcp.src_port, tcp.str_src_port)}</td></tr>
                  <tr><th>Destination Port</th><td>{port(tcp.dst_port, tcp.str_dst_port)}</td></tr>
                  <tr><th>Sequence Number</th><td>{tcp.seq}</td></tr>
                  <tr><th>Acknowledgment Number</th><td>{tcp.ack}</td></tr>
                  <tr><th>Header Length</th><td>{headerLen} bytes ({headerLen / 4} words)</td></tr>
                  <tr><th>Flags</th><td>{flagNames(tcp.flags)}</td></tr>
                  <tr><th>Window</th><td>{tcp.window}</td></tr>
                  <tr><th>Checksum</th><td>{hex4(tcp.checksum)}</td></tr>
                  <tr><th>Urgent Pointer</th><td>{tcp.urgent}</td></tr>
                  {optionsLen > 0 && <tr><th>Options</th><td>{optionsLen} bytes</td></tr>}
                  <tr><th>Payload</th><td>{payloadLen} bytes</td></tr>
                </tbody>
              </table>
            </div>
            <div className="raw-layout-dump">
              {/* The header itself, options included (as UDP shows its 8 bytes) */}
              <HexDump raw={[...(tcp.raw || []), ...(tcp.options || [])]} />
            </div>
          </div>
        ) : (
          <table className="bit-grid-table udp-table">
            <BitGridHeader showOctet={true} />
            <tbody>
              <tr>
                <th colSpan="2" className="field">0</th>
                <td colSpan="16" className="field"><i>Source Port:</i> {port(tcp.src_port, tcp.str_src_port)}</td>
                <td colSpan="16" className="field"><i>Destination Port:</i> {port(tcp.dst_port, tcp.str_dst_port)}</td>
              </tr>
              <tr>
                <th colSpan="2" className="field">4</th>
                <td colSpan="32" className="field"><i>Sequence Number:</i> {tcp.seq}</td>
              </tr>
              <tr>
                <th colSpan="2" className="field">8</th>
                <td colSpan="32" className="field"><i>Acknowledgment Number:</i> {tcp.ack}</td>
              </tr>
              <tr>
                <th colSpan="2" className="field">12</th>
                <td colSpan="4" className="field" title={`Data offset ${headerLen / 4} words = ${headerLen} bytes`}>
                  <i>Off:</i> {headerLen / 4}
                </td>
                <td colSpan="4" className="field"><i>Rsv</i></td>
                {FLAGS.map((f) => (
                  <td
                    key={f.name}
                    className={`field tcp-flag${tcp.flags & f.bit ? " is-set" : ""}`}
                    title={`${f.name} ${tcp.flags & f.bit ? "set" : "not set"}`}
                  >
                    {f.short}
                  </td>
                ))}
                <td colSpan="16" className="field"><i>Window:</i> {tcp.window}</td>
              </tr>
              <tr>
                <th colSpan="2" className="field">16</th>
                <td colSpan="16" className="field"><i>Checksum:</i> {hex4(tcp.checksum)}</td>
                <td colSpan="16" className="field"><i>Urgent Pointer:</i> {tcp.urgent}</td>
              </tr>
              {optionsLen > 0 && (
                <tr>
                  <th colSpan="2" className="field">20</th>
                  <td colSpan="32" className="field"><i>Options:</i> {optionsLen} bytes</td>
                </tr>
              )}
              {payloadLen > 0 && (
                <tr>
                  <th colSpan="2" className="field">{headerLen}</th>
                  <td colSpan="32" className="field"><i>Data:</i> {payloadLen} bytes</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
