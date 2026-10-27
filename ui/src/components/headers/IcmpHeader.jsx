import React, { useState, useId } from "react";
import "./ip.css";
import "./UdpHeader.css";
import BitGridHeader from "./common/BitGridHeader";
import HexDump from "./common/HexDump";

// RFC 792
const ICMP_TYPES = {
  0: "Echo Reply",
  3: "Destination Unreachable",
  5: "Redirect",
  8: "Echo Request",
  11: "Time Exceeded",
  12: "Parameter Problem",
  13: "Timestamp Request",
  14: "Timestamp Reply",
};

const hex4 = (n) => (n != null ? `0x${n.toString(16).toUpperCase().padStart(4, "0")}` : "-");
const typeName = (t) => (ICMP_TYPES[t] ? `${ICMP_TYPES[t]} [${t}]` : `${t}`);
// Echo, Timestamp and their replies carry an identifier and sequence number
const hasIdSeq = (t) => [0, 8, 13, 14].includes(t);

export default function IcmpHeader({ icmp }) {
  const [viewMode, setViewMode] = useState("decoded");
  const switchId = useId(); // unique per card, so each label toggles its own switch

  if (!icmp) return null;
  const payloadLen = icmp.payload?.length ?? 0;

  return (
    <div className="card mb-3">
      <div className="card-header icmp-header d-flex justify-content-between align-items-center">
        <strong>Layer 4 (Transport)</strong>
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
                    <th colSpan="2" style={{ textAlign: "center" }}><b>ICMP Header</b></th>
                  </tr>
                  <tr><th>Type</th><td>{typeName(icmp.icmp_type)}</td></tr>
                  <tr><th>Code</th><td>{icmp.code}</td></tr>
                  <tr><th>Checksum</th><td>{hex4(icmp.checksum)}</td></tr>
                  {hasIdSeq(icmp.icmp_type) && (
                    <>
                      <tr><th>Identifier</th><td>{hex4(icmp.id)}</td></tr>
                      <tr><th>Sequence</th><td>{icmp.seq}</td></tr>
                    </>
                  )}
                  <tr><th>Payload</th><td>{payloadLen} bytes</td></tr>
                </tbody>
              </table>
            </div>
            <div className="raw-layout-dump">
              <HexDump raw={[...(icmp.raw || []), ...(icmp.payload || [])]} />
            </div>
          </div>
        ) : (
          <table className="bit-grid-table udp-table">
            <BitGridHeader showOctet={true} />
            <tbody>
              <tr>
                <th colSpan="2" className="field">0</th>
                <td colSpan="8" className="field"><i>Type:</i> {typeName(icmp.icmp_type)}</td>
                <td colSpan="8" className="field"><i>Code:</i> {icmp.code}</td>
                <td colSpan="16" className="field"><i>Checksum:</i> {hex4(icmp.checksum)}</td>
              </tr>
              <tr>
                <th colSpan="2" className="field">4</th>
                {hasIdSeq(icmp.icmp_type) ? (
                  <>
                    <td colSpan="16" className="field"><i>Identifier:</i> {hex4(icmp.id)}</td>
                    <td colSpan="16" className="field"><i>Sequence:</i> {icmp.seq}</td>
                  </>
                ) : (
                  <td colSpan="32" className="field"><i>Rest of header</i></td>
                )}
              </tr>
              {payloadLen > 0 && (
                <tr>
                  <th colSpan="2" className="field">8</th>
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