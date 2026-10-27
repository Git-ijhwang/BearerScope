/* global BigInt */

import React, { useState, useId, useMemo } from "react";
import BitGridHeader from '../common/BitGridHeader';
import HexDump from '../common/HexDump';
import { ieOffsets } from '../common/ieOffsets';
import PfcpIeViewer from './PfcpIeViewer';
import PfcpIeTable from './PfcpIeTable';
import "./PfcpViewer.css";



export default function PfcpHeader({ pfcp }) {
  const [viewMode, setViewMode] = useState("decoded");
  const switchId = useId(); // unique per card, so each label toggles its own switch
  const [hoveredRaw, setHoveredRaw] = useState(null); // ★ hover 상태
  const offsets = useMemo(() => ieOffsets(pfcp?.raw || [], pfcp?.ies, (pfcp?.raw?.[0] & 0x01) ? 16 : 8), [pfcp]);
  const highlight = hoveredRaw && offsets.has(hoveredRaw)
    ? { start: offsets.get(hoveredRaw), length: hoveredRaw.length } : null;

  // const high = Number((BigInt(pfcp.seid) >> 32n) & 0xffffffffn);
  // const low  = Number(BigInt(pfcp.seid) & 0xffffffffn);
  const raw = pfcp?.raw || [];
  const word = (o) => ((raw[o] << 24) | (raw[o + 1] << 16) | (raw[o + 2] << 8) | raw[o + 3]) >>> 0;
  const hasSeid = Boolean(pfcp?.s_flag) && raw.length >= 12;
  const high = hasSeid ? word(4) : 0;
  const low = hasSeid ? word(8) : 0;
  const hex8 = (n) => n.toString(16).padStart(8, "0");

  if (!pfcp) return null;


  return (
    <div className="card mb-3">
      <div className="card-header pfcp-header d-flex justify-content-between align-items-center">
        <div className="d-flex align-items-center">
          <span className="protocol-badge">L7</span>
        <strong className="protocol-title">PFCP</strong>
        </div>

        <div className="form-check form-switch d-inline-flex align-items-center ms-3"
          style={{ fontSize: "14px" }} >

          <label className="form-check-label me-5" htmlFor={switchId}>
            {viewMode === "raw" ? "Raw" : "Decoded"}
          </label>

          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id={switchId}
            checked={viewMode === "raw"}
            onChange={() =>
              setViewMode(viewMode === "raw" ? "decoded" : "raw")
            }
          />
        </div>
      </div>

      <div className="card-body pfcp-card-body">
        {viewMode === "raw" ? (

          <div className="raw-layout">
            <div className="raw-layout-fields">

              <table className="table table-bordered table-sm" style={{ fontSize: "14px" }}>
                <tbody>
                  <tr>
                    <th colSpan="2" style={{textAlign: "Center"}}>
                      <b>PFCP Header</b>
                    </th>
                  </tr>

                  <tr>
                    <th>Version</th>
                    <td>{pfcp.version}</td>
                  </tr>
                  
                  <tr>
                    <th>FO Flag</th>
                    <td>{ pfcp.fo_flag?  "1":"0" }</td>
                  </tr>
                  
                  <tr>
                    <th>MP Flag</th>
                    <td>{ pfcp.mp_flag?  "1":"0" }</td>
                  </tr>
                  
                  <tr>
                    <th>S Flag</th>
                    <td>{ pfcp.s_flag?  "1":"0" }</td>
                  </tr>
                  
                  <tr>
                    <th>Message Type</th>
                    <td>{pfcp.msg_type_str} [{pfcp.msg_type}]</td>
                  </tr>
                  
                  <tr>
                    <th>Message Length</th>
                    <td>{pfcp.msg_len}</td>
                  </tr>
                  
                  { pfcp.s_flag ? (
                    <tr>
                      <th>SEID</th>
                      <td>
                        0x{hex8(high)}{hex8(low)}
                      </td>
                    </tr>
                  ) : (
                    <></>
                  )}

                  <tr>
                    <th>Sequence</th>
                    <td>
                      0x{(pfcp.seq ?? 0).toString(16).padStart(6, "0")}

                    </td>
                  </tr>

                  <tr >
                    <td colSpan="2" style={{backgroundColor:"#a3b2c3"}}>
                      PFCP IEs
                      <PfcpIeViewer ies={pfcp.ies} onHoverRaw={setHoveredRaw} />  {/* 여기서 호출 */}
                    </td>
                  </tr>

                </tbody>
              </table>

            </div>
            <div className="raw-layout-dump">
              {/* One dump of the whole message; hovering an IE highlights its bytes */}
              <HexDump raw={pfcp.raw} highlight={highlight} />
            </div>
          </div>

        ):(
          <div>
            {/* <table className="pfcp-table "> */}
            <table className="bit-grid-table ">

              <BitGridHeader showOctet={true}/>

              <tbody>
                <tr>
                { pfcp.s_flag ? (
                  <th rowSpan="4" colSpan="2" className="vertical pfcp-header">
                    PFCP Header
                  </th>
                ):(
                  <th rowSpan="2" colSpan="2" className="vertical pfcp-header">
                    PFCP Header
                  </th>
                )}
                  <td colSpan="3" className="field"><i>Version:</i> {pfcp.version}</td>
                  <td colSpan="2" className="field"><i>Spare</i> </td>
                  <td colSpan="1" className="field"><i>FO:</i> {pfcp.fo_flag ? "1" : "0"}</td>
                  <td colSpan="1" className="field"><i>MP:</i> {pfcp.mp_flag ? "1" : "0"}</td>
                  <td colSpan="1" className="field"><i>S:</i> {pfcp.s_flag ? "1" : "0"}</td>

                  <td colSpan="8" className="field"><i>Message Type: </i> {pfcp.msg_type_str}[{pfcp.msg_type}] </td>
                  <td colSpan="16" className="field"><i>Length: </i>{pfcp.msg_len} </td>
                </tr>

                { pfcp.s_flag ? (
                  <>
                  <tr>
                    <td colSpan="32" className="field">
                      <i>SEID[63:32]</i> : 0x{hex8(high)}
                    </td>
                  </tr>

                  <tr>
                    <td colSpan="32" className="field">
                      <i>SEID[31:0]</i> : 0x{hex8(low)}
                    </td>
                  </tr>
                  </>
                ):( <></>)}

                <tr>
                    <>
                      <td colSpan="24" className="field"><i>Sequence Number:0x</i>
                        {pfcp.seq != null ? pfcp.seq.toString(16).padStart(6, "0")
                        // .toUpperCase()
                        : "-"}
                        {/* {pfcp.seq} */}
                      </td>
                      {/* <td colSpan="8"><i>Sequence Number</i> </td> */}
                      <td colSpan="8" className="field"><i>Spare</i> </td>
                    </>
                </tr>
                <PfcpIeTable ies={pfcp.ies} />
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}