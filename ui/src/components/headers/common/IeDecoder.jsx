import "../gtp/GtpTable.css";
import { decodeIeFields, valueFields } from "./ieFields";

function ComponentRenderer({ comp })
{
  if (!comp) return <div>None</div>;
   // comp가 string ("None")일 수도 있음

  if (typeof comp === "string") {
    return <div>{comp}</div>;
  }

  const type = Object.keys(comp)[0];   // "Ipv4Addr", "Protocol", ...
  const data = comp[type];

  switch (type) {

    case "Ipv4Addr":
      return (
        <div>
          <div>   IPv4 Addr: 
          {data.addr}</div>
          <div>  Mask: {data.mask}</div>
        </div>
      );

    case "Ipv6Addr":
      return (
        <div>
          <div>  IPv6 Addr: {data.addr}</div>
          <div>  Mask: {data.mask}</div>
        </div>
      );

    case "Protocol":
      return <div>  Protocol: {data.proto}</div>;

    case "SinglePort":
      return <div>  Port: {data.port}</div>;

    case "PortRange":
      return (
        <div>  Port Range: {data.start} - {data.end}
        </div>
      );

    case "SecParamIdx":
      return <div>  SPI: {data.spi}</div>;

    case "TypeOfService":
      return (
        <div>  ToS Value: {data.value}, Mask: {data.mask} </div>
      );

    case "FlowLabel":
      return <div>  low Label: {data.label}</div>;

    case "Unknown":
      return (
        <div>
          <i>Unknown data</i>: type {data.t}, raw = [{data.data.join(", ")}]
        </div>
      );

    default:
      return <div>None</div>;
  }
}

/** label: value lines. Grid mode (numrow > 1) fills the IE's byte rows; viewer mode is a plain block */
function renderFields(fields, numrow) {
  const list = (
    <div className={numrow > 1 ? "ie-fields" : "ie-fields is-stacked"}>
      {fields.map(([label, val], i) => (
        <div key={i} className="ie-field">
          <span className="ie-field-key">{label}</span>
          <span className="ie-field-val">{String(val)}</span>
        </div>
      ))}
    </div>
  );
  if (numrow <= 1) return list;
  return (
    <>
      <tr className="value-row">
        <td colSpan="32" className="field">{list}</td>
      </tr>
      {Array.from({ length: numrow - 2 }).map((_, index) => (
        <tr key={index}>
          <td colSpan="32" className="text-center text-gray-300 italic continuation-cell field">
            Continuation
          </td>
        </tr>
      ))}
    </>
  );
}

// Value kinds the core leaves undecoded; these get field-level decoding here
const PLAIN_KINDS = ["Raw", "Uint8", "Uint16", "Uint32", "Ipv4", "Ipv6", "None"];
const STRUCT_KINDS = ["Utf8String", "Apn", "Ambr", "BearerQoS", "FTeid", "ServingNetwork", "UserLocationInfo", "Timer"];

function decodeIe(value, ietype, numrow=1, ieLength=0, raw=null, proto="gtp") {
  if (!value) return null;

  const type = typeof value === "string" ? value : Object.keys(value)[0];
  const data = typeof value === "string" ? null : value[type];

  if (PLAIN_KINDS.includes(type)) {
    if (proto === "gtp" && ietype == 73) {
      return renderFields([["EPS bearer ID", data]], numrow);
    }
    const fields = decodeIeFields(proto, ietype, raw, ieLength);
    if (fields) return renderFields(fields, numrow);
    // Unknown IE: show the number, or the bytes as hex
    const shown = Array.isArray(data)
      ? data.map((b) => b.toString(16).padStart(2, "0")).join(" ")
      : data ?? "(empty)";
    return renderFields([[type === "Raw" ? "Bytes" : "Value", shown]], numrow);
  }
  // Values the core already decoded: decode from the bytes where we can
  // (more complete), otherwise list what the core gave us
  if (STRUCT_KINDS.includes(type)) {
    const fields = decodeIeFields(proto, ietype, raw, ieLength) ?? valueFields(proto, ietype, type, data);
    if (fields) return renderFields(fields, numrow);
  }

  const numDataRows = numrow - 1; // 실제 데이터가 차지하는 행 수
  const lastRowBytes = ieLength % 4 || 4; // 마지막 줄이 차지하는 바이트 수 (1, 2, 3, 4)

  switch (type) {

    case "Uint8":
      if (ietype == 73) {
        return (
          <>
            <td colSpan="4" className="field"><span> Spare </span> </td>
            <td colSpan="4" className="field"> <span>{data}</span> </td>
          </>
        );
      } else {
        return (
          <>
            <td colSpan="8" className="field"> <span>{data}</span> </td>
          </>
        );
      }
    case "Uint16":
      return (
        <td colSpan="16" className="field"> <span>{data}</span> </td>
      );

    case "Uint32":
      return (
        <td colSpan="32" className="field"> <span>{data}</span> </td>
      );
    case "Ipv4":
      return( <td colSpan="32" className="field"> <span>{data}</span>; </td>);

    case "Ambr":
      return (
        <>
        {Array.from({ length: numDataRows }).map((_, index) => {
          const isFirst = index === 0;
          const isLast = index === numDataRows - 1;

          const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

          return (
            <tr key={index} className={rowClassName}>
              {isFirst ? (
                /* 1. 첫 번째 줄: 모든 데이터를 출력 */
                isLast && lastRowBytes < 4 ? (
                  /* 만약 데이터가 딱 한 줄인데 4바이트가 안 되는 경우 */
                  <>
                    <td colSpan={lastRowBytes * 8}
                      className="text-center font-mono font-bold text-blue-700 field">
                        <div>UL: {data.ul}</div>
                        <div>DL: {data.dl}</div>
                    </td>
                    <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center field">
                      Spare
                    </td>
                  </>
                ) : (
                  /* 일반적인 첫 번째 줄 (전체 너비 사용) */
                  <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700  field">
                    {typeof data === 'object' ?(
                    // JSON.stringify(data)
                    <>
                      <div>UL: {data.ul}</div>
                      <div>DL: {data.dl}</div>
                    </>
                    )
                    : data}
                  </td>
                )
              ) : isLast && lastRowBytes < 4 ? (
                /* 2. 마지막 줄: 데이터가 남은 만큼만 Continuation을 그리고 나머지는 Spare */
                <>
                  <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-400 italic field">
                    Continuation
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-cente field">
                  </td>
                </>
              ) : (
                /* 3. 중간 줄 혹은 딱 떨어지는 마지막 줄: 전체 너비 Continuation */
                <td colSpan="32" className="text-center text-[10px] text-gray-400  italic field">
                  Continuation
                </td>
              )}
            </tr>
          );
        })}
        </>
      );

    case "Utf8String":
    case "Apn":
      return(
        <>
        {Array.from({ length: numDataRows }).map((_, index) => {
        const isFirst = index === 0;
        const isLast = index === numDataRows - 1;

        const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

        return (
          <tr key={index} className={rowClassName}>
            {isFirst ? (
              /* 1. 첫 번째 줄: 모든 데이터를 출력 */
              isLast && lastRowBytes < 4 ? (
                /* 만약 데이터가 딱 한 줄인데 4바이트가 안 되는 경우 */
                <>
                  <td colSpan={lastRowBytes * 8}
                    className="text-center font-mono font-bold text-blue-700  field">
                    {JSON.stringify(data)}
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className=" text-gray-900 italic text-[9px] text-center field">
                  </td>
                </>
              ) : (
                /* 일반적인 첫 번째 줄 (전체 너비 사용) */
                <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700  field">
                  {typeof data === 'object' ? JSON.stringify(data) : data}
                </td>
              )
            ) : isLast && lastRowBytes < 4 ? (
              /* 2. 마지막 줄: 데이터가 남은 만큼만 Continuation을 그리고 나머지는 Spare */
              <>
                <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-900  italic field">
                  Continuation
                </td>
                <td colSpan={(4 - lastRowBytes) * 8} className=" text-gray-400 italic text-[9px] text-center field">
                </td>
              </>
            ) : (
              /* 3. 중간 줄 혹은 딱 떨어지는 마지막 줄: 전체 너비 Continuation */
              <td colSpan="32" className="text-center text-[10px] text-gray-900  italic field">
                Continuation
              </td>
            )}
          </tr>
        );
      })}
        </>
      );

    case "BearerQoS":
      return (
        <>
          {/* <tr>
            <td colSpan="32">
              <div>
                <div>QCI: {data.qci}</div>
                <div>Max UL: {data.max_ul?  data.max_ul : "-" }</div>
                <div>Max DL: { data.max_dl?  data.max_ul : "-" }</div>
                <div>Guaranteed UL: {data.gbr_ul}</div>
                <div>Guaranteed DL: {data.gbr_dl}</div>
              </div>
            </td>
          </tr>

          {Array.from({ length: numrow -2 }).map((_, index) => (
            <tr key={index}>
              <td colSpan="32"
                  className="text-center bg-gray-50 text-gray-300 italic">
                Continuation
              </td>
            </tr>
          ))} */}
        {Array.from({ length: numDataRows }).map((_, index) => {
          const isFirst = index === 0;
          const isLast = index === numDataRows - 1;

          const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

          return (
            <tr key={index} className={rowClassName}>
              {isFirst ? (
                /* 1. 첫 번째 줄: 모든 데이터를 출력 */
                isLast && lastRowBytes < 4 ? (
                  /* 만약 데이터가 딱 한 줄인데 4바이트가 안 되는 경우 */
                  <>
                    <td colSpan={lastRowBytes * 8}
                      className="text-center font-mono font-bold text-blue-700  field">
                      {/* {JSON.stringify(data)} */}
                        <div>QCI: {data.qci}</div>
                        <div>Max UL: {data.max_ul?  data.max_ul : "-" }</div>
                        <div>Max DL: { data.max_dl?  data.max_ul : "-" }</div>
                        <div>Guaranteed UL: {data.gbr_ul}</div>
                        <div>Guaranteed DL: {data.gbr_dl}</div>
                    </td>
                    <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center field">
                      Spare
                    </td>
                  </>
                ) : (
                  /* 일반적인 첫 번째 줄 (전체 너비 사용) */
                  <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700  field">
                    {typeof data === 'object' ?(
                    // JSON.stringify(data)
                    <>
                        <div>QCI: {data.qci}</div>
                        <div>Max UL: {data.max_ul?  data.max_ul : "-" }</div>
                        <div>Max DL: { data.max_dl?  data.max_ul : "-" }</div>
                        <div>Guaranteed UL: {data.gbr_ul}</div>
                        <div>Guaranteed DL: {data.gbr_dl}</div>
                    </>
                    )
                    : data}
                  </td>
                )
              ) : isLast && lastRowBytes < 4 ? (
                /* 2. 마지막 줄: 데이터가 남은 만큼만 Continuation을 그리고 나머지는 Spare */
                <>
                  <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-400  italic field">
                    Continuation
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center field">
                  </td>
                </>
              ) : (
                /* 3. 중간 줄 혹은 딱 떨어지는 마지막 줄: 전체 너비 Continuation */
                <td colSpan="32" className="text-center text-[10px] text-gray-400  italic field">
                  Continuation
                </td>
              )}
            </tr>
          );
        })}
        </>
      );

    case "BearerTFT":
      // 1. 내부 콘텐츠 렌더링 헬퍼
      const renderTftDetails = () => (
        <div className="tft-wrapper text-left p-2"
            style={{ lineHeight: '1.4' }}>
          <div className="mb-1 border-b border-blue-100 pb-1">
            <span className="text-blue-800">TFT Op:</span> 
            {data.str_tft_op_code} [{data.tft_op_code}]
            <span className="mx-2 text-gray-300">|</span>
            Filters:  {data.num_filter}
          </div>

          <div className="pf-scroll-area"
              style={{ maxHeight: '150px', overflowY: 'auto' }}>

            {data.packet_filter_list?.map((pf, pfIdx) => (

              <div key={`pf-${pfIdx}`}
                // className="mb-2 p-1 bg-gray-50 border-l-2 border-blue-400"
                >

                <div className="font-bold text-blue-600">
                   Packet Filter ID#{pfIdx + 1}  ({pf.pf_dir})
                </div>

                <ul className="ml-2 list-none text-[10px]"
                    style={{ listStyle: 'none', paddingLeft: '5px', margin: 0 }}
                >
                  {pf.packet_filter_component_list?.map((comp, cidx) => (
                     <li key={`comp-${cidx}`} className="truncate">
                      {/* ID: 0x{comp.pf_type_id.toString(16)} | */}
                      <ComponentRenderer comp={comp.components} />
                    </li>
                  ))}

                </ul>
              </div>
            ))}
          </div>
        </div>
      );

      // Raw view: no byte rows to fill, just the details
      if (numrow <= 1) return renderTftDetails();

  return (
    <>
      {Array.from({ length: numrow - 1 }).map((_, index) => {
        const isFirst = index === 0;
        const isLast = index === (numrow - 2); // numrow-1개 중 마지막
        const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;

        return (
          <tr key={index} className={rowClassName}>
            {isFirst ? (
              /* 첫 번째 줄: TFT 상세 정보 출력 */
              <>
                <td 
                  colSpan={isLast && lastRowBytes < 4 ? lastRowBytes * 8 : 32} 
                  className=" align-top field"
                  style={{ height: 'auto' }} // 데이터가 많으면 첫 줄만 늘어남
                >
                  {renderTftDetails()}
                </td>
                {isLast && lastRowBytes < 4 && (
                  <td colSpan={(4 - lastRowBytes) * 8} className="spare-cell field">Spare</td>
                )}
              </>
            ) : (
              /* 나머지 줄: Continuation + Spare 처리 */
              <>
                <td 
                  colSpan={isLast && lastRowBytes < 4 ? lastRowBytes * 8 : 32} 
                  className="text-center text-[10px] text-gray-400  italic field"
                >
                  Continuation
                </td>
                {isLast && lastRowBytes < 4 && (
                  <td colSpan={(4 - lastRowBytes) * 8} className="spare-cell field"></td>
                )}
              </>
            )}
          </tr>
        );
      })}
    </>
  );
/*
    case "BearerTFT":
      return (
        <>
        {Array.from({ length: numDataRows }).map((_, index) => {
          const isFirst = index === 0;
          const isLast = index === numDataRows - 1;

          const rowClassName = `value-row ${isLast ? 'ie-last-row' : ''}`;
          return (
            <tr key={index} className={rowClassName}>
              {isFirst ? (
                isLast && lastRowBytes < 4 ? (
                  <>
                    <td colSpan={lastRowBytes * 8}
                      className="text-center font-mono font-bold text-blue-700 bg-white">

            <div>TFT Operation Code: {data.tft_op_code} ({data.str_tft_op_code})</div>
            <div>Number of Packet Filters: {data.num_filter}</div>

            <hr />

            {data.packet_filter_list?.map((pf, pfIdx) => (
              <div key={`pf-${pfIdx}`} style={{ marginTop: "10px", padding: "10px", border: "1px solid #ccc" }}>
                Packet Filter #{pfIdx + 1}

                <div>Direction: {pf.pf_dir}</div>

                <div style={{ marginTop: "10px" }}>
                  Components:
                  <ul>
                    {pf.packet_filter_component_list?.map((comp, cidx) => (
                      <li key={`comp-${cidx}`} style={{ marginTop: "5px" }}>
                        <div>Type ID: 0x{comp.pf_type_id.toString(16)}</div>

                        <ComponentRenderer comp={comp.components} />
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
                    </td>
                    <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                      Spare
                    </td>
                  </>
                ):(
                  <td colSpan="32" className="p-2 text-center font-mono font-bold text-blue-700 bg-white">
                    {typeof data === 'object' ?(
                    <>
            <div>TFT Operation Code: {data.tft_op_code} ({data.str_tft_op_code})</div>
            <div>Number of Packet Filters: {data.num_filter}</div>

            <hr />

            {data.packet_filter_list?.map((pf, pfIdx) => (
              <div key={`pf-${pfIdx}`} style={{ marginTop: "10px", padding: "10px", border: "1px solid #ccc" }}>
                Packet Filter #{pfIdx + 1}

                <div>Direction: {pf.pf_dir}</div>

                <div style={{ marginTop: "10px" }}>
                  Components:
                  <ul>
                    {pf.packet_filter_component_list?.map((comp, cidx) => (
                      <li key={`comp-${cidx}`} style={{ marginTop: "5px" }}>
                        <div>Type ID: 0x{comp.pf_type_id.toString(16)}</div>

                        <ComponentRenderer comp={comp.components} />
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
                    </>
                    )
                    : data}
                  </td>
                )
              ): isLast && lastRowBytes < 4 ? (
                <>
                  <td colSpan={lastRowBytes * 8} className="text-center text-[10px] text-gray-400 bg-gray-50/50 italic">
                    Continuation
                  </td>
                  <td colSpan={(4 - lastRowBytes) * 8} className="bg-gray-100 text-gray-400 italic text-[9px] text-center">
                    Spare
                  </td>
                </>
              ) : (
                <td colSpan="32" className="text-center text-[10px] text-gray-400 bg-gray-50/50 italic">
                  Continuation
                </td>
              )}

            </tr>

          );
        })}
        </>
      );
*/
    case "FTeid":
      // F-TEID도 데이터가 길어질 수 있으므로 행을 분리합니다.
      return (
        <>
          <tr>
            <td colSpan="32" className="field">
              <div>
                {/* <div>TEID: 0x{data.teid(16)}</div> */}
                TEID: 0x{data?.teid?.toString(16).padStart(8, '0').toUpperCase()}
                {data.v4 &&
                  <div>IPv4 Address: {data.ipv4}</div>
                }
                {data.v6 &&
                  <div>IPv6 Address: {data.ipv6}</div>
                }
                <div>Interface Type: {data.iface_type}</div>
              </div>
            </td>
          </tr>

          {Array.from({ length: numrow -2 }).map((_, index) => (
            <tr key={index}>
              <td colSpan="32"
                  className="text-center  text-gray-300 italic field">
                Continuation
              </td>
            </tr>
          ))}
          </>
      );

    default:
      // 기본형 데이터
      // return renderIeGrid(data );
      return(
        <>
          <tr>
            <td colSpan="32" className="text-center text-gray-300 italic continuation-cell field">
              {typeof data === 'object' ? JSON.stringify(data) : data}
            </td>
          </tr>

          {Array.from({ length: numrow -2 }).map((_, index) => (
            <tr key={index}>
              <td colSpan="32" className="text-center text-gray-300 italic continuation-cell field">
                Continuation
              </td>
            </tr>
          ))}
        </>
      );
  }
}
/** One malformed or unexpected IE must not take the whole screen down */
function IeDecoder(value, ietype, numrow = 1, ieLength = 0, raw = null, proto = "gtp") {
  try {
    return decodeIe(value, ietype, numrow, ieLength, raw, proto);
  } catch (err) {
    console.error(`IE ${ietype} decode failed`, err, value);
    return renderFields([["Decode error", String(err?.message || err)], ["Value", JSON.stringify(value)]], numrow);
  }
}

export default IeDecoder;