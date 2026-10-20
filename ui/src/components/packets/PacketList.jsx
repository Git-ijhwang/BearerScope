import { useEffect, useMemo, useRef } from "react";
import {
  PROTO_FILTERS, canOpenFlow, filterPackets, protoFamily, protoLabel, splitDescription,
} from "./packetFormat";

function Address({ ip, port }) {
  return (
    <span className="data">
      {ip}
      {port ? <span className="port">:{port}</span> : null}
    </span>
  );
}

export default function PacketList({
  packets, selectedId, onSelect, onOpenFlow, filterText, onFilterText, proto, onProto, filterRef,
}) {
  const visible = useMemo(() => filterPackets(packets, filterText, proto), [packets, filterText, proto]);
  const counts = useMemo(() => {
    const c = { all: packets.length, gtp: 0, pfcp: 0, other: 0 };
    packets.forEach((p) => { c[protoFamily(p)] += 1; });
    return c;
  }, [packets]);

  // Keep the selected row in view when moving with the keyboard
  const bodyRef = useRef(null);
  useEffect(() => {
    const row = bodyRef.current?.querySelector(`tr[data-id="${selectedId}"]`);
    row?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  const move = (delta) => {
    if (visible.length === 0) return;
    const idx = visible.findIndex((p) => p.id === selectedId);
    const next = idx < 0 ? 0 : Math.min(visible.length - 1, Math.max(0, idx + delta));
    onSelect(visible[next].id);
  };

  const onKeyDown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") {
      const pkt = visible.find((p) => p.id === selectedId);
      if (pkt && canOpenFlow(pkt)) onOpenFlow(pkt.id);
    }
  };

  return (
    <section className="list-pane" aria-label="Packets">
      <div className="filter-bar">
        <input
          ref={filterRef}
          className="filter-input"
          type="search"
          placeholder="Filter by address, port or message"
          value={filterText}
          onChange={(e) => onFilterText(e.target.value)}
          aria-label="Filter packets"
        />
        <div className="proto-chips" role="group" aria-label="Protocol">
          {PROTO_FILTERS.map((f) => (
            <button
              key={f.id}
              className="chip"
              aria-pressed={proto === f.id}
              onClick={() => onProto(f.id)}
              disabled={f.id !== "all" && counts[f.id] === 0}
            >
              {f.label}<span className="count">{counts[f.id]}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="packet-scroll" tabIndex={0} onKeyDown={onKeyDown}>
        {visible.length === 0 ? (
          <div className="list-empty">
            No packets match this filter.
            <div>
              <button onClick={() => { onFilterText(""); onProto("all"); }}>Clear filter</button>
            </div>
          </div>
        ) : (
          <table className="packet-table">
            <thead>
              <tr>
                <th className="col-no">No.</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                {/*
                <th>Source Port</th>
                <th>Destination Port</th>
                */}
                <th>Protocol</th>
                <th className="col-len">Length</th>
                <th>Info</th>
                <th className="col-act"><span className="visually-hidden">Actions</span></th>
              </tr>
            </thead>

            <tbody ref={bodyRef}>
              {visible.map((pkt) => {
                const { text, code } = splitDescription(pkt.description);
                return (
                  <tr
                    key={pkt.id}
                    data-id={pkt.id}
                    aria-selected={pkt.id === selectedId}
                    onClick={() => onSelect(pkt.id)}
                    onDoubleClick={() => canOpenFlow(pkt) && onOpenFlow(pkt.id)}
                  >
                    <td className="col-no data">{pkt.id}</td>
                    {/*
                    <td className="col-addr"><Address ip={pkt.src_ip} /></td>
                    <td className="col-addr"><Address ip={pkt.dst_ip} /></td>
                    */}
                    <td className="col-addr"><Address ip={pkt.src_ip} port={pkt.src_port} /></td>
                    <td className="col-addr"><Address ip={pkt.dst_ip} port={pkt.dst_port} /></td>

{/*
                    <td className="col-port"><Address port={pkt.src_port} /></td>
                    <td className="col-port"><Address port={pkt.dst_port} /></td>
                    */}

                    <td><span className={`proto proto-${protoFamily(pkt)}`}>{protoLabel(pkt)}</span></td>
                    <td className="col-len data">{pkt.length || ""}</td>
                    <td className="col-info" title={pkt.description}>
                      {text}{code && <span className="code">{code}</span>}
                    </td>
                    <td className="col-act">
                      {canOpenFlow(pkt) && (
                        <button
                          className="btn-flow"
                          title="Show the call flow and bearer state for this session"
                          onClick={(e) => { e.stopPropagation(); onOpenFlow(pkt.id); }}
                        >
                          Call flow
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="status-line">
        <span>{visible.length === packets.length ? `${packets.length} packets` : `${visible.length} of ${packets.length} packets`}</span>
        <span><kbd>↑</kbd> <kbd>↓</kbd> select</span>
        <span><kbd>Enter</kbd> call flow</span>
        <span><kbd>/</kbd> filter</span>
      </div>
    </section>
  );
}
