import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ContextMenu from "../ContextMenu";
import {
  PROTO_FILTERS, canOpenFlow, filterPackets, protoFamily, protoLabel, splitDescription, startsSession,
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
  packets, selectedId, onSelect, onOpenFlow, onOpenWindow, filterText, onFilterText, proto, onProto, filterRef,
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

  // Right-click menu: { x, y, pkt } or null
  const [menu, setMenu] = useState(null);
  const scrollRef = useRef(null);
  const closeMenu = useCallback(() => {
    setMenu(null);
    scrollRef.current?.focus({ preventScroll: true });
  }, []);

  const openMenu = (e, pkt) => {
    e.preventDefault();
    // onSelect(pkt.id);
    setMenu({ x: e.clientX, y: e.clientY, pkt });
  };

  // Shift+F10 or the Menu key: open the menu under the selected row
  const openMenuFromKeyboard = () => {
    const pkt = visible.find((p) => p.id === selectedId);
    const row = bodyRef.current?.querySelector(`tr[data-id="${selectedId}"]`);
    if (!pkt || !row) return;
    const r = row.getBoundingClientRect();
    setMenu({ x: r.left + 120, y: r.bottom - 4, pkt });
  };

  const menuItems = (pkt) => [
    {
      id: "flow",
      label: "Show call flow",
      shortcut: "Enter",
      disabled: !canOpenFlow(pkt),
      hint: canOpenFlow(pkt) ? null : "GTPv2-C session messages only",
      onSelect: () => onOpenFlow(pkt.id),
    },
    {
      id: "window",
      label: "Open in new window",
      shortcut: "⇧ Enter",
      onSelect: () => onOpenWindow(pkt),
    },
  ];

  const onKeyDown = (e) => {
    if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) { e.preventDefault(); openMenuFromKeyboard(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") {
      const pkt = visible.find((p) => p.id === selectedId);
      if (!pkt) return;
      if (e.shiftKey) onOpenWindow(pkt);
      else if (canOpenFlow(pkt)) onOpenFlow(pkt.id);
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

      <div className="packet-scroll" tabIndex={0} onKeyDown={onKeyDown} ref={scrollRef}>
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
                    data-menu={menu?.pkt.id === pkt.id || undefined}
                    onClick={() => onSelect(pkt.id)}
                    // onDoubleClick={() => canOpenFlow(pkt) && onOpenFlow(pkt.id)}
                    onDoubleClick={() => onOpenWindow(pkt)}
                    onContextMenu={(e) => openMenu(e, pkt)}
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
                      {startsSession(pkt) && (
                        <button
                          // Always shown where a session starts; on hover or selection elsewhere
                          className={`btn-flow${startsSession(pkt) ? "" : " is-quiet"}`}
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

      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={menuItems(menu.pkt)}
          onClose={closeMenu}
          label={`Packet ${menu.pkt.id}`}
        />
      )}

      <div className="status-line">
        <span>{visible.length === packets.length ? `${packets.length} packets` : `${visible.length} of ${packets.length} packets`}</span>
        <span><kbd>↑</kbd> <kbd>↓</kbd> select</span>
        <span><kbd>Enter</kbd> call flow</span>
        <span><kbd>/</kbd> filter</span>
      </div>
    </section>
  );
}
