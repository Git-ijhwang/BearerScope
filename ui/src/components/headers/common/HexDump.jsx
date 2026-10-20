import { useEffect, useRef, useState } from "react";

const toHex = (n) => n.toString(16).padStart(2, "0").toUpperCase();
const toAscii = (n) => (n >= 0x20 && n <= 0x7e ? String.fromCharCode(n) : ".");

// Characters in one line: offset(4) + 2 + hex + 2 + ascii
const lineChars = (n) => 4 + 2 + (n * 3 - 1 + (n > 8 ? 1 : 0)) + 2 + n;

/**
 * Hex + ASCII dump.
 *
 * - Fits the width it is given: 16 bytes per line when there is room,
 *   otherwise 8 (or 4), so it never runs past its box.
 * - `highlight` ({ start, length }) marks a byte range, e.g. the IE under the mouse.
 *   Pass `null` (not undefined) to show the caption line with a hint instead.
 */
export default function HexDump({ raw, highlight }) {
  const ref = useRef(null);
  const [perLine, setPerLine] = useState(16);

  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const ro = new ResizeObserver(([entry]) => {
      const charW = parseFloat(getComputedStyle(el).fontSize) * 0.6; // monospace advance
      const room = entry.contentRect.width / charW;
      setPerLine(room >= lineChars(16) ? 16 : room >= lineChars(8) ? 8 : 4);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Scroll the highlighted bytes into view inside the dump
  useEffect(() => {
    ref.current?.querySelector(".hl")?.scrollIntoView({ block: "nearest" });
  }, [highlight?.start, highlight?.length]);

  if (!raw || raw.length === 0) return <div className="hexdump-empty">No raw data</div>;

  const inHl = (i) => highlight && i >= highlight.start && i < highlight.start + highlight.length;
  const rows = [];
  for (let base = 0; base < raw.length; base += perLine) {
    const hex = [];
    const ascii = [];
    for (let j = 0; j < perLine; j += 1) {
      const i = base + j;
      const gap = j === 0 ? "" : perLine > 8 && j === 8 ? "  " : " ";
      if (i < raw.length) {
        const cls = inHl(i) ? "hl" : undefined;
        // the space before a byte is part of the highlight only inside the range
        hex.push(gap && inHl(i) && inHl(i - 1) ? <span key={`g${j}`} className="hl">{gap}</span> : gap);
        hex.push(<span key={j} className={cls}>{toHex(raw[i])}</span>);
        ascii.push(<span key={j} className={cls}>{toAscii(raw[i])}</span>);
      } else {
        hex.push(gap + "  ");
      }
    }
    rows.push(
      <div key={base}>
        <span className="off">{base.toString(16).padStart(4, "0")}</span>{"  "}{hex}{"  "}{ascii}
      </div>
    );
  }

  return (
    <div className="hexdump" ref={ref} role="region" aria-label="Raw bytes">
      {highlight !== undefined && (
        <div className={`hexdump-caption ${highlight ? "" : "is-hint"}`}>
          {highlight
            ? `Bytes ${highlight.start}–${highlight.start + highlight.length - 1} (${highlight.length} bytes)`
            : `${raw.length} bytes · point at an IE to find its bytes`}
        </div>
      )}
      <pre>{rows}</pre>
    </div>
  );
}
