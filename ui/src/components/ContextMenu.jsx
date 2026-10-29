import { useEffect, useLayoutEffect, useRef, useState } from "react";

/**
 * A right-click menu at (x, y), in viewport pixels.
 *
 * items: [{ id, label, shortcut?, hint?, disabled?, onSelect }] or "separator".
 * Closes on Escape, a click or right-click elsewhere, the mouse wheel, resizing
 * or leaving the window. (Not on "scroll": selecting the right-clicked row
 * scrolls it into view, which would close the menu as it opens.)
 * Arrow keys move between items, Enter picks one.
 */
export default function ContextMenu({ x, y, items, onClose, label = "Actions" }) {
  const ref = useRef(null);
  const [pos, setPos] = useState({ left: x, top: y });
  const enabled = items.filter((it) => it !== "separator" && !it.disabled);
  const [active, setActive] = useState(enabled[0]?.id ?? null);

  // Keep the whole menu inside the window
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const { width, height } = el.getBoundingClientRect();
    const pad = 6;
    setPos({
      left: Math.max(pad, Math.min(x, window.innerWidth - width - pad)),
      top: Math.max(pad, Math.min(y, window.innerHeight - height - pad)),
    });
  }, [x, y]);

  useEffect(() => {
    ref.current?.focus();
    const outside = (e) => { if (!ref.current?.contains(e.target)) onClose(); };
    const close = () => onClose();
    document.addEventListener("mousedown", outside, true);
    document.addEventListener("contextmenu", outside, true);
    window.addEventListener("wheel", close, { capture: true, passive: true });
    window.addEventListener("resize", close);
    window.addEventListener("blur", close);
    return () => {
      document.removeEventListener("mousedown", outside, true);
      document.removeEventListener("contextmenu", outside, true);
      window.removeEventListener("wheel", close, { capture: true });
      window.removeEventListener("resize", close);
      window.removeEventListener("blur", close);
    };
  }, [onClose]);

  const pick = (it) => {
    if (!it || it.disabled) return;
    onClose();
    it.onSelect();
  };

  const onKeyDown = (e) => {
    const i = enabled.findIndex((it) => it.id === active);
    if (e.key === "Escape") { e.preventDefault(); onClose(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); setActive(enabled[(i + 1) % enabled.length]?.id); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive(enabled[(i - 1 + enabled.length) % enabled.length]?.id); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(enabled[i]); }
    else if (e.key === "Tab") { e.preventDefault(); }
  };

  return (
    <div
      ref={ref}
      className="ctx-menu"
      role="menu"
      aria-label={label}
      tabIndex={-1}
      style={{ left: pos.left, top: pos.top }}
      onKeyDown={onKeyDown}
      onContextMenu={(e) => e.preventDefault()}
    >
      {items.map((it, i) => it === "separator" ? (
        <div key={`sep${i}`} className="ctx-sep" role="separator" />
      ) : (
        <div
          key={it.id}
          role="menuitem"
          aria-disabled={it.disabled || undefined}
          className={`ctx-item${it.id === active ? " is-active" : ""}`}
          onMouseEnter={() => !it.disabled && setActive(it.id)}
          onClick={() => pick(it)}
        >
          <span className="ctx-label">
            {it.label}
            {it.hint && <span className="ctx-hint">{it.hint}</span>}
          </span>
          {it.shortcut && <kbd className="ctx-key">{it.shortcut}</kbd>}
        </div>
      ))}
    </div>
  );
}
