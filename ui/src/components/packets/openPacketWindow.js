import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { splitDescription } from "./packetFormat";

const fileName = (p) => p?.split(/[\\/]/).pop();

/** Short stable id for a capture path, so window labels differ per file */
function pathKey(path) {
  let h = 0;
  for (const c of path) h = (Math.imul(h, 31) + c.charCodeAt(0)) >>> 0;
  return h.toString(36);
}

/**
 * Open one packet in its own window (like Wireshark's "Open in new window").
 * Opening the same packet again brings its window to the front.
 */
export async function openPacketWindow(path, pkt) {
  const label = `packet-${pathKey(path)}-${pkt.id}`;
  const existing = await WebviewWindow.getByLabel(label);
  if (existing) {
    await existing.setFocus();
    return;
  }

  const params = new URLSearchParams({
    view: "packet",
    path,
    id: String(pkt.id),
    summary: JSON.stringify(pkt),
  });
  const { text } = splitDescription(pkt.description);

  await new Promise((resolve, reject) => {
    const win = new WebviewWindow(label, {
      url: `index.html?${params}`,
      title: `Packet ${pkt.id}${text ? ` · ${text}` : ""} — ${fileName(path)}`,
      width: 980,
      height: 820,
      minWidth: 560,
      minHeight: 420,
    });
    win.once("tauri://created", () => resolve());
    win.once("tauri://error", (e) => reject(e.payload ?? e));
  });
}