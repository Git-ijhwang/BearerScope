// Where each IE sits inside the raw message, so hovering an IE can highlight
// its bytes in the dump. IEs follow the header back to back; a grouped IE's
// children start after its own 4-byte IE header.

function indexOf(haystack, needle, from = 0) {
  outer: for (let i = from; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

const sameAt = (raw, bytes, at) => bytes.every((b, j) => raw[at + j] === b);

/** Map from each IE's `raw` array (by identity) to its start offset in `raw`. */
export function ieOffsets(raw, ies, headerLen) {
  const map = new Map();
  const walk = (list, start) => {
    let at = start;
    (list || []).forEach((ie) => {
      if (!ie.raw) return;
      // Trust the sequential position, fall back to searching if it doesn't line up
      const pos = sameAt(raw, ie.raw, at) ? at : indexOf(raw, ie.raw);
      if (pos >= 0) {
        map.set(ie.raw, pos);
        walk(ie.ie_value?.SubIeList, pos + 4);
        at = pos + ie.raw.length;
      }
    });
  };
  walk(ies, headerLen);
  return map;
}
