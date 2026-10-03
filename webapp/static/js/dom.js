// Small DOM helpers shared by app.js, report.js and highlight.js.
//
// Security rule for the whole UI: contract source, function names, model output and error text are untrusted.
// Nothing here ever parses a string as markup. Strings become text nodes, and attributes are set with setAttribute, so
// untrusted text cannot become markup. (The server's CSP also forbids inline script and inline style attributes,
// so styling goes through classes, data-* attributes and CSS custom properties set via the CSSOM.)

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Append children of any shape: nested arrays, strings, numbers, Nodes. null/undefined/false are skipped. */
function append(parent, children) {
  for (const child of children) {
    if (child == null || child === false || child === true) continue;
    if (Array.isArray(child)) append(parent, child);
    else if (child instanceof Node) parent.append(child);
    else parent.append(document.createTextNode(String(child)));
  }
}

function applyAttrs(el, attrs) {
  if (!attrs) return;
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'class') el.setAttribute('class', String(value));
    else if (key === 'vars') {
      // CSS custom properties, e.g. { vars: { flex: '3' } } sets --flex: 3 (allowed by CSP, unlike style="").
      for (const [name, v] of Object.entries(value)) el.style.setProperty(`--${name}`, String(v));
    } else if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) el.setAttribute(key, '');
    else el.setAttribute(key, String(value));
  }
}

/** h('div', { class: 'x', onclick }, child, [children], 'text') -> HTMLElement */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  applyAttrs(el, attrs);
  append(el, children);
  return el;
}

/** Same as h() for SVG elements. */
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyAttrs(el, attrs);
  append(el, children);
  return el;
}

/** Replace everything inside `parent` with `children`. */
export function mount(parent, ...children) {
  parent.replaceChildren();
  append(parent, children);
  return parent;
}

// ---------------------------------------------------------------------------------------------------------------
// addresses and formatting
// ---------------------------------------------------------------------------------------------------------------
const ADDRESS = /^0x[a-fA-F0-9]{40}$/;

export const isAddress = (value) => typeof value === 'string' && ADDRESS.test(value);

export const shortAddr = (addr) => (isAddress(addr) ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : String(addr || ''));

/** Only ever links to a string that passed the strict address check, so the href cannot be anything else. */
export const etherscanUrl = (addr) => (isAddress(addr) ? `https://etherscan.io/address/${addr}` : null);

export const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** 340 -> "340 ms", 1450 -> "1.5 s", 72000 -> "1 min 12 s" */
export function formatMs(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s`;
}

const RELATIVE = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60]];

/** "3 hours ago" for an ISO timestamp or epoch ms. Falls back to an empty string for bad input. */
export function timeAgo(value) {
  const t = typeof value === 'number' ? value : Date.parse(value);
  if (!Number.isFinite(t)) return '';
  const seconds = Math.round((Date.now() - t) / 1000);
  if (seconds < 45) return 'just now';
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, size] of RELATIVE) {
    if (seconds >= size) return fmt.format(-Math.floor(seconds / size), unit);
  }
  return fmt.format(-Math.max(1, Math.round(seconds / 60)), 'minute');
}

// ---------------------------------------------------------------------------------------------------------------
// feedback: toast, screen-reader announcements, clipboard
// ---------------------------------------------------------------------------------------------------------------
let toastTimer = 0;

export function toast(message, ms = 2200) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.dataset.show = 'true';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.dataset.show = 'false'; }, ms);
}

/** Politely announce a status change to screen readers (the #live region in index.html). */
export function announce(message) {
  const el = document.getElementById('live');
  if (!el) return;
  el.textContent = '';
  // A change of text content is what triggers the announcement; the empty write above makes repeats register.
  setTimeout(() => { el.textContent = message; }, 30);
}

export async function copyText(text, message = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard API unavailable (non-secure context, denied permission): fall back to a temporary textarea.
    const area = h('textarea', { 'aria-hidden': 'true', readonly: true, tabindex: '-1' });
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    area.remove();
    if (!ok) { toast('Could not copy. Select the text and copy it manually.'); return false; }
  }
  toast(message);
  return true;
}
