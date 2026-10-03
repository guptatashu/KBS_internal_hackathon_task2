// Chain-Mind front end: entry point.
//
//   landing  ->  scanning (live pipeline over Server-Sent Events)  ->  report (rendered by report.js)
//
// Everything shown here comes from the server's real pipeline events. Nothing is simulated in the browser: a stage
// is drawn as running / done / failed / skipped only because the server said so.
// Scan history is kept in this browser only (localStorage). There is no account and no database.
import { h, svg, mount, isAddress, shortAddr, plural, formatMs, timeAgo, toast, announce } from './dom.js';
import { renderReport } from './report.js';

const BASE_TITLE = 'Chain-Mind: smart contract intelligence';
const HISTORY_KEY = 'chainmind.history.v1';
const PREFS_KEY = 'chainmind.prefs.v1';
const MAX_HISTORY = 20;
const RECENT_ON_LANDING = 5;
const ID_PATTERN = /^[a-f0-9]{6,64}$/;

const STAGES = [
  { id: 'INGEST', desc: 'Validate the address and fetch the verified source from Etherscan.' },
  { id: 'INSPECT', desc: 'Normalise the source files and flag library code.' },
  { id: 'DETECT', desc: 'Run the deterministic pattern scanner and collect evidence.' },
  { id: 'INTERPRET', desc: 'Optional. An AI model explains the code, and its answer is checked against the source.' },
  { id: 'REPORT', desc: 'Assemble the report you are about to read.' },
];

const HINTS = {
  INVALID_ADDRESS: 'Copy the full address from Etherscan. It is 0x followed by 40 hexadecimal characters.',
  NOT_VERIFIED: 'Chain-Mind can only read contracts whose source is verified on Etherscan. Check that this is a contract on Ethereum mainnet and not on another chain.',
  NOT_SOLIDITY: 'Only Solidity source is supported. Vyper and other languages are not.',
  EMPTY_SOURCE: 'Etherscan lists the contract as verified but returned no readable Solidity files, so there is nothing to scan.',
  INVALID_API_KEY: 'The server’s Etherscan key was rejected. Check ETHERSCAN_API_KEY in .env and restart the server.',
  RATE_LIMITED: 'Etherscan is limiting requests. Wait a few seconds and try again.',
  NETWORK_ERROR: 'The server could not reach Etherscan. Check its internet connection and try again.',
  SERVER_BUSY: 'Scans use your API quota, so the server only runs a couple at a time. Try again in a moment.',
  CONNECTION_LOST: 'The connection to the Chain-Mind server dropped before the scan finished. Check that the server is still running, then try again.',
  INTERNAL_ERROR: 'Something unexpected went wrong on the server. Your input was not at fault.',
};

const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH'];

// ---------------------------------------------------------------------------------------------------------------
// state + storage
// ---------------------------------------------------------------------------------------------------------------
const store = {
  read(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw == null ? fallback : JSON.parse(raw);
    } catch { return fallback; }
  },
  write(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
  },
};

const validEntry = (e) => e && typeof e === 'object' && typeof e.id === 'string' && ID_PATTERN.test(e.id) && e.report && typeof e.report === 'object';

function loadHistory() {
  const list = store.read(HISTORY_KEY, []);
  return Array.isArray(list) ? list.filter(validEntry).slice(0, MAX_HISTORY) : [];
}

/** Persist, dropping the oldest entries if the browser's storage quota is hit. Returns what was actually kept. */
function persistHistory(list) {
  const kept = list.slice(0, MAX_HISTORY);
  while (!store.write(HISTORY_KEY, kept) && kept.length) kept.pop();
  return kept;
}

const state = {
  health: null,
  history: loadHistory(),
  prefs: { ai: true, ...(store.read(PREFS_KEY, {}) || {}) },
  active: null,          // the scan in flight, if any
  view: { type: null },  // what is on screen: landing | scan | report
  cleanup: null,         // destroys the current view's observers
  drawerOpen: false,
  returnFocus: null,
};

const $ = (id) => document.getElementById(id);
const els = {
  view: $('view'), drawer: $('drawer'), drawerBody: $('drawer-body'), backdrop: $('backdrop'),
  btnHistory: $('btn-history'), btnNew: $('btn-new'), drawerClose: $('drawer-close'), brand: $('brand'),
};

const savePrefs = () => store.write(PREFS_KEY, state.prefs);
const setLocation = (hash, { replace = false } = {}) => {
  try { history[replace ? 'replaceState' : 'pushState'](null, '', hash); } catch { /* sandboxed or file:// */ }
};

function entryId(report) {
  if (report && typeof report.reportId === 'string' && ID_PATTERN.test(report.reportId)) return report.reportId;
  return Array.from(crypto.getRandomValues(new Uint8Array(5)), (b) => b.toString(16).padStart(2, '0')).join('');
}

const riskOf = (report) => {
  const level = report && report.ai && report.ai.status === 'ok' && report.ai.analysis ? String(report.ai.analysis.riskLevel || '').toUpperCase() : '';
  return RISK_LEVELS.includes(level) ? level : null;
};

// ---------------------------------------------------------------------------------------------------------------
// view switching
// ---------------------------------------------------------------------------------------------------------------
function showView(node, { title = BASE_TITLE, destroy = null, afterMount = null, focus = true, scroll = true } = {}) {
  if (state.cleanup) { try { state.cleanup(); } catch { /* ignore */ } }
  state.cleanup = destroy;
  mount(els.view, node);
  document.title = title;
  if (scroll) window.scrollTo(0, 0);
  if (afterMount) afterMount();
  if (focus) els.view.focus({ preventScroll: true });
}

const isCurrent = (type, id) => state.view.type === type && (id == null || state.view.id === id);

// ---------------------------------------------------------------------------------------------------------------
// shared pieces
// ---------------------------------------------------------------------------------------------------------------
function logo() {
  return svg('svg', { width: 34, height: 34, viewBox: '0 0 32 32', fill: 'none', 'aria-hidden': 'true' },
    svg('rect', { x: 4, y: 11, width: 15, height: 10, rx: 5, stroke: 'currentColor', 'stroke-width': 2 }),
    svg('rect', { x: 13, y: 11, width: 15, height: 10, rx: 5, stroke: 'currentColor', 'stroke-width': 2 }));
}

function glyph(status) {
  const base = { viewBox: '0 0 18 18', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' };
  switch (status) {
    case 'running': return svg('svg', base, svg('circle', { cx: 9, cy: 9, r: 6, opacity: 0.25 }), svg('path', { class: 'spin', d: 'M9 3a6 6 0 0 1 6 6' }));
    case 'done': return svg('svg', base, svg('path', { d: 'M4 9.5l3.2 3.2L14 5.8' }));
    case 'failed': return svg('svg', base, svg('path', { d: 'M5 5l8 8M13 5l-8 8' }));
    case 'skipped': return svg('svg', base, svg('path', { d: 'M5 9h8' }));
    default: return svg('svg', base, svg('circle', { cx: 9, cy: 9, r: 5 }));
  }
}

/** The five-link chain. On the landing page it is a preview; on the scan page it is live. */
function pipelineRail({ live }) {
  const refs = {};
  const rail = h('ol', { class: 'rail', 'aria-label': live ? 'Scan progress' : 'Scan stages' },
    STAGES.map((s) => {
      const glyphEl = h('span', { class: 'glyph' }, glyph('pending'));
      const stateEl = live ? h('p', { class: 'stage-state' }, 'Waiting') : null;
      const detailEl = live ? h('p', { class: 'stage-detail' }) : null;
      const li = h('li', { class: 'stage', 'data-stage': s.id, 'data-status': 'pending' },
        h('div', { class: 'link' }, glyphEl, s.id),
        h('p', { class: 'stage-desc' }, s.desc), stateEl, detailEl);
      refs[s.id] = { li, glyphEl, stateEl, detailEl };
      return li;
    }));
  return { rail, refs };
}

function problemBlock({ title, message, hint, code, actions }) {
  return h('section', { class: 'problem', role: 'alert' },
    h('h2', null, title),
    h('p', { class: 'msg' }, message),
    hint ? h('p', { class: 'hint' }, hint) : null,
    code ? h('p', { class: 'code-id' }, `Error code: ${code}`) : null,
    h('div', { class: 'scan-actions' }, actions));
}

// ---------------------------------------------------------------------------------------------------------------
// history rows (landing + drawer)
// ---------------------------------------------------------------------------------------------------------------
function historyRow(entry) {
  const report = entry.report;
  const level = riskOf(report);
  const name = (report.contract && report.contract.name) || 'Unnamed contract';
  const sub = report.mode === 'demo' ? 'Built-in sample' : (report.address || '');
  return h('div', { class: 'hist-row' },
    h('button', { class: 'hist-open', type: 'button', 'aria-label': `Open report for ${name}`, onclick: () => openEntry(entry.id) },
      h('span', { class: 'badge-risk', 'data-risk': level, 'data-none': level ? null : true }, level || 'Unrated'),
      h('span', { class: 'hist-main' }, h('span', { class: 'name' }, name), h('span', { class: 'sub' }, sub)),
      h('span', { class: 'hist-when' }, timeAgo(report.scannedAt))),
    h('button', { class: 'hist-del', type: 'button', 'aria-label': `Remove ${name} from history`, onclick: () => deleteEntry(entry.id) }, 'Remove'));
}

function openEntry(id) {
  const entry = state.history.find((e) => e.id === id);
  if (!entry) return;
  if (state.drawerOpen) closeDrawer({ restore: false });
  cancelScan();
  setLocation(`#/r/${id}`);
  showSaved(entry);
}

function deleteEntry(id) {
  state.history = persistHistory(state.history.filter((e) => e.id !== id));
  if (state.drawerOpen) renderDrawer();
  if (isCurrent('landing')) refreshLanding();
  toast('Removed from history');
}

// ---------------------------------------------------------------------------------------------------------------
// drawer
// ---------------------------------------------------------------------------------------------------------------
function renderDrawer() {
  if (!state.history.length) {
    mount(els.drawerBody, h('p', { class: 'hist-empty' }, 'No scans yet. Finished reports are kept here, in this browser only.'));
    return;
  }
  mount(els.drawerBody,
    h('div', { class: 'hist-list' }, state.history.map(historyRow)),
    h('p', { class: 'fineprint drawer-note' }, `${plural(state.history.length, 'report')} saved in this browser only. Nothing is stored on the server.`),
    h('button', {
      class: 'btn btn-sm', type: 'button',
      onclick: () => {
        if (!window.confirm('Remove all saved reports from this browser?')) return;
        state.history = persistHistory([]);
        renderDrawer();
        if (isCurrent('landing')) refreshLanding();
        toast('History cleared');
      },
    }, 'Clear all history'));
}

function openDrawer() {
  if (state.drawerOpen) return;
  state.drawerOpen = true;
  state.returnFocus = document.activeElement;
  renderDrawer();
  els.drawer.removeAttribute('inert');
  els.drawer.dataset.open = 'true';
  els.backdrop.hidden = false;
  els.btnHistory.setAttribute('aria-expanded', 'true');
  els.view.inert = true;
  els.drawerClose.focus();
}

function closeDrawer({ restore = true } = {}) {
  if (!state.drawerOpen) return;
  state.drawerOpen = false;
  els.drawer.dataset.open = 'false';
  els.drawer.setAttribute('inert', '');
  els.backdrop.hidden = true;
  els.btnHistory.setAttribute('aria-expanded', 'false');
  els.view.inert = false;
  if (restore && state.returnFocus && state.returnFocus.focus) state.returnFocus.focus();
  state.returnFocus = null;
}

// ---------------------------------------------------------------------------------------------------------------
// landing
// ---------------------------------------------------------------------------------------------------------------
const DEFAULT_HINT = 'Paste a verified Ethereum mainnet contract address.';

function checkAddress(raw) {
  const v = raw.trim();
  if (!v) return { tone: null, text: DEFAULT_HINT };
  if (isAddress(v)) return { tone: 'ok', text: 'Looks like a valid address.' };
  if (v.length >= 2 && !/^0x/i.test(v)) return { tone: 'bad', text: 'An Ethereum address starts with 0x.' };
  if (/[^0-9a-fx]/i.test(v)) return { tone: 'bad', text: 'Addresses only contain the characters 0-9 and a-f after the 0x.' };
  if (v.length > 42) return { tone: 'bad', text: 'That is longer than an address. It should be 0x followed by 40 characters.' };
  return { tone: null, text: `${v.length} of 42 characters` };
}

function landing(prefill = '') {
  const input = h('input', {
    id: 'address', name: 'address', type: 'text', placeholder: '0x… contract address', value: prefill, maxlength: 100,
    autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': 'Ethereum contract address', 'aria-describedby': 'address-hint',
  });
  const hint = h('p', { class: 'field-hint', id: 'address-hint' }, DEFAULT_HINT);
  const field = h('div', { class: 'field' }, input, h('button', { class: 'btn btn-primary', type: 'submit' }, 'Scan contract'));

  const setHint = ({ tone, text }) => {
    hint.textContent = text;
    if (tone) hint.dataset.tone = tone; else hint.removeAttribute('data-tone');
    if (tone === 'bad') field.dataset.state = 'bad'; else field.removeAttribute('data-state');
  };
  if (prefill) setHint(checkAddress(prefill));
  input.addEventListener('input', () => setHint(checkAddress(input.value)));

  const aiInfo = state.health && state.health.ai;
  const aiAvailable = !aiInfo || aiInfo.configured !== false;   // unknown (health unreachable) counts as available
  const aiBox = h('input', { type: 'checkbox', id: 'opt-ai', disabled: !aiAvailable });
  aiBox.checked = aiAvailable && state.prefs.ai !== false;
  aiBox.addEventListener('change', () => { state.prefs.ai = aiBox.checked; savePrefs(); });
  const aiText = aiAvailable
    ? `Sends the contract source to ${aiInfo && aiInfo.provider ? `${aiInfo.provider}${aiInfo.model ? ` (${aiInfo.model})` : ''}` : 'the configured AI provider'} for a plain-language reading. Uses your API quota.`
    : 'Not configured on this server. Set GEMINI_API_KEY or GROQ_API_KEY in .env to turn it on. The scanner works without it.';

  const form = h('form', { class: 'scan-form', novalidate: true, onsubmit: (e) => {
    e.preventDefault();
    const address = input.value.trim();
    if (!isAddress(address)) {
      const found = checkAddress(address);
      setHint(found.tone === 'bad' ? found : { tone: 'bad', text: address ? 'An address is 0x followed by 40 hex characters.' : 'Paste a contract address to scan.' });
      input.focus();
      return;
    }
    startScan({ address, ai: aiBox.checked });
  } },
  field, hint,
  h('div', { class: 'options' },
    h('label', { class: 'opt', 'aria-disabled': aiAvailable ? null : 'true' }, aiBox,
      h('span', null, h('strong', null, 'Include AI analysis'), h('small', null, aiText))),
    h('div', { class: 'opt static' },
      h('span', null,
        h('button', { class: 'linklike', type: 'button', onclick: () => startScan({ demo: true }) }, 'See a demo report'),
        h('small', null, 'A built-in sample contract with a recorded AI answer. Needs no keys and makes no network requests.')))));

  const needsKey = state.health && state.health.etherscanConfigured === false;

  return h('div', { class: 'landing' },
    h('section', { class: 'hero' },
      h('h1', null, 'Know what a contract can do before you use it.'),
      h('p', { class: 'lede' }, 'Paste a verified Ethereum contract address. Chain-Mind reads the Solidity source and shows who controls it, where funds can move, and the exact lines behind every claim.'),
      form,
      needsKey ? h('div', { class: 'callout' },
        h('strong', null, 'Live scans need an Etherscan key'),
        'Set ETHERSCAN_API_KEY in .env and restart the server. The demo report works without it.') : null,
      h('p', { class: 'fineprint hero-note' }, 'An AI-assisted prototype. A first-pass triage, not an audit: the scanner matches text patterns, the AI can be wrong, and a LOW rating never means safe.')),
    h('section', { class: 'pipeline' },
      h('h2', { class: 'pipeline-title' }, 'What happens when you scan'),
      pipelineRail({ live: false }).rail),
    recentSection());
}

function recentSection() {
  if (!state.history.length) return null;
  const shown = state.history.slice(0, RECENT_ON_LANDING);
  return h('section', { class: 'recent' },
    h('h2', null, 'Recent scans'),
    h('div', { class: 'hist-list' }, shown.map(historyRow)),
    state.history.length > shown.length
      ? h('p', { class: 'fineprint' }, h('button', { class: 'linklike', type: 'button', onclick: openDrawer }, `Show all ${state.history.length} saved reports`)) : null);
}

function showLanding({ focusInput = false, prefill = '' } = {}) {
  state.view = { type: 'landing' };
  showView(landing(prefill), { title: BASE_TITLE, focus: !focusInput });
  if (focusInput) $('address')?.focus();
}

/** Re-draw the landing page after history changed, keeping whatever the person had typed. */
function refreshLanding() {
  const typed = $('address') ? $('address').value : '';
  const hadFocus = document.activeElement === $('address');
  showView(landing(typed), { title: BASE_TITLE, focus: false, scroll: false });
  if (hadFocus) $('address')?.focus();
}

// ---------------------------------------------------------------------------------------------------------------
// scanning (live pipeline)
// ---------------------------------------------------------------------------------------------------------------
function stateText(ev) {
  switch (ev.status) {
    case 'running': return 'Running…';
    case 'done': return ev.durationMs != null ? `Done in ${formatMs(ev.durationMs)}` : 'Done';
    case 'failed': return 'Failed';
    case 'skipped': return 'Skipped';
    default: return 'Waiting';
  }
}

function hintFor(error, stage) {
  if (error.code === 'MISSING_API_KEY' && stage === 'INGEST') return 'The server has no Etherscan key. Set ETHERSCAN_API_KEY in .env and restart the server.';
  return HINTS[error.code] || null;
}

function buildScanView({ address, demo, onCancel }) {
  const { rail, refs } = pipelineRail({ live: true });
  const logList = h('ol');
  const log = h('details', { class: 'log', open: true }, h('summary', null, 'Activity log'), logList);
  const title = h('h1', null, demo ? 'Running the demo scan' : 'Scanning contract');
  const cancelBtn = h('button', { class: 'btn', type: 'button', onclick: onCancel }, 'Cancel scan');
  const actions = h('div', { class: 'scan-actions' }, cancelBtn);
  const problemSlot = h('div');

  const el = h('div', { class: 'scan-view' },
    h('section', { class: 'scan-head' },
      title,
      h('p', { class: 'addr' }, demo ? 'Built-in sample contract' : address),
      h('p', null, demo
        ? 'Each stage below runs the real scanner on a built-in sample. The AI answer is a recording, and nothing is fetched from Etherscan.'
        : 'Each stage below reports a real step. Nothing is simulated, so the AI step can take a while on large contracts.'),
      actions),
    h('section', { class: 'pipeline' }, h('h2', { class: 'pipeline-title' }, 'Pipeline'), rail),
    problemSlot, log);

  const addLog = (ev, text) => {
    const when = new Date(typeof ev.t === 'number' ? ev.t : Date.now()).toLocaleTimeString([], { hour12: false });
    logList.append(h('li', null, h('span', { class: 'lt' }, when), h('span', { class: 'ls', 'data-status': ev.status }, ev.status), h('span', null, text)));
    logList.scrollTop = logList.scrollHeight;
  };

  return {
    el, title,
    setStage(ev) {
      const ref = refs[ev.stage];
      if (!ref) return;
      ref.li.dataset.status = ev.status;
      ref.glyphEl.replaceChildren(glyph(ev.status));
      ref.stateEl.textContent = stateText(ev);
      const detail = ev.status === 'failed' && ev.error ? ev.error.message : ev.detail;
      ref.detailEl.textContent = ev.status === 'running' && detail ? `Using ${detail}` : (detail || '');
      addLog(ev, `${ev.stage}${detail ? `: ${detail}` : ''}`);
      if (ev.status !== 'running') announce(`${ev.stage.charAt(0)}${ev.stage.slice(1).toLowerCase()} ${ev.status}`);
    },
    showProblem({ error, stage, onRetry, onNew }) {
      actions.remove();
      title.textContent = 'The scan stopped';
      for (const ref of Object.values(refs)) {
        if (ref.li.dataset.status === 'pending') ref.stateEl.textContent = 'Not run';
      }
      const actionButtons = [
        onRetry ? h('button', { class: 'btn btn-primary', type: 'button', onclick: onRetry }, 'Try again') : null,
        h('button', { class: onRetry ? 'btn' : 'btn btn-primary', type: 'button', onclick: onNew }, 'New scan'),
      ];
      mount(problemSlot, problemBlock({
        title: stage ? `The scan stopped during ${stage.toLowerCase()}` : 'The scan could not run',
        message: error.message || 'The scan failed.',
        hint: hintFor(error, stage), code: error.code, actions: actionButtons,
      }));
      announce(`The scan stopped. ${error.message || ''}`);
      problemSlot.firstChild.scrollIntoView({ block: 'nearest' });
    },
  };
}

function cancelScan() {
  const scan = state.active;
  if (!scan) return;
  scan.finished = true;
  scan.source.close();   // EventSource would otherwise reconnect on its own, and a reconnect starts a new (billable) scan
  state.active = null;
}

function startScan({ address = '', demo = false, ai = true } = {}) {
  cancelScan();
  if (state.drawerOpen) closeDrawer({ restore: false });

  const params = new URLSearchParams();
  if (demo) params.set('demo', '1'); else params.set('address', address);
  if (!ai) params.set('ai', '0');

  const retry = () => startScan({ address, demo, ai });
  const view = buildScanView({ address, demo, onCancel: () => { cancelScan(); newScan(); toast('Scan cancelled'); } });
  state.view = { type: 'scan' };
  setLocation('#/scan', { replace: location.hash === '#/scan' });
  showView(view.el, { title: `${demo ? 'Demo scan' : shortAddr(address)} · Chain-Mind`, focus: true });
  announce('Scan started');

  const scan = { source: new EventSource(`/api/scan/stream?${params}`), finished: false };
  state.active = scan;

  const finish = () => {
    scan.finished = true;
    scan.source.close();
    if (state.active === scan) state.active = null;
  };
  const fail = (error, stage) => view.showProblem({
    error, stage, onRetry: error.retryable ? retry : null, onNew: () => newScan(),
  });
  const parse = (e) => { try { return JSON.parse(e.data); } catch { return null; } };

  scan.source.addEventListener('stage', (e) => {
    const ev = parse(e);
    if (ev && !scan.finished) view.setStage(ev);
  });
  scan.source.addEventListener('report', (e) => {
    const ev = parse(e);
    finish();
    if (!ev || !ev.report || typeof ev.report !== 'object') {
      fail({ code: 'INVALID_RESPONSE', message: 'The server sent a report the browser could not read.', retryable: true });
      return;
    }
    completeScan(ev.report);
  });
  scan.source.addEventListener('fatal', (e) => {
    const ev = parse(e);
    finish();
    fail((ev && ev.error) || { code: 'INTERNAL_ERROR', message: 'The scan failed for an unknown reason.' }, ev && ev.stage);
  });
  scan.source.onerror = () => {
    if (scan.finished) return;
    finish();
    fail({ code: 'CONNECTION_LOST', message: 'The connection to the server was lost before the scan finished.', retryable: true });
  };
}

function completeScan(report) {
  const id = entryId(report);
  state.history = persistHistory([{ id, savedAt: Date.now(), report }, ...state.history.filter((e) => e.id !== id)]);
  setLocation(`#/r/${id}`, { replace: true });
  showReport(report, id);
}

// ---------------------------------------------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------------------------------------------
function reportContext() {
  return {
    health: state.health,
    onNewScan: () => newScan(),
    onRescan: (address, opts = {}) => startScan({ address, ai: opts.ai != null ? opts.ai : state.prefs.ai !== false }),
    onScanAddress: (address) => startScan({ address, ai: state.prefs.ai !== false }),
  };
}

function showReport(report, id) {
  let rendered;
  try {
    rendered = renderReport(report, reportContext());
  } catch (err) {
    console.error('Report failed to render', err);
    state.view = { type: 'report', id };
    showView(problemBlock({
      title: 'This report could not be displayed',
      message: 'The report data is incomplete or in an unexpected shape.',
      hint: 'If it came from your saved history, remove it and run the scan again.',
      actions: [
        h('button', { class: 'btn btn-primary', type: 'button', onclick: () => newScan() }, 'New scan'),
        h('button', { class: 'btn', type: 'button', onclick: () => { deleteEntry(id); newScan(); } }, 'Remove from history'),
      ],
    }), { title: 'Report error · Chain-Mind' });
    return;
  }
  state.view = { type: 'report', id };
  const name = (report.contract && report.contract.name) || 'Unnamed contract';
  showView(rendered.el, { title: `${name} · Chain-Mind`, destroy: rendered.destroy, afterMount: rendered.afterMount });
  const level = riskOf(report);
  announce(`Report ready for ${name}. ${level ? `The AI rated the risk ${level}.` : 'No AI risk rating for this scan.'}`);
}

const showSaved = (entry) => showReport(entry.report, entry.id);

function newScan() {
  cancelScan();
  if (state.drawerOpen) closeDrawer({ restore: false });
  if (location.hash && location.hash !== '#/') setLocation('#/');
  showLanding({ focusInput: true });
}

// ---------------------------------------------------------------------------------------------------------------
// routing: the browser's back/forward buttons and pasted links
// ---------------------------------------------------------------------------------------------------------------
function route() {
  const hash = location.hash;
  const match = /^#\/r\/([a-f0-9]{6,64})$/.exec(hash);
  if (match) {
    const entry = state.history.find((e) => e.id === match[1]);
    if (entry) {
      if (isCurrent('report', entry.id)) return;
      cancelScan();
      showSaved(entry);
      return;
    }
    toast('That report is not in this browser’s history.');
  } else if (hash === '#/scan' && state.active) {
    return;
  }
  if (hash && hash !== '#/') setLocation('#/', { replace: true });
  if (isCurrent('landing')) return;
  cancelScan();
  showLanding();
}

// ---------------------------------------------------------------------------------------------------------------
// start-up
// ---------------------------------------------------------------------------------------------------------------
async function loadHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const res = await fetch('/api/health', { signal: controller.signal });
    return res.ok ? await res.json() : null;
  } catch { return null; } finally { clearTimeout(timer); }
}

async function init() {
  mount(els.brand, logo(), h('span', { class: 'brand-name' }, 'Chain-Mind'), h('span', { class: 'brand-sub' }, 'Smart contract intelligence'));
  els.brand.addEventListener('click', (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    newScan();
  });
  els.btnNew.addEventListener('click', () => newScan());
  els.btnHistory.addEventListener('click', () => (state.drawerOpen ? closeDrawer() : openDrawer()));
  els.drawerClose.addEventListener('click', () => closeDrawer());
  els.backdrop.addEventListener('click', () => closeDrawer());
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && state.drawerOpen) closeDrawer(); });
  window.addEventListener('hashchange', route);
  window.addEventListener('popstate', route);
  window.addEventListener('pagehide', cancelScan);

  state.health = await loadHealth();
  route();
}

init();
