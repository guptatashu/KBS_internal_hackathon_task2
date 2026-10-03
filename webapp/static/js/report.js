// Renders a report object (see webapp/pipeline.py: build_report) into the DOM.
// Everything in the report derives from untrusted contract text or model output, so it is only ever rendered as text.
import { h, svg, isAddress, shortAddr, etherscanUrl, plural, copyText, toast } from './dom.js';
import { codeBlock } from './highlight.js';

const SEV_ORDER = { high: 3, medium: 2, low: 1, info: 0 };
const RISK_ROT = { LOW: 29, MEDIUM: 90, HIGH: 151 };   // needle angle (degrees clockwise from pointing left)
const ACCESS = {
  'none-detected': ['No restriction detected', 'high'],
  modifier: ['Role-restricted', 'medium'],
  'inline-check': ['Caller checked', 'medium'],
  'caller-scoped': ["Caller's own funds", 'low'],
};
const RISK_NOTE = {
  LOW: 'Few privileged or dangerous patterns were identified in the code that was analysed.',
  MEDIUM: 'There are powers or patterns here worth understanding before you rely on this contract.',
  HIGH: 'Significant risk signals are present. Read the evidence before you interact with this contract.',
};
const SECTIONS = [
  ['overview', 'Overview'], ['risk', 'Risk'], ['signals', 'Security signals'], ['permissions', 'Permissions'],
  ['funds', 'Fund movement'], ['functions', 'Key functions'], ['assessment', 'AI assessment'],
];

const sev = (s) => (SEV_ORDER[s] != null ? s : 'info');
const upper = (s) => String(s || '').toUpperCase();
const arr = (v) => (Array.isArray(v) ? v : []);
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---------------------------------------------------------------------------------------------------------------
export function renderReport(report, ctx) {
  const analysis = report.ai && report.ai.status === 'ok' ? report.ai.analysis : null;
  const scan = report.scan || { findings: [], summary: { bySeverity: {} } };
  const view = { report, analysis, scan, ai: report.ai || {}, contract: report.contract || {}, ctx };

  const root = h('div', { class: 'report' },
    report.mode === 'demo' ? h('p', { class: 'demo-banner' },
      'Demo report: a built-in sample contract with a recorded AI answer. Nothing was fetched from Etherscan, and the AI step used no live model.') : null,
    header(view),
    tabs(),
    safe('overview', 'Overview', overview, view),
    safe('risk', 'Risk', risk, view),
    safe('signals', 'Security signals', signals, view),
    safe('permissions', 'Permissions', permissions, view),
    safe('funds', 'Fund movement', funds, view),
    safe('functions', 'Key functions', functions, view),
    safe('assessment', 'AI assessment', assessment, view),
    footer(view));

  const spy = scrollSpy(root);
  return { el: root, destroy: () => spy.disconnect(), afterMount: () => animateNeedle(root) };
}

/** One broken section must not take the whole report down. */
function safe(id, title, build, view) {
  try { return build(view); } catch (err) {
    console.error(`Section "${id}" failed to render`, err);
    return section(id, title, '', h('div', { class: 'empty' }, 'This section could not be displayed.'));
  }
}

function section(id, title, note, ...body) {
  return h('section', { class: 'sec', id: `sec-${id}`, 'aria-labelledby': `h-${id}` },
    h('div', { class: 'sec-head' }, h('h2', { id: `h-${id}` }, title), note ? h('p', null, note) : null),
    h('div', { class: 'sec-body' }, ...body));
}

const empty = (strong, text, ...extra) => h('div', { class: 'empty' }, h('strong', null, strong), text ? ` ${text}` : '', ...extra);

// ---------------------------------------------------------------------------------------------------------------
// header + tabs + footer
// ---------------------------------------------------------------------------------------------------------------
function header({ report, contract, ctx }) {
  const addr = report.address;
  const url = etherscanUrl(addr);
  return h('header', { class: 'rhead' },
    h('div', null,
      h('div', { class: 'kicker' }, 'Smart contract report'),
      h('h1', null, contract.name || 'Unnamed contract'),
      h('div', { class: 'addr-row' },
        addr ? h('span', { class: 'addr' }, addr) : h('span', { class: 'addr' }, 'Built-in sample'),
        addr ? h('button', { class: 'btn btn-sm', type: 'button', onclick: () => copyText(addr, 'Address copied') }, 'Copy') : null,
        url ? h('a', { class: 'btn btn-sm', href: url, target: '_blank', rel: 'noopener noreferrer' }, 'Open on Etherscan') : null),
      h('div', { class: 'badges' },
        h('span', { class: 'chip' }, (report.chain && report.chain.name) || 'Ethereum mainnet'),
        report.mode === 'live' ? h('span', { class: 'chip', 'data-tone': 'accent' }, 'Source verified on Etherscan') : null,
        contract.isProxy ? h('span', { class: 'chip', 'data-tone': 'warn' }, 'Proxy contract') : null,
        report.mode === 'demo' ? h('span', { class: 'chip', 'data-tone': 'warn' }, 'Demo') : null,
        h('span', { class: 'chip mono', title: 'Report ID' }, report.reportId || ''),
        h('span', { class: 'chip' }, report.scannedAt ? new Date(report.scannedAt).toLocaleString() : ''))),
    h('div', { class: 'rhead-actions' },
      h('button', { class: 'btn', type: 'button', onclick: () => exportJson(report) }, 'Export JSON'),
      addr ? h('button', { class: 'btn', type: 'button', onclick: () => ctx.onRescan(addr) }, 'Scan again') : null,
      h('button', { class: 'btn btn-primary', type: 'button', onclick: ctx.onNewScan }, 'New scan')));
}

function exportJson(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: `chain-mind-${report.reportId || 'report'}.json` });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  toast('Report exported');
}

function tabs() {
  return h('nav', { class: 'tabs', 'aria-label': 'Report sections' }, h('ul', null, SECTIONS.map(([id, label]) =>
    h('li', null, h('a', {
      href: `#sec-${id}`, 'data-sec': id,
      onclick: (e) => {
        e.preventDefault();
        document.getElementById(`sec-${id}`)?.scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth', block: 'start' });
      },
    }, label)))));
}

function scrollSpy(root) {
  const links = new Map([...root.querySelectorAll('.tabs a')].map((a) => [a.dataset.sec, a]));
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      links.forEach((a) => a.removeAttribute('aria-current'));
      links.get(e.target.id.replace('sec-', ''))?.setAttribute('aria-current', 'true');
    }
  }, { rootMargin: '-25% 0px -65% 0px' });
  root.querySelectorAll('.sec').forEach((s) => io.observe(s));
  return io;
}

function footer({ ai, scan }) {
  const meta = ai.meta || {};
  return h('footer', { class: 'foot' },
    h('p', { class: 'fineprint' }, scan.disclaimer || ''),
    meta.disclaimer ? h('p', { class: 'fineprint' }, meta.disclaimer) : null);
}

// ---------------------------------------------------------------------------------------------------------------
// 1. Overview
// ---------------------------------------------------------------------------------------------------------------
function noAiBlock(view, what) {
  const { ai, report, ctx } = view;
  const reasons = {
    skipped: ai.reason || 'AI analysis was turned off for this scan.',
    unavailable: ai.reason || 'AI analysis is not configured on the server.',
    failed: (ai.error && ai.error.message) || 'The AI analysis failed.',
  };
  const canRetry = report.address && ctx.health && ctx.health.ai && ctx.health.ai.configured && ai.status !== 'unavailable';
  return empty(`${what} needs the AI analysis.`, reasons[ai.status] || '',
    canRetry ? h('div', null, h('button', { class: 'btn btn-sm', type: 'button', onclick: () => ctx.onRescan(report.address, { ai: true }) }, 'Scan again with AI analysis')) : null);
}

function overview(view) {
  const { analysis, contract, ctx } = view;
  const files = arr(contract.files);
  const dl = [
    ['Compiler', contract.compilerVersion],
    ['Optimizer', contract.optimizationUsed ? `Enabled${contract.runs ? `, ${contract.runs} runs` : ''}` : 'Disabled'],
    ['EVM version', contract.evmVersion],
    ['License', contract.licenseType],
    ['Source', `${contract.sourceFormat || 'unknown'}, ${plural(files.length, 'file')}`],
  ].filter(([, v]) => v);

  return section('overview', 'Overview', 'What this contract is and where its code comes from.',
    h('div', { class: 'ov-grid' },
      h('div', null,
        analysis ? [h('p', { class: 'purpose' }, analysis.contractPurpose), h('p', { class: 'purpose-src' }, h('span', { class: 'tag', 'data-kind': 'ai' }, 'Interpreted by AI'))]
          : noAiBlock(view, 'The contract’s purpose')),
      h('div', null,
        h('dl', { class: 'dl' }, dl.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
        files.length ? h('details', { class: 'files' }, h('summary', null, `Show ${plural(files.length, 'source file')}`),
          h('ul', null, files.map((f) => h('li', null, h('span', null, f.path, f.isDependency ? ' (library)' : ''), h('span', null, `${f.lines} lines`))))) : null)),
    contract.isProxy ? h('div', { class: 'callout' },
      h('strong', null, 'This address is a proxy'),
      'The code analysed here belongs to the proxy. The contract’s real logic usually lives at the implementation address, so the findings below may not describe what it actually does.',
      contract.implementationAddress ? h('div', { class: 'addr-row' }, h('span', { class: 'addr' }, contract.implementationAddress)) : null,
      contract.implementationAddress ? h('button', { class: 'btn btn-sm', type: 'button', onclick: () => ctx.onScanAddress(contract.implementationAddress) }, 'Scan the implementation') : null) : null);
}

// ---------------------------------------------------------------------------------------------------------------
// 2. Risk overview
// ---------------------------------------------------------------------------------------------------------------
function arc(cx, cy, r, a0, a1) {
  const pt = (a) => [cx + r * Math.cos((a * Math.PI) / 180), cy - r * Math.sin((a * Math.PI) / 180)];
  const [x0, y0] = pt(a0);
  const [x1, y1] = pt(a1);
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 0 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

function gauge(level) {
  const segs = [['LOW', 180, 122], ['MEDIUM', 118, 62], ['HIGH', 58, 0]];
  return svg('svg', { viewBox: '0 0 240 134', role: 'img', 'aria-label': level ? `Risk gauge: ${level}` : 'Risk gauge: not assessed' },
    ...segs.map(([lvl, a0, a1]) => svg('path', { class: 'seg', d: arc(120, 120, 96, a0, a1), 'data-lvl': lvl, 'data-on': String(lvl === level) })),
    level ? svg('g', { class: 'needle', 'data-rot': RISK_ROT[level] }, svg('line', { x1: 120, y1: 120, x2: 46, y2: 120 }), svg('circle', { cx: 120, cy: 120, r: 6 })) : null);
}

function animateNeedle(root) {
  const n = root.querySelector('.needle');
  if (!n) return;
  const set = () => n.style.setProperty('--rot', `${n.dataset.rot}deg`);
  reduceMotion() ? set() : requestAnimationFrame(() => requestAnimationFrame(set));   // the one orchestrated moment
}

function risk(view) {
  const { analysis, scan, ai, contract } = view;
  const level = analysis ? upper(analysis.riskLevel) : null;
  const counts = (scan.summary && scan.summary.bySeverity) || {};
  const total = ['high', 'medium', 'low', 'info'].reduce((n, k) => n + (counts[k] || 0), 0);
  const topSignal = ['high', 'medium', 'low', 'info'].find((k) => counts[k]);
  const meta = ai.meta || {};

  let reasoning;
  if (analysis) {
    const long = analysis.riskReasoning.length > 330;
    const p = h('p', { class: 'reasoning', 'data-clamped': String(long) }, analysis.riskReasoning);
    reasoning = [p, long ? h('button', { class: 'linklike', type: 'button', onclick: (e) => {
      const clamped = p.dataset.clamped === 'true';
      p.dataset.clamped = String(!clamped);
      e.target.textContent = clamped ? 'Show less' : 'Read more';
    } }, 'Read more') : null,
    h('p', { class: 'risk-note' }, `${RISK_NOTE[level] || ''} The level is the AI model’s reading of the code and the scanner signals. LOW does not mean safe.`)];
  } else {
    reasoning = [h('p', { class: 'reasoning' }, 'No risk level was produced for this scan, because it comes from the AI analysis.'),
      h('p', { class: 'risk-note' }, topSignal ? `The pattern scanner’s highest signal was ${topSignal.toUpperCase()}. A scanner signal is a place to look, not a verdict.` : 'The pattern scanner found no signals. That is not evidence of safety.')];
  }

  const legend = [['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']].filter(([k]) => counts[k]);
  const files = arr(contract.files).length;

  return section('risk', 'Risk overview', 'How risky the contract looks, and what that rating rests on.',
    h('div', { class: 'risk', 'data-risk': level || null },
      h('div', { class: 'gauge' }, gauge(level),
        level ? h('div', { class: 'risk-word' }, level) : h('div', { class: 'risk-word', 'data-none': true }, 'Not assessed'),
        h('div', { class: 'risk-label' }, 'Risk level')),
      h('div', { class: 'risk-right' },
        h('h3', null, 'Why this rating'),
        reasoning,
        h('div', { class: 'sigbar' },
          h('h3', null, 'Scanner signals'),
          total ? h('div', { class: 'sigbar-track', role: 'img', 'aria-label': `${total} scanner signals` },
            legend.map(([k]) => h('span', { 'data-sev': k, vars: { flex: String(counts[k]) } }))) : h('p', { class: 'fineprint' }, 'No scanner rules triggered.'),
          total ? h('div', { class: 'sigbar-legend' }, legend.map(([k, label]) => h('span', { 'data-sev': k }, h('i'), `${counts[k]} ${label}`))) : null),
        h('div', { class: 'basis' }, h('h3', null, 'What this rests on'),
          h('div', { class: 'chain' },
            chainLink('Verified source', view.report.mode === 'demo' ? 'Built-in sample' : `Etherscan, ${plural(files, 'file')}`, true),
            chainLink('Pattern scan', `${arr(scan.rules).length} rules, ${plural(total, 'signal')}`, true),
            chainLink('AI interpretation', analysis ? `${meta.provider || 'model'}${meta.model ? `, ${meta.model}` : ''}` : 'Not run', Boolean(analysis)))))));
}

const chainLink = (title, sub, on) => h('div', { class: 'chain-link', 'data-state': on ? 'on' : 'off' }, h('b', null, title), h('span', null, sub));

// ---------------------------------------------------------------------------------------------------------------
// 3. Security signals
// ---------------------------------------------------------------------------------------------------------------
function evidenceBlock(ev, severity) {
  const lines = arr(ev.context);
  const bits = [];
  if (lines.length) bits.push(codeBlock({ file: ev.file, lines, severity }));
  else bits.push(h('div', { class: 'chip chip-fn' }, `${ev.file}:${ev.line}`));
  return bits;
}

function accessChip(code) {
  const [label, s] = ACCESS[code] || [null, null];
  return label ? h('span', { class: 'access', 'data-sev': s }, label) : null;
}

function scannerCard(f, aiRules) {
  const evs = arr(f.evidence);
  const list = h('div', { class: 'ev' });
  const show = (n) => {
    list.replaceChildren(...evs.slice(0, n).map((e) => h('div', null, evidenceBlock(e, sev(e.severity)), e.detail ? h('p', { class: 'ev-note' }, e.detail) : null)));
  };
  show(2);
  const hidden = Math.max(0, f.count - 2);
  const moreBtn = evs.length > 2 ? h('button', { class: 'btn btn-sm more', type: 'button', onclick: (e) => {
    const open = e.target.dataset.open === '1';
    show(open ? 2 : evs.length);
    e.target.dataset.open = open ? '0' : '1';
    e.target.textContent = open ? `Show ${evs.length - 2} more locations` : 'Show fewer';
  } }, `Show ${evs.length - 2} more locations`) : null;

  return h('article', { class: 'finding', 'data-sev': sev(f.severity), 'data-kind': 'scanner', id: `rule-${f.rule}` },
    h('div', { class: 'finding-head' },
      h('span', { class: 'pill' }, upper(f.severity)),
      h('h3', null, f.title),
      h('span', { class: 'tag', 'data-kind': 'scanner' }, 'Scanner signal'),
      h('span', { class: 'tag' }, plural(f.count, 'location'))),
    h('p', null, f.description),
    list, moreBtn,
    f.count > evs.length ? h('p', { class: 'ev-note' }, `${f.count - evs.length} more ${f.count - evs.length === 1 ? 'location is' : 'locations are'} not shown.`) : null,
    h('details', null, h('summary', null, 'Why this is only a signal'), h('p', null, f.whyOnlySignal)),
    aiRules.has(f.rule) ? h('div', { class: 'xref' }, h('span', { class: 'tag', 'data-kind': 'ai' }, 'Discussed in the AI analysis')) : null);
}

function aiCard(f) {
  return h('article', { class: 'finding', 'data-sev': sev(String(f.severity).toLowerCase()), 'data-kind': 'ai' },
    h('div', { class: 'finding-head' },
      h('span', { class: 'pill' }, upper(f.severity)),
      h('h3', null, f.title),
      h('span', { class: 'tag', 'data-kind': 'ai' }, 'AI analysis'),
      h('span', { class: 'tag' }, `Confidence ${String(f.confidence || '').toLowerCase()}`)),
    h('div', { class: 'pair' },
      h('div', null, h('h4', null, 'Observed in the code'), h('p', null, f.observed)),
      h('div', null, h('h4', null, 'Potential risk, depends on circumstances'), h('p', null, f.potentialRisk))),
    arr(f.evidence).length ? h('div', { class: 'ev' }, arr(f.evidence).map((e) => h('div', null, evidenceBlock(e, sev(String(f.severity).toLowerCase()))))) : null,
    f.scannerRule ? h('div', { class: 'xref' }, h('a', { class: 'tag', 'data-kind': 'scanner', href: `#rule-${f.scannerRule}`, onclick: (e) => {
      const target = document.getElementById(`rule-${f.scannerRule}`);
      if (target) { e.preventDefault(); target.scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth', block: 'center' }); }
    } }, `Also flagged by the scanner: ${f.scannerRule}`)) : null);
}

function signals(view) {
  const { scan, analysis } = view;
  const sFindings = arr(scan.findings);
  const aFindings = analysis ? arr(analysis.securityFindings) : [];
  const aiRules = new Set(aFindings.map((f) => f.scannerRule).filter(Boolean));
  const all = [
    ...sFindings.map((f) => ({ src: 'scanner', sev: sev(f.severity), node: () => scannerCard(f, aiRules) })),
    ...aFindings.map((f) => ({ src: 'ai', sev: sev(String(f.severity).toLowerCase()), node: () => aiCard(f) })),
  ].sort((a, b) => SEV_ORDER[b.sev] - SEV_ORDER[a.sev] || (a.src === 'scanner' ? -1 : 1));

  const list = h('div', { class: 'findings' });
  let filter = 'all';
  const draw = () => {
    const rows = all.filter((x) => filter === 'all' || x.src === filter);
    list.replaceChildren(...(rows.length ? rows.map((x) => x.node()) : [empty('Nothing here.', filter === 'ai' ? (analysis ? 'The AI analysis reported no findings.' : 'The AI analysis did not run.') : 'No scanner rules were triggered.')]));
  };
  const counts = { all: all.length, scanner: sFindings.length, ai: aFindings.length };
  const buttons = [['all', 'All'], ['scanner', 'Scanner'], ['ai', 'AI']].map(([key, label]) =>
    h('button', { type: 'button', 'aria-pressed': String(key === filter), onclick: () => {
      filter = key;
      buttons.forEach((b, i) => b.setAttribute('aria-pressed', String(['all', 'scanner', 'ai'][i] === key)));
      draw();
    } }, `${label} ${counts[key]}`));
  draw();

  const notTriggered = arr(scan.summary && scan.summary.rulesNotTriggered);
  return section('signals', 'Security signals', 'Patterns the scanner matched and risks the AI found. A signal is a place to look, not a confirmed vulnerability.',
    h('div', null, h('div', { class: 'filters', role: 'group', 'aria-label': 'Filter findings' }, buttons), list),
    h('details', { class: 'check' }, h('summary', null, `How the scanner worked (${arr(scan.rules).length} rules)`),
      h('div', null,
        notTriggered.length ? h('p', { class: 'fineprint' }, 'Rules that matched nothing: ', notTriggered.join(', '), '. That is not evidence of safety.') : null,
        h('ul', { class: 'plain-list' }, arr(scan.limitations).map((l) => h('li', null, l))))));
}

// ---------------------------------------------------------------------------------------------------------------
// 4. Permissions
// ---------------------------------------------------------------------------------------------------------------
function ruleEvidence(scan, rules) {
  return arr(scan.findings).filter((f) => rules.includes(f.rule)).flatMap((f) => arr(f.evidence).map((e) => ({ ...e, rule: f.rule, title: f.title, count: f.count })));
}

function permissions(view) {
  const { analysis, scan } = view;
  const priv = arr(arr(scan.findings).find((f) => f.rule === 'owner-controlled-functions')?.evidence);
  const privTotal = arr(scan.findings).find((f) => f.rule === 'owner-controlled-functions')?.count || 0;
  return section('permissions', 'Permissions', 'Who holds special powers over this contract, and which functions they control.',
    analysis ? (arr(analysis.permissions).length
      ? h('div', { class: 'cards' }, analysis.permissions.map((p) => h('div', { class: 'card' },
        h('h3', null, p.role), h('ul', null, arr(p.capabilities).map((c) => h('li', null, c))),
        arr(p.functions).length ? h('div', { class: 'chips' }, p.functions.map((fn) => h('span', { class: 'chip chip-fn' }, `${fn}()`))) : null)))
      : empty('No special roles identified.', 'The AI analysis found no privileged roles in the code it saw.'))
      : noAiBlock(view, 'Role descriptions'),
    h('div', null, h('h3', { class: 'sub-h' }, 'Privileged functions found by the scanner'),
      priv.length ? h('div', { class: 'rows' }, priv.map((e) => h('div', { class: 'row' },
        h('div', { class: 'meta' }, h('span', { class: 'fn-name' }, `${e.function || '?'}()`), accessChip(e.access)),
        h('div', null, h('p', null, e.detail || ''), h('p', { class: 'where' }, `${e.file}:${e.line}${e.inDependency ? ' (library)' : ''}`)))))
        : empty('No privileged functions matched.', 'The scanner looks for functions guarded by modifiers such as onlyOwner or onlyRole. That is not evidence that none exist.'),
      privTotal > priv.length ? h('p', { class: 'fineprint' }, `${privTotal - priv.length} more not shown.`) : null));
}

// ---------------------------------------------------------------------------------------------------------------
// 5. Fund movement
// ---------------------------------------------------------------------------------------------------------------
function scannerRows(scan, rules, emptyText) {
  const rows = ruleEvidence(scan, rules);
  if (!rows.length) return empty('Nothing matched.', emptyText);
  return h('div', { class: 'rows' }, rows.map((e) => h('div', { class: 'row' },
    h('div', { class: 'meta' }, h('span', { class: 'fn-name' }, e.function ? `${e.function}()` : 'In the contract body'), h('span', { class: 'tag', 'data-kind': 'scanner' }, e.title), accessChip(e.access)),
    h('div', null, e.detail ? h('p', null, e.detail) : null, arr(e.context).length ? h('div', { class: 'ev' }, codeBlock({ file: e.file, lines: e.context, severity: sev(e.severity) })) : h('p', { class: 'where' }, `${e.file}:${e.line}`)))));
}

function funds(view) {
  const { analysis, scan } = view;
  const aiFunds = analysis ? arr(analysis.fundMovement) : [];
  const aiCalls = analysis ? arr(analysis.externalCalls) : [];
  return section('funds', 'Fund movement', 'Functions that can move, create or pay out assets, and the external calls the contract makes.',
    h('div', null, h('h3', { class: 'sub-h' }, 'Moves or creates assets'),
      analysis ? (aiFunds.length ? h('div', { class: 'rows' }, aiFunds.map((f) => h('div', { class: 'row' },
        h('div', { class: 'meta' }, h('span', { class: 'fn-name' }, `${f.function}()`), h('span', { class: 'tag', 'data-kind': 'ai' }, f.mechanism)),
        h('div', null, h('p', null, f.description), h('p', { class: 'acc' }, 'Access control: ', h('b', null, f.accessControl))))))
        : empty('No fund-moving functions identified by the AI.', '')) : noAiBlock(view, 'The description of fund flows'),
      h('h3', { class: 'sub-h', style: undefined }, 'Matched by the scanner (mint and withdrawal rules)'),
      scannerRows(scan, ['mint-function', 'fund-withdrawal'], 'No minting or withdrawal-style functions matched. That is not evidence that funds cannot move.')),
    h('div', null, h('h3', { class: 'sub-h' }, 'External calls'),
      analysis ? (aiCalls.length ? h('div', { class: 'rows' }, aiCalls.map((c) => h('div', { class: 'row' },
        h('div', { class: 'meta' }, h('span', { class: 'fn-name' }, `${c.function}()`), h('span', { class: 'tag', 'data-kind': 'ai' }, c.kind)),
        h('div', null, h('p', null, c.description), h('p', { class: 'acc' }, 'Target: ', h('b', null, c.target))))))
        : empty('No external calls identified by the AI.', '')) : null,
      h('h3', { class: 'sub-h' }, 'Matched by the scanner (call, delegatecall, selfdestruct)'),
      scannerRows(scan, ['low-level-call', 'delegatecall', 'selfdestruct'], 'No low-level calls, delegatecall or selfdestruct matched.')));
}

// ---------------------------------------------------------------------------------------------------------------
// 6. Key functions
// ---------------------------------------------------------------------------------------------------------------
function functions(view) {
  const { analysis } = view;
  return section('functions', 'Key functions', 'The functions that matter most for understanding what this contract does.',
    analysis ? (arr(analysis.keyFunctions).length
      ? h('div', { class: 'cards' }, analysis.keyFunctions.map((f) => h('div', { class: 'card' },
        h('div', { class: 'fn-card-head' }, h('span', { class: 'fn-name' }, `${f.name}()`), h('span', { class: 'vis', 'data-vis': f.visibility }, f.visibility)),
        h('p', null, f.description))))
      : empty('No key functions listed.', 'The AI analysis did not single out any functions.'))
      : noAiBlock(view, 'The list of key functions'));
}

// ---------------------------------------------------------------------------------------------------------------
// 7. AI assessment
// ---------------------------------------------------------------------------------------------------------------
function assessment(view) {
  const { analysis, ai, report, ctx } = view;
  if (!analysis) {
    const failed = ai.status === 'failed';
    return section('assessment', 'AI assessment', 'A plain-language reading of the contract.',
      failed
        ? empty('The AI analysis failed.', `${(ai.error && ai.error.message) || ''} The scanner results above are unaffected.`,
          report.address && ai.error && ai.error.retryable ? h('div', null, h('button', { class: 'btn btn-sm', type: 'button', onclick: () => ctx.onRescan(report.address, { ai: true }) }, 'Try the AI analysis again')) : null)
        : noAiBlock(view, 'This section'));
  }
  const meta = ai.meta || {};
  const notes = [
    ...arr(meta.warnings),
    ...arr(meta.dropped).map((d) => `${plural(d.count, 'item')} dropped from ${d.section}: ${d.reason}.`),
    ...(arr(meta.scannerRulesNotReferenced).length && meta.scannerFindingsProvided ? [`Scanner signals the AI did not discuss: ${meta.scannerRulesNotReferenced.join(', ')}.`] : []),
  ];
  const cov = meta.sourceCoverage;
  return section('assessment', 'AI assessment', 'A plain-language reading of the contract. It can be wrong; check it against the evidence.',
    h('div', null,
      h('div', { class: 'ai-meta' },
        h('span', { class: 'tag', 'data-kind': 'ai' }, `${meta.provider || 'AI'}${meta.model ? `, ${meta.model}` : ''}`),
        ai.demo ? h('span', { class: 'tag' }, 'Recorded answer, not a live model') : null),
      h('p', { class: 'ai-summary' }, analysis.summary)),
    h('div', { class: 'cols2' },
      h('div', null, h('h3', { class: 'sub-h' }, 'Risks when you interact with it'),
        arr(analysis.interactionRisks).length ? h('ol', { class: 'olist' }, analysis.interactionRisks.map((r) => h('li', null, r.description, h('small', null, `Depends on: ${r.dependsOn}`))))
          : h('p', { class: 'fineprint' }, 'None identified.')),
      h('div', null, h('h3', { class: 'sub-h' }, 'What to check next'),
        arr(analysis.recommendations).length ? h('ol', { class: 'olist' }, analysis.recommendations.map((r) => h('li', null, r))) : h('p', { class: 'fineprint' }, 'None given.'))),
    arr(analysis.limitations).length ? h('div', null, h('h3', { class: 'sub-h' }, 'Limits of this analysis'), h('ul', { class: 'plain-list' }, analysis.limitations.map((l) => h('li', null, l)))) : null,
    h('details', { class: 'check' }, h('summary', null, 'How this analysis was checked'),
      h('div', null,
        h('p', { class: 'fineprint' }, 'Before this reached you, the server verified the AI’s answer against the source: functions must exist in the code, evidence must point at real lines, and findings without verifiable evidence were discarded.'),
        notes.length ? h('ul', { class: 'plain-list' }, notes.map((n) => h('li', null, n))) : h('p', { class: 'fineprint' }, 'No items were dropped and no warnings were raised.'),
        cov ? h('p', { class: 'fineprint' }, `Source sent to the model: ${plural(arr(cov.filesSent).length, 'file')}${arr(cov.filesTruncated).length ? `, ${arr(cov.filesTruncated).length} truncated` : ''}${arr(cov.filesOmitted).length ? `, ${arr(cov.filesOmitted).length} omitted` : ''}.`) : null)));
}

export { shortAddr, isAddress };