// A tiny Solidity highlighter for the evidence excerpts (a few lines each), plus the code-block component.
//
// It is deliberately simple: one pass per line, no parser. Evidence excerpts are cut out of a larger file, so a
// block comment can start before the first visible line; that case is handled with a heuristic below.
// Output is built from text nodes only (via h()), so untrusted contract text can never turn into markup.
import { h } from './dom.js';

const KEYWORDS = new Set((
  'abstract anonymous as assembly break calldata catch constant constructor continue contract delete do else emit enum ' +
  'error event external fallback false for from function if immutable import indexed interface internal is library ' +
  'mapping memory modifier new override payable pragma private public pure receive return returns revert storage ' +
  'struct super this throw true try type unchecked using view virtual while require assert'
).split(' '));

const TYPES = /^(?:address|bool|string|bytes\d{0,2}|u?int\d{0,3}|fixed|ufixed|byte)$/;

// Constructs that are worth drawing the eye to. These are the same things the scanner's rules look for.
const DANGEROUS = /^(?:selfdestruct|suicide|delegatecall|callcode)$/;

const NUMBER = /^(?:0x[0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)(?:\s?(?:wei|gwei|ether|seconds|minutes|hours|days|weeks))?/;
const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*/;

const span = (cls, text) => (cls ? h('span', { class: cls }, text) : text);

/**
 * Tokenise one line. `inBlock` says whether the line starts inside a /* ... *\/ comment.
 * Returns the DOM nodes for the line and whether the next line starts inside a block comment.
 */
export function highlightLine(text, inBlock = false) {
  const out = [];
  let i = 0;
  let plain = '';
  const flush = () => { if (plain) { out.push(plain); plain = ''; } };
  const push = (cls, value) => { flush(); out.push(span(cls, value)); };
  let block = inBlock;
  let prevWord = '';

  while (i < text.length) {
    if (block) {
      const end = text.indexOf('*/', i);
      if (end === -1) { push('tok-c', text.slice(i)); i = text.length; break; }
      push('tok-c', text.slice(i, end + 2));
      i = end + 2;
      block = false;
      continue;
    }

    const rest = text.slice(i);
    const ch = text[i];

    if (rest.startsWith('//')) { push('tok-c', rest); i = text.length; break; }
    if (rest.startsWith('/*')) {
      const end = text.indexOf('*/', i + 2);
      if (end === -1) { push('tok-c', rest); block = true; i = text.length; break; }
      push('tok-c', text.slice(i, end + 2));
      i = end + 2;
      continue;
    }

    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < text.length && text[j] !== ch) j += text[j] === '\\' ? 2 : 1;
      push('tok-s', text.slice(i, Math.min(j + 1, text.length)));
      i = Math.min(j + 1, text.length);
      prevWord = '';
      continue;
    }

    if (/\d/.test(ch)) {
      const m = NUMBER.exec(rest);
      if (m) { push('tok-n', m[0]); i += m[0].length; prevWord = ''; continue; }
    }

    if (/[A-Za-z_$]/.test(ch)) {
      const word = IDENT.exec(rest)[0];
      const after = text.slice(i + word.length);
      const before = text.slice(0, i);
      let cls = null;
      if (word === 'origin' && /tx\.\s*$/.test(before)) cls = 'tok-d';
      else if (word === 'tx' && /^\s*\.\s*origin\b/.test(after)) cls = 'tok-d';
      else if (DANGEROUS.test(word)) cls = 'tok-d';
      else if (KEYWORDS.has(word)) cls = 'tok-k';
      else if (TYPES.test(word)) cls = 'tok-t';
      else if (prevWord === 'function' || prevWord === 'modifier' || prevWord === 'event' || prevWord === 'error' || /^\s*\(/.test(after)) cls = 'tok-f';
      else if (prevWord === 'contract' || prevWord === 'interface' || prevWord === 'library' || /^[A-Z]/.test(word)) cls = 'tok-t';
      push(cls, word);
      prevWord = word;
      i += word.length;
      continue;
    }

    plain += ch;
    if (!/\s/.test(ch)) prevWord = '';
    i += 1;
  }
  flush();
  return { nodes: out, inBlock: block };
}

/**
 * One source excerpt. `lines` is [{ n, text, hit }]: the cited line has hit = true.
 * `severity` ('high' | 'medium' | 'low' | 'info') colours the marked line through the data-sev attribute.
 */
export function codeBlock({ file, lines, severity }) {
  const rows = Array.isArray(lines) ? lines : [];
  const first = rows[0] ? String(rows[0].text).trim() : '';
  // The excerpt can begin in the middle of a block comment; a leading "*" or "*/" is a reliable sign of that.
  let inBlock = first.startsWith('*');

  const body = h('div', { class: 'code-body', tabindex: '0', role: 'region', 'aria-label': `Source lines from ${file || 'contract'}` },
    rows.map((row) => {
      const result = highlightLine(String(row.text ?? ''), inBlock);
      inBlock = result.inBlock;
      return h('div', { class: row.hit ? 'cl hit' : 'cl' },
        h('span', { class: 'n', 'aria-hidden': 'true' }, row.n),
        h('span', { class: 't' }, result.nodes.length ? result.nodes : '\u200b'));
    }));

  const hit = rows.find((r) => r.hit);
  return h('div', { class: 'code', 'data-sev': severity || 'info', role: 'group', 'aria-label': `Evidence from ${file || 'contract'}` },
    h('div', { class: 'code-head' },
      h('span', { class: 'path', title: file || '' }, h('bdi', null, file || 'unknown file')),
      hit ? h('span', null, `line ${hit.n}`) : null),
    body);
}
