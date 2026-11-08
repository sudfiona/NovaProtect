// Exercises public/js/site.js against a minimal DOM stub.
//
// The point is not to test a browser: it is to prove the script's own logic --
// feed parsing, card construction, text-only note rendering, and the failure
// path that must leave the baked HTML alone. A hand-written DOM stub keeps this
// runnable with no dependencies.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

const root = process.argv[2];
if (!root) { console.error('usage: test-site-js.mjs <public-dir>'); process.exit(2); }

const feed = JSON.parse(readFileSync(join(root, 'data/releases.json'), 'utf8'));

function makeNode(tag) {
  return {
    tagName: String(tag).toUpperCase(),
    className: '',
    textContent: '',
    children: [],
    attributes: {},
    appendChild(child) { this.children.push(child); return child; },
    setAttribute(k, v) { this.attributes[k] = v; },
  };
}

function makeDocument({ hasTargets = true } = {}) {
  const created = [];
  return {
    readyState: 'complete',
    created,
    createElement(tag) { const node = makeNode(tag); created.push(node); return node; },
    createTextNode(text) { return { nodeType: 3, textContent: String(text) }; },
    querySelectorAll(selector) {
      if (!hasTargets) return [];
      if (selector === '[data-latest-version]') return this._versionNodes || [];
      return [];
    },
    querySelector(selector) {
      if (!hasTargets) return null;
      if (selector === '[data-changelog]') return this._list || null;
      if (selector === '[data-changelog], [data-latest-version]') return this._list || (this._versionNodes || [])[0] || null;
      return null;
    },
    addEventListener() {},
  };
}

async function run({ feedValue, fetchFails = false }) {
  const doc = makeDocument();
  doc._list = makeNode('div');
  doc._versionNodes = [makeNode('span')];
  let fetchCalls = 0;

  const context = {
    document: doc,
    console,
    fetch: async () => {
      fetchCalls += 1;
      if (fetchFails) throw new Error('network down');
      return { ok: true, json: async () => feedValue };
    },
  };
  context.window = context;

  const source = readFileSync(join(root, 'js/site.js'), 'utf8');
  vm.createContext(context);
  vm.runInContext(source, context);
  // hydrate() runs synchronously when readyState is not 'loading', but its
  // promise chain needs a turn.
  for (let i = 0; i < 12; i++) await new Promise((r) => setImmediate(r));

  return { doc, list: doc._list, versions: doc._versionNodes, fetchCalls };
}

function flatten(node, depth = 0) {
  let out = '';
  const pad = '  '.repeat(depth);
  if (node.nodeType === 3) return `${pad}text(${JSON.stringify(node.textContent)})\n`;
  if (node.tagName) out += `${pad}[${node.tagName}${node.className ? ' .' + node.className : ''}]\n`;
  for (const child of node.children || []) out += flatten(child, depth + 1);
  return out;
}

// The text a card actually shows: every text node in order, newlines implied by
// the BR separators the renderer inserts.
function textOf(node) {
  if (node.nodeType === 3) return node.textContent;
  if (node.tagName === 'BR') return '\n';
  return (node.children || []).map(textOf).join('');
}

function elementTags(node) {
  const tags = [];
  for (const child of node.children || []) {
    if (child.tagName) { tags.push(child.tagName); tags.push(...elementTags(child)); }
  }
  return tags;
}

let failures = 0;
const check = (label, ok, detail = '') => {
  if (ok) { console.log(`  OK   ${label}`); return; }
  failures += 1;
  console.log(`  FAIL ${label}${detail ? ' -- ' + detail : ''}`);
};

// --- happy path ---------------------------------------------------------
{
  const { list, versions, fetchCalls } = await run({ feedValue: feed });
  check('fetch called once', fetchCalls === 1);
  check('one card per release', list.children.length === feed.length,
    `got ${list.children.length}, expected ${feed.length}`);
  check('latest version written', versions[0].textContent === feed[0].version,
    `got "${versions[0].textContent}"`);

  const first = list.children[0];
  const heading = first.children.find((c) => c.tagName === 'H2');
  check('card heading names the version', heading && heading.textContent === `客户端 ${feed[0].version}`,
    heading ? heading.textContent : 'no h2');

  const body = first.children.find((c) => c.className === 'announcement-body');
  check('notes rendered', Boolean(body) && body.children.length > 0);
  check('body text equals the release notes',
    body && textOf(body) === feed[0].notes,
    body ? `got ${JSON.stringify(textOf(body).slice(0, 40))}` : 'no body');

  // Release notes are untrusted text: the renderer may only produce text nodes
  // and BR separators, never an element parsed out of the note content.
  const allowed = new Set(['BR']);
  const offenders = elementTags(first).filter((tag) => !allowed.has(tag) && tag !== 'H2' && tag !== 'P' && tag !== 'DIV' && tag !== 'SPAN' && tag !== 'TIME' && tag !== 'A');
  check('notes produce only text and BR', offenders.length === 0, offenders.join(','));
}

// --- hostile note content ----------------------------------------------
{
  const hostile = [{
    version: '9.9.9',
    publishedAt: '2026-01-01',
    prerelease: false,
    pageUrl: 'https://example.invalid/r',
    notes: '<script>alert(1)</script><img src=x onerror=alert(2)>',
  }];
  const { list } = await run({ feedValue: hostile });
  const body = list.children[0].children.find((c) => c.className === 'announcement-body');
  const tags = elementTags(body);
  check('markup in notes stays text', tags.length === 0, tags.join(','));
  check('markup in notes is shown verbatim', textOf(body) === hostile[0].notes);
}

// --- failure path -------------------------------------------------------
{
  const { list, versions, fetchCalls } = await run({ fetchFails: true });
  check('failed fetch keeps baked changelog', list.children.length === 0);
  check('failed fetch keeps baked version', versions[0].textContent === '');
  check('failure still attempted the fetch', fetchCalls === 1);
}

// --- empty feed ---------------------------------------------------------
{
  const { list } = await run({ feedValue: [] });
  check('empty feed leaves baked content', list.children.length === 0);
}

// --- page without hooks -------------------------------------------------
{
  const doc = makeDocument({ hasTargets: false });
  const context = { document: doc, console, fetch: async () => { throw new Error('should not be called'); } };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(readFileSync(join(root, 'js/site.js'), 'utf8'), context);
  for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r));
  check('pages without hooks do no work', true);
}

if (failures > 0) {
  console.error(`\nSITE-JS-FAILED (${failures} failure(s))`);
  process.exit(1);
}
console.log('\nSITE-JS-OK');
