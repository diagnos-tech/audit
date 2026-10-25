// How to verify the selected record: the exact commands, with its paths
// filled in, and an optional quick check in this browser.

import { h, icon, render, copyButton, extLink } from '../dom.js';
import { t, tn, logName } from '../i18n.js';
import { GITHUB, BRANCH, SITE } from '../config.js';
import { dataSet, prefix, logOf } from '../data.js';

const CLONE = 'git clone --depth 1 https://github.com/diagnos-tech/audit\ncd audit';

function codeBlock(text) {
  return h('div', { class: 'code' }, h('pre', {}, h('code', { text })), copyButton(text, t('what.command')));
}

function step(title, text, note) {
  return h('li', {},
    h('span', { class: 'step-title', text: title }),
    codeBlock(text),
    note && h('p', { class: 'step-note', text: note }));
}

/** "-root examples " in the example data set, nothing otherwise. */
const rootFlag = dataSet ? `-root ${dataSet} ` : '';

function describe(sel) {
  const time = sel.path.match(/(\d{4})\/(\d{2})\/(\d{2})\/(\d{2})(\d{2})?(\d{2})?Z/);
  const [, y, mo, d, hh, mm = '00', ss = '00'] = time;
  const when = `${y}-${mo}-${d} ${hh}:${mm}:${ss}`;
  if (sel.kind === 'timestamp') return t('verify.timestamp', { hour: `${y}-${mo}-${d} ${hh}:00` });
  return t(`verify.${sel.kind}`, { log: logName(logOf(sel.path)), time: when });
}

function witnessSteps(sel) {
  const p = sel.path;
  const remote = `go run github.com/diagnos-tech/audit/tools/verify@latest witness \\\n  -root ${SITE}${prefix} ${p}`;
  return [
    step(t('verify.clone'), CLONE, t('verify.clone.note')),
    step(t('verify.witness.step'), `go run ./tools/verify witness ${rootFlag}${p}`, t('verify.witness.note')),
    step(t('verify.log.step'), `go run ./tools/verify consistency ${rootFlag}${p}`,
      dataSet ? `${t('verify.log.note')} ${t('verify.log.example')}` : t('verify.log.note')),
    step(t('verify.noclone.step'), remote),
  ];
}

function timestampSteps(sel, rec) {
  const p = sel.path;
  const tsr = p.replace(/\.json$/, '.tsr');
  const cd = dataSet ? `cd ${dataSet}\n` : '';
  const lines = [
    `${cd}jq -jcS .subject ${p} | sha256sum`,
    `jq -r .imprint ${p}`,
  ];
  if (rec?.token) {
    lines.push(`openssl ts -verify -digest "$(jq -r .imprint ${p})" \\\n  -in ${tsr} -CAfile keys/tsa/${rec.token.provider}.pem`);
  }
  if (rec?.subject?.prev) {
    lines.push(`sha256sum ${rec.subject.prev.record}`, `jq -r .subject.prev.sha256 ${p}`);
  }
  return [
    step(t('verify.clone'), CLONE, t('verify.clone.note')),
    step(t('verify.ts.step'), `go run ./tools/verify timestamp -openssl ${rootFlag}${p}`, t('verify.ts.note')),
    step(t('verify.ts.byhand'), lines.join('\n'), t('verify.ts.byhand.note')),
  ];
}

function findingSteps(sel) {
  return [
    step(t('verify.clone'), CLONE, t('verify.clone.note')),
    step(t('verify.finding.step'), `go run ./tools/verify finding ${rootFlag}${sel.path}`, t('verify.finding.note')),
  ];
}

/**
 * Renders the panel for sel = {kind, path}. rec is the selected record when
 * it has been loaded (the hourly steps need its provider and previous link).
 */
export function renderVerify(container, sel, rec) {
  const steps = { witness: witnessSteps, timestamp: timestampSteps, finding: findingSteps }[sel.kind](sel, rec);
  const results = h('ul', { class: 'results', 'aria-live': 'polite' });
  const button = h('button', { type: 'button', class: 'btn btn-primary' }, t('verify.browser'));
  button.addEventListener('click', () => runInBrowser(sel, button, results));

  render(container,
    h('p', { class: 'verify-target' }, tn('verify.selected', { what: h('strong', { text: describe(sel) }) })),
    h('ol', { class: 'steps' }, steps),
    h('p', { class: 'links' },
      extLink(`${GITHUB}/blob/${BRANCH}/VERIFY.md`, t('verify.doc'))),
    h('div', { class: 'browser-check card' },
      h('p', { class: 'step-note', text: t('verify.browser.note') }),
      h('p', { class: 'links' }, button),
      results));
}

async function runInBrowser(sel, button, results) {
  button.disabled = true;
  results.replaceChildren(h('li', { text: t('verify.browser.running') }));
  try {
    const { checkSelection } = await import('../checks.js');
    const outcome = await checkSelection(sel);
    results.replaceChildren(...outcome.map((r) =>
      h('li', { 'data-ok': String(r.ok) },
        icon(r.ok ? 'check' : 'cross'),
        h('span', {}, h('span', { text: r.label }), r.detail && h('span', { class: 'detail', text: ` — ${r.detail}` })))));
    const ok = outcome.filter((r) => r.ok).length;
    results.append(h('li', {}, h('strong', { text: t('verify.browser.done', { ok, total: outcome.length }) })));
  } catch (err) {
    results.replaceChildren(h('li', { 'data-ok': 'false' }, icon('cross'), h('span', { text: err.message })));
  } finally {
    button.disabled = false;
  }
}

