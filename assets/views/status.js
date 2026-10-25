// Status at a glance: the verdict, any findings, and one card per log.

import { h, icon, render, hashChip, timeEl, extLink } from '../dom.js';
import { t, tn, fmt, logName } from '../i18n.js';
import { overall, treeHealth, growth } from '../health.js';
import { fileHref, githubHistory, must, mustSize } from '../data.js';

const HEALTH_ICON = { fresh: 'check', stale: 'clock', finding: 'finding', error: 'warn' };

/** A health pill: icon and word, coloured by state. */
export function pill(health) {
  return h('span', { class: 'pill', 'data-health': health }, icon(HEALTH_ICON[health]), t(`health.${health}`));
}

/** A relative time that the app's ticker keeps current. */
function relative(iso, now) {
  return h('span', { 'data-rel': iso, text: fmt.relative(now - Date.parse(iso)) });
}

export function renderStatus(els, latest, now, select) {
  const { health, age } = overall(latest, now);
  const time = timeEl(latest.updatedAt, `${fmt.hm(latest.updatedAt)} UTC`);
  const body = {
    fresh: () => tn('verdict.fresh.body', { ago: relative(latest.updatedAt, now), time }),
    stale: () => tn('verdict.stale.body', { age: fmt.duration(age), time }),
    finding: () => tn('verdict.finding.body'),
  }[health]();

  els.verdict.dataset.health = health;
  render(els.verdict,
    icon(HEALTH_ICON[health]),
    h('div', {},
      h('strong', { text: t(`verdict.${health}`) }),
      h('p', {}, body),
      h('p', { class: 'witness-key' },
        `${t('witness.key')}: `,
        h('a', { href: fileHref('keys/witness/auditor.vkey') }, h('code', { text: latest.witness.name })),
        ` · ${latest.witness.keyHash}`)));

  renderFindings(els.findings, latest.findings, select);

  const logs = Object.keys(latest.logs).sort();
  render(els.trees, logs.map((log) => treeCard(log, latest, now, select)));
}

function treeCard(log, latest, now, select) {
  const e = latest.logs[log];
  const record = must('witness', e.record, `latest.logs.${log}.record`);
  must('treeHash', e.root, `latest.logs.${log}.root`);
  mustSize(e.size, `latest.logs.${log}.size`);
  const grew = growth(e);

  return h('article', { class: 'card tree', 'aria-labelledby': `tree-${log}` },
    h('div', { class: 'tree-head' },
      h('h3', { id: `tree-${log}`, text: logName(log) }),
      pill(treeHealth(log, latest, now))),
    h('p', { class: 'tree-origin' }, h('code', { text: e.origin })),
    h('p', { class: 'tree-size' }, fmt.number(e.size), ' ', h('small', { text: t('tree.entries') })),
    h('p', { class: 'muted', text: grew == null ? t('tree.first') : t('tree.grew', { n: fmt.number(grew) }) }),
    h('dl', { class: 'kv' },
      h('dt', { text: t('tree.root') }),
      h('dd', {}, hashChip(e.root, t('what.root'))),
      h('dt', { text: t('tree.witnessed') }),
      h('dd', {}, timeEl(e.witnessedAt, `${fmt.utc(e.witnessedAt)} UTC`), ' · ', relative(e.witnessedAt, now)),
      h('dt', { text: t('tree.checked') }),
      h('dd', {}, timeEl(e.checkedAt, `${fmt.utc(e.checkedAt)} UTC`)),
      h('dt', { text: t('tree.cosigned') }),
      h('dd', { text: t('tree.cosigned.value', { name: latest.witness.name }) })),
    h('div', { class: 'links' },
      h('a', { href: fileHref(record), text: t('tree.record') }),
      extLink(githubHistory(record), t('tree.history')),
      h('button', { type: 'button', class: 'linklike', onclick: () => select({ kind: 'witness', path: record }) }, t('tree.verify'))));
}

function renderFindings(container, findings, select) {
  if (!findings.length) {
    container.replaceChildren();
    return;
  }
  render(container, h('div', { class: 'finding-list' }, findings.map((f) => {
    const record = must('finding', f.record, 'finding.record');
    return h('article', { class: 'finding', 'aria-labelledby': `finding-${f.detectedAt}` },
      h('h3', { id: `finding-${f.detectedAt}` }, icon('finding'),
        t('finding.in', { kind: t(`finding.${f.kind}`), log: logName(f.log) })),
      h('p', { text: t(`finding.${f.kind}.body`) }),
      h('dl', { class: 'kv' },
        h('dt', { text: t('finding.detected') }),
        h('dd', {}, timeEl(f.detectedAt, `${fmt.utc(f.detectedAt)} UTC`)),
        h('dt', { text: t('finding.summary') }),
        h('dd', { text: f.summary }),
        h('dt', { text: t('finding.evidence') }),
        h('dd', {}, h('a', { href: fileHref(record) }, h('code', { text: record })))),
      h('div', { class: 'links' },
        extLink(githubHistory(record), t('tree.history')),
        h('button', { type: 'button', class: 'linklike', onclick: () => select({ kind: 'finding', path: record }) }, t('finding.verify'))));
  })));
}

/** The verdict when there is nothing to show yet, or loading failed. */
export function renderProblem(els, kind, detail, retry) {
  els.verdict.dataset.health = kind === 'empty' ? 'stale' : 'error';
  const actions = kind === 'empty'
    ? h('p', {}, h('a', { href: '?data=examples', text: t('verdict.empty.preview') }))
    : h('p', {}, h('button', { type: 'button', class: 'btn', onclick: retry }, t('verdict.retry')));
  render(els.verdict, icon(kind === 'empty' ? 'clock' : 'warn'),
    h('div', {},
      h('strong', { text: t(kind === 'empty' ? 'verdict.empty' : 'verdict.error') }),
      h('p', { text: kind === 'empty' ? t('verdict.empty.body') : detail }),
      actions));
  render(els.trees);
  els.findings.replaceChildren();
}
