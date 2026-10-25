// The hourly independent proof: the latest RFC 3161 timestamp, a strip of
// the last hours, and the chain of hourly records as a table.

import { h, icon, render, hashChip, timeEl, extLink } from '../dom.js';
import { t, fmt } from '../i18n.js';
import { hourState } from '../health.js';
import { PROVIDERS } from '../config.js';
import { fileHref, githubHistory, timestampPath, must } from '../data.js';

const STATES = ['ok', 'fallback', 'gap', 'missing', 'broken'];

export function providerName(id) {
  return PROVIDERS[id] ?? id;
}

/**
 * view: { latest, hours: [{hour, entry, record, link}] oldest first,
 *         selected, select(selection), earlier(), later() (null when not possible) }
 */
export function renderHourly(container, view) {
  render(container,
    h('div', { class: 'hourly-grid' }, latestCard(view), stripCard(view)),
    chainTable(view));
}

function latestCard({ latest, select }) {
  const ts = latest.timestamp;
  if (!ts) return h('article', { class: 'card' }, h('h3', { text: t('hourly.latest') }), h('p', { class: 'muted', text: '—' }));
  const record = must('timestamp', ts.record, 'latest.timestamp.record');
  const token = ts.token;

  return h('article', { class: 'card', 'aria-labelledby': 'ts-latest' },
    h('h3', { id: 'ts-latest', text: t('hourly.latest') }),
    h('dl', { class: 'kv' },
      h('dt', { text: t('hourly.hour') }),
      h('dd', {}, timeEl(ts.hour, `${fmt.utc(ts.hour)} UTC`)),
      h('dt', { text: t('hourly.provider') }),
      h('dd', { text: token ? providerName(token.provider) : '—' }),
      h('dt', { text: t('hourly.genTime') }),
      h('dd', {}, token ? timeEl(token.genTime, `${fmt.utc(token.genTime)} UTC`) : '—'),
      h('dt', { text: t('hourly.imprint') }),
      h('dd', {}, hashChip(must('sha256', ts.imprint, 'imprint'), t('what.imprint'), 16))),
    token
      ? h('p', { class: 'checks' }, h('span', { class: 'pill', 'data-tone': 'ok' }, icon('check'), t('hourly.checked')))
      : h('p', { class: 'checks' }, h('span', { class: 'pill', 'data-tone': 'warn' }, icon('warn'), t('hourly.none'))),
    h('div', { class: 'links' },
      h('a', { href: fileHref(record), text: t('tree.record') }),
      token && h('a', { href: fileHref(must('token', token.file, 'token.file')), text: t('hourly.token') }),
      extLink(githubHistory(record), t('tree.history')),
      h('button', { type: 'button', class: 'linklike', onclick: () => select({ kind: 'timestamp', path: record }) }, t('hourly.verify'))));
}

function stateLabel(hour) {
  return t(`hourly.state.${hourState(hour)}`);
}

function stripCard({ hours, selected, select, earlier, later }) {
  const first = hours[0].hour;
  const last = hours[hours.length - 1].hour;
  return h('article', { class: 'card strip-card', 'aria-labelledby': 'ts-strip' },
    h('div', { class: 'tree-head' },
      h('h3', { id: 'ts-strip', text: t('hourly.strip', { n: hours.length }) }),
      h('div', { class: 'pager' },
        h('button', { type: 'button', class: 'btn', disabled: !earlier, onclick: earlier }, '← ', t('hourly.earlier')),
        h('button', { type: 'button', class: 'btn', disabled: !later, onclick: later }, t('hourly.later'), ' →'))),
    h('p', { class: 'strip-note', text: t('hourly.strip.note') }),
    h('ol', { class: 'strip' }, hours.map((hour) => {
      const state = hourState(hour);
      const path = timestampPath(hour.hour);
      const label = `${fmt.utc(hour.hour)} UTC: ${stateLabel(hour)}`;
      return h('li', {},
        h('button', {
          type: 'button',
          'data-state': state,
          'aria-label': label,
          title: label,
          'aria-pressed': String(selected === path),
          disabled: state === 'missing',
          onclick: () => select({ kind: 'timestamp', path }),
        }));
    })),
    h('div', { class: 'strip-axis', 'aria-hidden': 'true' },
      h('span', { text: `${fmt.utc(first).slice(5, 16)} UTC` }),
      h('span', { text: `${fmt.utc(last).slice(5, 16)} UTC` })),
    h('ul', { class: 'legend' }, STATES.map((state) =>
      h('li', {}, h('span', { class: 'swatch', 'data-state': state }), t(`hourly.state.${state}`)))),
    chainSummary(hours));
}

/** One sentence on the links checked in this browser. */
function chainSummary(hours) {
  const links = hours.filter((hr) => hr.entry?.prev != null);
  const bad = links.filter((hr) => hr.link === false).length;
  const unknown = links.filter((hr) => hr.link == null).length;
  if (bad) return h('p', { class: 'chain-summary link-bad' }, icon('cross'), ' ', t('hourly.chain.bad', { bad, n: links.length }));
  if (!hours.checked) return h('p', { class: 'chain-summary muted', text: t('hourly.chain.pending') });
  if (unknown) return h('p', { class: 'chain-summary muted', text: t('hourly.chain.unknown', { unknown, n: links.length }) });
  return h('p', { class: 'chain-summary link-ok' }, icon('check'), ' ', t('hourly.chain.ok', { n: links.length }));
}

/** "13:00 UTC" for data/v1/timestamps/YYYY/MM/DD/13Z.json. */
function hourOfPath(path) {
  const hh = /\/(\d{2})Z\.json$/.exec(path ?? '')?.[1];
  return hh ? `${hh}:00 UTC` : '?';
}

function linkCell(hour) {
  if (!hour.entry) return '—';
  if (hour.entry.prev == null) return h('span', { class: 'muted', text: t('hourly.link.first') });
  const prevHour = hourOfPath(hour.record?.subject?.prev?.record);
  if (hour.link === true) return h('span', { class: 'link-ok' }, icon('check'), ' ', t('hourly.link.ok', { hour: prevHour }));
  if (hour.link === false) return h('span', { class: 'link-bad' }, icon('cross'), ' ', t('hourly.link.bad', { hour: prevHour }));
  return h('span', { class: 'muted', text: t('hourly.link.unchecked') });
}

function chainTable({ hours, selected, select }) {
  const rows = [...hours].reverse();
  const caption = t('hourly.table', { from: fmt.utc(hours[0].hour).slice(0, 16), to: fmt.utc(hours[hours.length - 1].hour).slice(0, 16) });
  const head = ['hourly.hour', 'hourly.provider', 'hourly.genTime', 'hourly.imprint', 'hourly.link', 'hourly.files'];

  return h('div', { class: 'table-wrap spaced', role: 'region', tabindex: '0', 'aria-labelledby': 'ts-caption' },
    h('table', {},
      h('caption', { id: 'ts-caption', text: caption }),
      h('thead', {}, h('tr', {}, head.map((k) => h('th', { scope: 'col', text: t(k) })))),
      h('tbody', {}, rows.map((hour) => {
        const e = hour.entry;
        const path = timestampPath(hour.hour);
        return h('tr', { 'data-selected': selected === path },
          h('th', { scope: 'row' }, timeEl(hour.hour, `${fmt.utc(hour.hour).slice(0, 16)}`)),
          h('td', { 'data-label': t('hourly.provider') },
            e ? (e.provider ? providerName(e.provider) : h('span', { class: 'muted', text: stateLabel(hour) })) : h('span', { class: 'muted', text: stateLabel(hour) })),
          h('td', { 'data-label': t('hourly.genTime') }, e?.genTime ? fmt.utc(e.genTime).slice(11) : '—'),
          h('td', { 'data-label': t('hourly.imprint') }, e ? hashChip(e.imprint, t('what.imprint'), 10) : '—'),
          h('td', { 'data-label': t('hourly.link') }, linkCell(hour)),
          h('td', { 'data-label': t('hourly.files') },
            e ? h('span', { class: 'row-actions' },
              h('a', { href: fileHref(path), text: t('history.json') }),
              e.provider && h('a', { href: fileHref(path.replace(/\.json$/, '.tsr')), text: '.tsr' }),
              extLink(githubHistory(path), t('history.commit')),
              h('button', {
                type: 'button',
                class: 'linklike',
                'aria-label': t('history.select.label', { time: fmt.utc(hour.hour) }),
                onclick: () => select({ kind: 'timestamp', path }),
              }, t('history.select'))) : '—'));
      }))));
}
