// Witness history: one tab per log, a month picker, and a paged table of the
// month's cosigned checkpoints (newest first) from the month index.

import { h, render, hashChip, timeEl, extLink } from '../dom.js';
import { t, fmt, logName } from '../i18n.js';
import { PAGE_SIZE } from '../config.js';
import { fileHref, githubHistory, must } from '../data.js';

/**
 * view: { logs, log, months, month, index (null while loading), page,
 *         selected, select(selection), setLog(log, viaKeyboard), setMonth(month), setPage(page) }
 */
export function renderHistory(container, view) {
  render(container, tabs(view), h('div', {
    id: 'history-panel',
    role: 'tabpanel',
    'aria-labelledby': `tab-${view.log}`,
  }, toolbar(view), table(view)));
}

function tabs({ logs, log, setLog }) {
  const list = h('div', { class: 'tabs', role: 'tablist', 'aria-label': t('history.title') }, logs.map((name) =>
    h('button', {
      type: 'button',
      role: 'tab',
      id: `tab-${name}`,
      'aria-selected': String(name === log),
      'aria-controls': 'history-panel',
      tabindex: name === log ? '0' : '-1',
      onclick: () => setLog(name, false),
    }, logName(name))));

  // Arrow keys, Home and End move between tabs (WAI-ARIA tabs pattern, with
  // automatic activation: the table follows the focused tab).
  list.addEventListener('keydown', (event) => {
    const i = logs.indexOf(log);
    const next = {
      ArrowRight: logs[(i + 1) % logs.length],
      ArrowLeft: logs[(i - 1 + logs.length) % logs.length],
      Home: logs[0],
      End: logs[logs.length - 1],
    }[event.key];
    if (!next) return;
    event.preventDefault();
    setLog(next, true);
  });
  return list;
}

function entriesOf({ index, log }) {
  return [...(index?.logs?.[log] ?? [])].reverse();
}

function toolbar(view) {
  const { months, month, page, setMonth, setPage } = view;
  const total = entriesOf(view).length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const from = total ? page * PAGE_SIZE + 1 : 0;
  const to = Math.min(total, (page + 1) * PAGE_SIZE);

  const select = h('select', { id: 'month-select', onchange: (e) => setMonth(e.target.value) },
    months.map((m) => h('option', { value: m, selected: m === month, text: fmt.month(m) })));

  return h('div', { class: 'toolbar' },
    h('div', { class: 'group' }, h('label', { for: 'month-select', text: t('history.month') }), select),
    h('div', { class: 'group' },
      h('span', { class: 'range', text: t('history.range', { from: fmt.number(from), to: fmt.number(to), total: fmt.number(total) }) }),
      h('div', { class: 'pager' },
        h('button', { type: 'button', class: 'btn', id: 'page-newer', disabled: page === 0, onclick: () => setPage(page - 1) }, '← ', t('history.newer')),
        h('button', { type: 'button', class: 'btn', id: 'page-older', disabled: page >= pages - 1, onclick: () => setPage(page + 1) }, t('history.older'), ' →'))));
}

function table(view) {
  const { log, month, page, index, selected, select } = view;
  if (!index) return h('div', { class: 'skeleton history-skeleton' });
  const all = entriesOf(view);
  if (!all.length) return h('p', { class: 'notice', text: t('history.empty', { month: fmt.month(month) }) });

  const rows = all.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const growths = rows.map((e) => (e.prev == null ? null : e.size - e.prev));
  const biggest = Math.max(1, ...growths.filter((g) => g != null));
  const head = [['history.time', ''], ['history.size', 'num'], ['history.growth', 'num'], ['history.root', ''], ['history.links', '']];

  return h('div', { class: 'table-wrap', role: 'region', tabindex: '0', 'aria-labelledby': 'history-caption' },
    h('table', {},
      h('caption', { id: 'history-caption', text: t('history.caption', { log: logName(log), month: fmt.month(month) }) }),
      h('thead', {}, h('tr', {}, head.map(([k, cls]) => h('th', { scope: 'col', class: cls || null, text: t(k) })))),
      h('tbody', {}, rows.map((e, i) => {
        const record = must('witness', e.record, 'index entry');
        return h('tr', { 'data-selected': selected === record },
          h('th', { scope: 'row' }, timeEl(e.at, fmt.utc(e.at))),
          h('td', { class: 'num', 'data-label': t('history.size') }, fmt.number(e.size)),
          h('td', { class: 'num', 'data-label': t('history.growth') }, growthCell(growths[i], biggest)),
          h('td', { 'data-label': t('history.root') }, hashChip(must('treeHash', e.root, 'index entry'), t('what.root'), 10)),
          h('td', { 'data-label': t('history.links') }, h('span', { class: 'row-actions' },
            h('a', { href: fileHref(record), text: t('history.json') }),
            extLink(githubHistory(record), t('history.commit')),
            h('button', {
              type: 'button',
              class: 'linklike',
              'aria-label': t('history.select.label', { time: fmt.utc(e.at) }),
              onclick: () => select({ kind: 'witness', path: record }),
            }, t('history.select')))));
      }))));
}

function growthCell(growth, biggest) {
  if (growth == null) return h('span', { class: 'muted', text: '—' });
  const fill = h('span');
  fill.style.width = `${Math.max(2, (growth / biggest) * 100)}%`; // CSSOM, allowed by the CSP
  return h('span', { class: 'growth' }, `+${fmt.number(growth)}`, h('span', { class: 'bar', 'aria-hidden': 'true' }, fill));
}
