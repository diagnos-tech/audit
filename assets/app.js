// Entry point: loads the record, renders each section, and keeps it current.
//
// Data flow: latest.json (small, re-read every few minutes) drives the status
// and says which month indexes exist; the month indexes drive the hourly
// strip and the history table; single records are read only to check links
// or to fill in the verify commands.

import { REFRESH_MS, STRIP_HOURS } from './config.js';
import { t, fmt, logName, initLang, getLang, setLang, translateStatic } from './i18n.js';
import { DataError, dataSet, getJSON, indexPath, must, mustSize } from './data.js';
import { announce, render } from './dom.js';
import { overall } from './health.js';
import { renderStatus, renderProblem } from './views/status.js';
import { renderHourly } from './views/hourly.js';
import { renderHistory } from './views/history.js';
import { renderVerify } from './views/verify.js';
import { windowHours, checkLinks } from './hours.js';

document.documentElement.dataset.app = 'started';

const $ = (id) => document.getElementById(id);
const els = {
  verdict: $('verdict'),
  findings: $('findings'),
  trees: $('trees'),
  hourly: $('hourly-body'),
  history: $('history-body'),
  verify: $('verify-body'),
  sections: ['status', 'hourly', 'history', 'verify'].map($),
  refreshState: $('refresh-state'),
};

const params = new URLSearchParams(location.search);
const state = {
  latest: null,
  refreshedAt: 0,
  indexes: new Map(), // "month@version" → Promise<index|null>
  hours: null,
  hourEnd: null, // end of the hourly window; null follows the latest hour
  firstHour: null, // the oldest hourly record, where the window stops
  history: { log: params.get('log'), month: params.get('month'), page: 0 },
  selection: null, // {kind, path} shown in the verify panel
};

/**
 * "Now" for freshness. The example data set is frozen in time, so its clock
 * is pinned a few minutes after its last commit (or to ?now= to preview other
 * states); the real record always uses the real clock.
 */
function now() {
  if (!dataSet || !state.latest) return Date.now();
  const pinned = Date.parse(params.get('now') ?? '');
  return Number.isFinite(pinned) ? pinned : Date.parse(state.latest.updatedAt) + 3 * 60_000;
}

// --- Loading ----------------------------------------------------------------

function checkLatest(latest) {
  if (latest?.schema !== 'latest/v1') throw new DataError('latest.json: unknown schema');
  must('time', latest.updatedAt, 'latest.updatedAt');
  for (const [log, e] of Object.entries(latest.logs)) {
    must('name', log, 'latest.logs');
    must('witness', e.record, `latest.logs.${log}`);
    must('time', e.witnessedAt, `latest.logs.${log}`);
    must('time', e.checkedAt, `latest.logs.${log}`);
    mustSize(e.size, `latest.logs.${log}`);
  }
  latest.months.forEach((m) => must('month', m, 'latest.months'));
  return latest;
}

/**
 * The month index, cached per commit: the newest month's copy is keyed by
 * latest.updatedAt, so it is fetched again only after the witness commits.
 */
function getIndex(month) {
  if (!state.latest.months.includes(month)) return Promise.resolve(null);
  const version = month === state.latest.months[0] ? state.latest.updatedAt : null;
  const key = `${month}@${version}`;
  if (!state.indexes.has(key)) {
    for (const old of state.indexes.keys()) if (old.startsWith(`${month}@`)) state.indexes.delete(old);
    const load = getJSON(indexPath(month), { version }).then((index) => {
      if (index?.schema !== 'index/v1' || index.month !== month) throw new DataError(`index ${month}: unexpected content`);
      return index;
    });
    load.catch(() => state.indexes.delete(key));
    state.indexes.set(key, load);
  }
  return state.indexes.get(key);
}

let timer;

async function refresh({ initial = false } = {}) {
  clearTimeout(timer);
  if (document.hidden && !initial) return schedule();
  els.refreshState.textContent = t('refresh.loading');
  let latest;
  try {
    latest = checkLatest(await getJSON('data/v1/latest.json', { fresh: true }));
  } catch (err) {
    if (!state.latest) {
      const empty = err instanceof DataError && err.status === 404;
      renderProblem(els, empty ? 'empty' : 'error', err.message, () => refresh({ initial: true }));
      els.sections.slice(1).forEach((s) => { s.hidden = true; });
    }
    els.refreshState.textContent = state.latest ? t('refresh.failed') : '';
    timer = setTimeout(refresh, 60_000);
    return;
  }

  const previous = state.latest;
  state.latest = latest;
  state.refreshedAt = Date.now();
  els.sections.forEach((s) => { s.hidden = false; });
  if (previous?.updatedAt === latest.updatedAt) {
    // No new commit: only the clock moved (relative times, maybe staleness).
    tick();
  } else {
    if (previous) announceChanges(previous, latest);
    renderAll();
  }
  updateRefreshState();
  schedule();
}

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(refresh, REFRESH_MS);
}

function announceChanges(before, after) {
  const messages = [];
  for (const [log, e] of Object.entries(after.logs)) {
    if (e.size > (before.logs[log]?.size ?? 0)) messages.push(t('announce.grew', { log: logName(log), size: fmt.number(e.size) }));
  }
  if (after.timestamp && after.timestamp.hour !== before.timestamp?.hour) {
    messages.push(t('announce.hour', { hour: fmt.hm(after.timestamp.hour) }));
  }
  const was = overall(before, now()).health;
  const is = overall(after, now()).health;
  if (was !== is) messages.push(t('announce.health', { health: t(`health.${is}`) }));
  if (messages.length) announce(messages.join(' '));
}

// --- Rendering ----------------------------------------------------------------

function renderAll() {
  const latest = state.latest;
  renderStatus(els, latest, now(), select);
  shownHealth = overall(latest, now()).health;
  if (!state.selection) {
    const first = Object.keys(latest.logs).sort()[0];
    if (first) state.selection = { kind: 'witness', path: latest.logs[first].record };
    else if (latest.timestamp) state.selection = { kind: 'timestamp', path: latest.timestamp.record };
  }
  renderHourlySection();
  renderHistorySection();
  renderVerifySection();
}

async function renderHourlySection() {
  const latest = state.latest;
  if (!latest.timestamp) {
    render(els.hourly, emptyNote(t('hourly.empty')));
    return;
  }
  const newest = latest.timestamp.hour;
  const end = state.hourEnd ?? newest;
  try {
    const hours = await windowHours(end, STRIP_HOURS, (m) => getIndex(m));
    const oldest = await getIndex(latest.months.at(-1));
    state.firstHour = oldest?.timestamps?.[0]?.hour ?? newest;
    state.hours = hours;
    drawHourly(hours, end, newest);
    await checkLinks(hours);
    if (state.hours === hours) drawHourly(hours, end, newest);
  } catch (err) {
    render(els.hourly, sectionError(err));
  }
}

function drawHourly(hours, end, newest) {
  const step = (delta) => () => {
    state.hourEnd = new Date(Date.parse(end) + delta * 3_600_000).toISOString().replace('.000Z', 'Z');
    if (state.hourEnd >= newest) state.hourEnd = null;
    renderHourlySection();
  };
  renderHourly(els.hourly, {
    latest: state.latest,
    hours,
    selected: state.selection?.path,
    select,
    earlier: hours[0].hour > state.firstHour ? step(-STRIP_HOURS) : null,
    later: end < newest ? step(STRIP_HOURS) : null,
  });
}

async function renderHistorySection(focus) {
  const latest = state.latest;
  const logs = Object.keys(latest.logs).sort();
  const h = state.history;
  if (!logs.includes(h.log)) h.log = logs[0];
  if (!latest.months.includes(h.month)) h.month = latest.months[0];
  if (!h.log || !h.month) {
    render(els.history, emptyNote(t('history.none')));
    return;
  }
  const view = (index) => ({
    logs,
    log: h.log,
    months: latest.months,
    month: h.month,
    index,
    page: h.page,
    selected: state.selection?.path,
    select,
    setLog: (log, viaKeyboard) => { h.log = log; h.page = 0; syncURL(); renderHistorySection(viaKeyboard ? `tab-${log}` : null); },
    setMonth: (month) => { h.month = month; h.page = 0; syncURL(); renderHistorySection('month-select'); },
    setPage: (page) => {
      const focus = page > h.page ? 'page-older' : 'page-newer';
      h.page = page;
      renderHistorySection(focus);
    },
  });
  const wanted = `${h.log}/${h.month}`;
  let index = null;
  try {
    index = await getIndex(h.month);
  } catch (err) {
    render(els.history, sectionError(err));
    return;
  }
  if (`${h.log}/${h.month}` !== wanted) return; // a newer choice is rendering
  renderHistory(els.history, view(index));
  // Keep keyboard focus on the control that was used; a pager button that
  // just became disabled hands it to its sibling.
  const target = focus && document.getElementById(focus);
  if (target?.disabled) target.parentElement.querySelector('button:not(:disabled)')?.focus();
  else target?.focus();
}

async function renderVerifySection() {
  const sel = state.selection;
  if (!sel) return;
  let rec = null;
  if (sel.kind === 'timestamp') {
    try { rec = await getJSON(sel.path); } catch { /* the commands still work without it */ }
  }
  if (state.selection === sel) renderVerify(els.verify, sel, rec);
}

function emptyNote(text) {
  const p = document.createElement('p');
  p.className = 'notice';
  p.textContent = text;
  return p;
}

function sectionError(err) {
  const p = document.createElement('p');
  p.className = 'error-box';
  p.textContent = `${t('verdict.error')}: ${err.message}`;
  return p;
}

/** Selects a record for the verify panel and takes the reader there. */
function select(sel) {
  state.selection = sel;
  syncURL();
  renderVerifySection();
  if (state.hours) drawHourly(state.hours, state.hourEnd ?? state.latest.timestamp.hour, state.latest.timestamp.hour);
  renderHistorySection();
  const title = $('verify-title');
  title.setAttribute('tabindex', '-1');
  title.focus({ preventScroll: true });
  title.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

/** Keeps the URL shareable: the selected log, month and record. */
function syncURL() {
  const p = new URLSearchParams(location.search);
  const set = (k, v) => (v ? p.set(k, v) : p.delete(k));
  set('log', state.history.log);
  set('month', state.history.month);
  set('record', state.selection?.path);
  const query = p.toString();
  history.replaceState(null, '', query ? `?${query}` : location.pathname);
}

function selectionFromURL() {
  const path = params.get('record');
  if (!path) return null;
  for (const kind of ['witness', 'timestamp', 'finding']) {
    try { return { kind, path: must(kind, path, 'record') }; } catch { /* try the next kind */ }
  }
  return null;
}

// --- Clock, language, refresh button -------------------------------------------

function updateRefreshState() {
  if (!state.refreshedAt) return;
  els.refreshState.textContent = t('refresh.updated', { ago: fmt.relative(Date.now() - state.refreshedAt) });
}

let shownHealth = null;

function tick() {
  const n = now();
  if (state.latest) {
    // Staleness depends on the clock alone; redraw the status when it flips.
    const health = overall(state.latest, n).health;
    if (shownHealth && health !== shownHealth) {
      renderStatus(els, state.latest, n, select);
      announce(t('announce.health', { health: t(`health.${health}`) }));
    }
    shownHealth = health;
  }
  for (const el of document.querySelectorAll('[data-rel]')) el.textContent = fmt.relative(n - Date.parse(el.dataset.rel));
  updateRefreshState();
}

function setupChrome() {
  const lang = $('lang');
  const label = () => {
    const other = getLang() === 'en' ? 'pt-BR' : 'en';
    lang.textContent = other === 'en' ? 'EN' : 'PT';
    lang.lang = other;
    lang.setAttribute('aria-label', t('lang.switch'));
  };
  label();
  lang.addEventListener('click', () => {
    setLang(getLang() === 'en' ? 'pt-BR' : 'en');
    translateStatic();
    label();
    if (dataSet) exampleBanner();
    if (state.latest) renderAll();
    updateRefreshState();
  });
  $('refresh').addEventListener('click', () => refresh());
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && Date.now() - state.refreshedAt > 60_000) refresh();
  });
  setInterval(tick, 30_000);
}

function exampleBanner() {
  const banner = $('example-banner');
  banner.hidden = false;
  if (!state.latest) return;
  const clock = banner.querySelector('.clock') ?? banner.querySelector('.wrap').appendChild(document.createElement('span'));
  clock.className = 'clock';
  clock.textContent = ` ${t('example.clock', { time: `${fmt.utc(new Date(now()).toISOString().slice(0, 19) + 'Z')} UTC` })}`;
}

initLang();
translateStatic();
setupChrome();
state.selection = selectionFromURL();
if (dataSet) exampleBanner();
await refresh({ initial: true });
if (dataSet) exampleBanner();
