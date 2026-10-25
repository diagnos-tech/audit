// Small DOM helpers. Data never goes through innerHTML: every value from a
// data file reaches the page as a text node or a checked attribute.

import { t } from './i18n.js';

/**
 * Creates an element. attrs: `class`, `text`, `on<event>` handlers, boolean
 * attributes as true/false, anything else as an attribute; null/undefined
 * skips. Children: nodes, strings, arrays; null/false are skipped.
 */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'text') el.textContent = value;
    else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children) {
    if (child == null || child === false) continue;
    if (Array.isArray(child)) append(el, child);
    else el.append(child);
  }
}

// Icons as shapes, built with createElementNS (no markup strings at all).
const ICONS = {
  check: [['path', { d: 'M5 12.5 10 17l9-10' }]],
  warn: [['path', { d: 'M12 3 2.5 20h19L12 3Z' }], ['path', { d: 'M12 10v4.5M12 17.5v.01' }]],
  finding: [['path', { d: 'M8 3h8l5 5v8l-5 5H8l-5-5V8l5-5Z' }], ['path', { d: 'M12 8v5M12 16.5v.01' }]],
  cross: [['path', { d: 'M6 6l12 12M18 6 6 18' }]],
  copy: [['rect', { x: 8, y: 8, width: 12, height: 12, rx: 2 }], ['path', { d: 'M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3' }]],
  clock: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 7v5l3 2' }]],
};

const SVG = 'http://www.w3.org/2000/svg';

/** A decorative icon; the meaning is always also in text next to it. */
export function icon(name) {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', 'icon');
  for (const [tag, attrs] of ICONS[name]) {
    const shape = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) shape.setAttribute(k, String(v));
    svg.append(shape);
  }
  return svg;
}

/**
 * Replaces the children of a container. If keyboard focus was inside, it
 * moves to the equivalent control in the new content (same kind, same name,
 * same position among equals), so a refresh never throws a reader back to
 * the top of the page.
 */
export function render(container, ...children) {
  const active = document.activeElement;
  const had = active && active !== container && container.contains(active);
  const key = had ? focusKey(active) : null;
  const nth = had ? equals(container, active, key).indexOf(active) : -1;

  container.replaceChildren();
  append(container, children);
  container.classList.remove('skeleton');
  container.removeAttribute('aria-busy');

  if (had) equals(container, active, key)[Math.max(0, nth)]?.focus({ preventScroll: true });
}

function focusKey(el) {
  return `${el.tagName}|${el.id}|${el.getAttribute('aria-label') ?? ''}|${el.textContent.trim()}`;
}

function equals(container, el, key) {
  return [...container.querySelectorAll(el.tagName)].filter((e) => focusKey(e) === key);
}

let announceTimer;

/** Says something through the page's single polite live region. */
export function announce(message) {
  const region = document.getElementById('announcer');
  region.textContent = '';
  clearTimeout(announceTimer);
  // A short delay makes screen readers treat repeated messages as new.
  announceTimer = setTimeout(() => { region.textContent = message; }, 120);
}

/**
 * A button that copies value. what names the thing for screen readers
 * ("Copy root hash"), since several copy buttons share a view.
 */
export function copyButton(value, what) {
  const label = h('span', { class: 'visually-hidden', text: t('copy.what', { what }) });
  const button = h('button', { type: 'button', class: 'copy', title: t('copy.what', { what }) }, icon('copy'), label);
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      button.dataset.copied = '';
      announce(t('copy.done', { what }));
      setTimeout(() => delete button.dataset.copied, 1500);
    } catch {
      announce(t('copy.failed'));
    }
  });
  return button;
}

/** A hash shown short, with the full value in its title and on copy. */
export function hashChip(value, what, chars = 12) {
  const shown = value.length > chars + 1 ? `${value.slice(0, chars)}…` : value;
  return h('span', { class: 'hash' }, h('code', { title: value, text: shown }), copyButton(value, what));
}

/** A <time> element; the title shows the instant in the reader's zone. */
export function timeEl(iso, text) {
  const local = new Date(iso).toLocaleString(document.documentElement.lang);
  return h('time', { datetime: iso, title: local, text });
}

/** A link that leaves the site. */
export function extLink(href, text) {
  return h('a', { href, rel: 'noopener', text });
}
