// Reading the data files: which data set, how to fetch each kind of file,
// and the checks a value must pass before the page uses it.

import { DATA_SETS, GITHUB, BRANCH } from './config.js';

const params = new URLSearchParams(location.search);
const setName = Object.hasOwn(DATA_SETS, params.get('data') ?? '') ? params.get('data') ?? '' : '';

/** The data set in use: '' for the real record, 'examples' for the preview. */
export const dataSet = setName;

/** Path prefix of the data set, relative to the page ('' or 'examples/'). */
export const prefix = DATA_SETS[setName];

export class DataError extends Error {
  constructor(message, { status } = {}) {
    super(message);
    this.name = 'DataError';
    this.status = status;
  }
}

/**
 * Fetches a data file.
 *  - fresh (latest.json): a per-minute query string gets past the Pages CDN
 *    cache, and 'no-cache' makes the browser revalidate.
 *  - version (the current month's index): the query string is the commit
 *    time from latest.json, so the file is downloaded once per commit and
 *    otherwise served from cache. It can grow to a few megabytes by the end
 *    of a busy month, so it must not be re-read on every refresh.
 *  - neither (dated records, which never change): the normal cache.
 */
async function fetchFile(path, { fresh = false, version = null } = {}) {
  const url = new URL(prefix + path, location.href);
  if (fresh) url.searchParams.set('t', String(Math.floor(Date.now() / 60_000)));
  else if (version) url.searchParams.set('v', version);
  let response;
  try {
    response = await fetch(url, { cache: fresh ? 'no-cache' : 'default' });
  } catch {
    throw new DataError(`network error reading ${path}`, { status: 0 });
  }
  if (!response.ok) throw new DataError(`${path}: HTTP ${response.status}`, { status: response.status });
  return response;
}

export async function getJSON(path, options = {}) {
  const response = await fetchFile(path, options);
  try {
    return await response.json();
  } catch {
    throw new DataError(`${path} is not valid JSON`);
  }
}

export async function getBytes(path) {
  const response = await fetchFile(path);
  return new Uint8Array(await response.arrayBuffer());
}

/** Lowercase hex SHA-256 of bytes, with the browser's own crypto. */
export async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Shapes of values that end up in links or in commands people paste into a
// shell. The schemas say the same; checking again here means a malformed
// file can break the page, but never inject into it.
const PATTERNS = {
  witness: /^data\/v1\/[a-z][a-z0-9-]{0,30}\/witness\/\d{4}\/\d{2}\/\d{2}\/\d{6}Z\.json$/,
  finding: /^data\/v1\/[a-z][a-z0-9-]{0,30}\/findings\/\d{4}\/\d{2}\/\d{2}\/\d{6}Z\.json$/,
  timestamp: /^data\/v1\/timestamps\/\d{4}\/\d{2}\/\d{2}\/\d{2}Z\.json$/,
  token: /^data\/v1\/timestamps\/\d{4}\/\d{2}\/\d{2}\/\d{2}Z\.tsr$/,
  time: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
  month: /^\d{4}-(0[1-9]|1[0-2])$/,
  treeHash: /^[A-Za-z0-9+/]{43}=$/,
  sha256: /^[0-9a-f]{64}$/,
  name: /^[a-z][a-z0-9-]{0,30}$/,
  origin: /^[A-Za-z0-9][A-Za-z0-9._/-]{0,253}$/,
  url: /^https:\/\/[A-Za-z0-9.-]+(\/[A-Za-z0-9._~-]+)*\/$/,
};

/** Returns value if it matches the named pattern, else throws DataError. */
export function must(kind, value, where) {
  if (typeof value !== 'string' || !PATTERNS[kind].test(value)) {
    throw new DataError(`${where}: unexpected ${kind} ${JSON.stringify(value)?.slice(0, 80)}`);
  }
  return value;
}

export function mustSize(value, where) {
  if (!Number.isSafeInteger(value) || value < 0) throw new DataError(`${where}: unexpected size`);
  return value;
}

/** Link to a data file on this site. */
export function fileHref(path) {
  return prefix + path;
}

/** The file's page on GitHub, and its commit history there. */
export function githubBlob(path) {
  return `${GITHUB}/blob/${BRANCH}/${prefix}${path}`;
}

export function githubHistory(path) {
  return `${GITHUB}/commits/${BRANCH}/${prefix}${path}`;
}

/** The month index path for a month "YYYY-MM". */
export function indexPath(month) {
  must('month', month, 'month');
  return `data/v1/index/${month.slice(0, 4)}/${month.slice(5)}.json`;
}

/** The hourly record path for an hour "YYYY-MM-DDTHH:00:00Z". */
export function timestampPath(hour) {
  return `data/v1/timestamps/${hour.slice(0, 4)}/${hour.slice(5, 7)}/${hour.slice(8, 10)}/${hour.slice(11, 13)}Z.json`;
}

/** The log a witness or finding path belongs to. */
export function logOf(path) {
  return path.split('/')[2];
}
