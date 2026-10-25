// What the page says about the state of the record. Pure functions of the
// data and the current time, so the rules are easy to read in one place.

import { STALE_AFTER_MS } from './config.js';

/**
 * Health of the whole record:
 *  - 'finding' if any finding was ever recorded (findings are permanent);
 *  - 'stale' if the witness has not committed for STALE_AFTER_MS (it commits
 *    at least hourly, so silence means it stopped, not that the logs are
 *    quiet: a log that does not grow is fine);
 *  - 'fresh' otherwise.
 */
export function overall(latest, now) {
  const age = now - Date.parse(latest.updatedAt);
  if (latest.findings.length > 0) return { health: 'finding', age };
  if (age > STALE_AFTER_MS) return { health: 'stale', age };
  return { health: 'fresh', age };
}

/** Health of one log, by the same rules. */
export function treeHealth(log, latest, now) {
  if (latest.findings.some((f) => f.log === log)) return 'finding';
  return now - Date.parse(latest.updatedAt) > STALE_AFTER_MS ? 'stale' : 'fresh';
}

/** Growth of the latest witnessed tree head, or null for the first record. */
export function growth(entry) {
  return entry.previousSize == null ? null : entry.size - entry.previousSize;
}

/**
 * State of one hour of the timestamp chain, for the strip:
 *  - 'missing': no record for that hour (the witness did not run);
 *  - 'broken': the record's link to the previous one does not match the
 *    previous record's bytes, as checked in this browser;
 *  - 'gap': a record, but every provider failed, so no token;
 *  - 'fallback': a token, from a provider after the first one failed;
 *  - 'ok'.
 */
export function hourState(hour) {
  if (!hour.entry) return 'missing';
  if (hour.link === false) return 'broken';
  if (!hour.entry.provider) return 'gap';
  if (hour.record?.attempts?.length) return 'fallback';
  return 'ok';
}

/** The whole hours from the newest back, oldest first. */
export function hourWindow(newest, count) {
  const end = Date.parse(newest);
  return Array.from({ length: count }, (_, i) => new Date(end - (count - 1 - i) * 3_600_000).toISOString().replace('.000Z', 'Z'));
}
