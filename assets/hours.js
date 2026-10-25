// Assembles a window of the hourly timestamp chain from the month indexes,
// then checks each link in this browser: the previous record's bytes must
// hash to what the next hour's subject says.

import { getBytes, sha256Hex, timestampPath, must } from './data.js';
import { hourWindow } from './health.js';

const bytesCache = new Map(); // path → Promise<{sha, json}>; hourly records never change

function readRecord(path) {
  if (!bytesCache.has(path)) {
    const load = getBytes(path).then(async (bytes) => ({
      sha: await sha256Hex(bytes),
      json: JSON.parse(new TextDecoder().decode(bytes)),
    }));
    load.catch(() => bytesCache.delete(path)); // let a later refresh retry
    bytesCache.set(path, load);
  }
  return bytesCache.get(path);
}

/**
 * The hours of the window ending at endHour, oldest first, each with its
 * index entry (or null when there is no record for that hour).
 * getIndex(month) resolves to the month index or null.
 */
export async function windowHours(endHour, count, getIndex) {
  const hours = hourWindow(endHour, count);
  const months = [...new Set(hours.map((h) => h.slice(0, 7)))];
  const indexes = await Promise.all(months.map((m) => getIndex(m)));
  const byHour = new Map();
  for (const index of indexes) {
    for (const e of index?.timestamps ?? []) byHour.set(e.hour, e);
  }
  return hours.map((hour) => {
    const entry = byHour.get(hour) ?? null;
    if (entry) {
      must('timestamp', entry.record, 'index timestamp');
      if (entry.record !== timestampPath(hour)) throw new Error(`index entry for ${hour} points at ${entry.record}`);
    }
    return { hour, entry, record: null, link: null };
  });
}

/**
 * Loads the records of the window and checks each hour's link to its
 * previous record. Sets hour.record and hour.link (true, false, or null when
 * the record is the first of the chain or could not be read).
 */
export async function checkLinks(hours) {
  await Promise.all(hours.map(async (hour) => {
    if (!hour.entry) return;
    let prev;
    try {
      hour.record = (await readRecord(hour.entry.record)).json;
      prev = hour.record.subject?.prev;
      if (!prev) return;
      must('timestamp', prev.record, 'subject.prev.record');
    } catch {
      return; // unreadable here; the link stays unchecked
    }
    try {
      const { sha } = await readRecord(prev.record);
      hour.link = sha === prev.sha256 && prev.sha256 === hour.entry.prev;
    } catch (err) {
      // A previous record that is gone is exactly what the chain exposes.
      hour.link = err?.status === 404 ? false : null;
    }
  }));
  hours.checked = true;
  return hours;
}
