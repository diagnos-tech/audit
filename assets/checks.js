// The quick check behind "Check in this browser": the same verifications as
// tools/verify, with the browser's own SHA-256 and Ed25519 (Web Crypto).
// Loaded only when asked for. It trusts this page's code, which is why the
// page always shows the commands that do not.

import { getJSON, getBytes, sha256Hex, logOf } from './data.js';
import { t } from './i18n.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// --- Signed notes (C2SP signed-note) ---------------------------------------

/** Splits a signed note into its body and signature lines. */
function parseNote(text) {
  const split = text.lastIndexOf('\n\n');
  if (split < 0 || !text.endsWith('\n')) throw new Error('not a signed note');
  const body = text.slice(0, split + 1);
  const sigs = text.slice(split + 2, -1).split('\n').map((line) => {
    const m = /^— (\S+) ([A-Za-z0-9+/]+=*)$/.exec(line);
    if (!m) throw new Error('malformed signature line');
    const raw = fromB64(m[2]);
    return { name: m[1], hash: raw.slice(0, 4), raw: raw.slice(4) };
  });
  return { body, sigs };
}

/**
 * Parses "<name>+<hash>+<base64(alg || key)>" and checks that the key hash
 * (the first 4 bytes of SHA-256(name || "\n" || alg || key)) is the key's.
 */
async function parseVKey(vkey) {
  // Base64 may itself contain '+': only the first two separate fields.
  const [, name, hash, key64] = /^([^+]+)\+([0-9a-f]{8})\+(.+)$/.exec(vkey.trim()) ?? [];
  if (!key64) throw new Error('malformed vkey');
  const key = fromB64(key64);
  const id = (await sha256(concat(enc.encode(`${name}\n`), key))).slice(0, 4);
  if (Array.from(id, (b) => b.toString(16).padStart(2, '0')).join('') !== hash) throw new Error(`key hash mismatch in ${name}`);
  return { name, alg: key[0], pub: key.slice(1), id };
}

async function ed25519(pub, msg, sig) {
  let key;
  try {
    key = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
  } catch {
    throw new Error(t('verify.browser.unsupported'));
  }
  return crypto.subtle.verify({ name: 'Ed25519' }, key, sig, msg);
}

/** The cosignature/v1 key ID is always computed with algorithm 0x04. */
async function cosigKeyHash(name, pub) {
  return (await sha256(concat(enc.encode(`${name}\n`), Uint8Array.of(0x04), pub))).slice(0, 4);
}

async function verifyLogSig(note, vkey) {
  const sig = note.sigs.find((s) => s.name === vkey.name && equal(s.hash, vkey.id));
  return !!sig && vkey.alg === 0x01 && ed25519(vkey.pub, enc.encode(note.body), sig.raw);
}

/** Verifies a cosignature/v1 line and returns its time (unix seconds) or null. */
async function verifyCosig(note, vkey) {
  const id = await cosigKeyHash(vkey.name, vkey.pub);
  const sig = note.sigs.find((s) => s.name === vkey.name && equal(s.hash, id));
  if (!sig || sig.raw.length !== 72) return null;
  const time = new DataView(sig.raw.buffer, sig.raw.byteOffset).getBigUint64(0);
  const msg = enc.encode(`cosignature/v1\ntime ${time}\n${note.body}`);
  return (await ed25519(vkey.pub, msg, sig.raw.slice(8))) ? Number(time) : null;
}

function parseCheckpoint(body) {
  const [origin, size, root] = body.split('\n');
  return { origin, size: Number(size), root };
}

// --- Merkle consistency (RFC 9162 section 2.1.4.2) -------------------------

const hashChildren = (l, r) => sha256(concat(Uint8Array.of(1), l, r));

async function verifyConsistency(size1, size2, root1, root2, proof) {
  if (size1 === size2) return proof.length === 0 && equal(root1, root2);
  if (size1 === 0) return proof.length === 0;
  if (size1 > size2 || proof.length === 0) return false;
  // When size1 is a power of two, the old root is a node of the new tree and
  // the proof leaves it out.
  const path = isPow2(size1) ? [root1, ...proof] : proof;
  let fn = BigInt(size1 - 1);
  let sn = BigInt(size2 - 1);
  while (fn & 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) || fn === sn) {
      fr = await hashChildren(c, fr);
      sr = await hashChildren(c, sr);
      while (!(fn & 1n) && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else {
      sr = await hashChildren(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(fr, root1) && equal(sr, root2);
}

function isPow2(n) {
  const b = BigInt(n);
  return b > 0n && (b & (b - 1n)) === 0n;
}

// --- Checks -----------------------------------------------------------------

async function loadKey(path) {
  return parseVKey(dec.decode(await getBytes(path)));
}

async function checkWitness(path) {
  const out = [];
  const add = (ok, label, detail) => out.push({ ok, label, detail });
  const rec = await getJSON(path);
  const logKey = await loadKey(`keys/logs/${rec.log}.vkey`);
  const witKey = await loadKey('keys/witness/auditor.vkey');
  const note = parseNote(rec.checkpoint.note);

  add(logKey.name === rec.origin && await verifyLogSig(note, logKey), t('check.logsig'), logKey.name);
  const time = await verifyCosig(note, witKey);
  add(time != null && new Date(time * 1000).toISOString().replace('.000Z', 'Z') === rec.witnessedAt, t('check.cosig'), `${witKey.name} · ${rec.witnessedAt}`);
  const head = parseCheckpoint(note.body);
  add(head.origin === rec.origin && head.size === rec.checkpoint.size && head.root === rec.checkpoint.root, t('check.head'), `${head.size} · ${head.root}`);

  if (!rec.previous) {
    add(rec.consistency.length === 0, t('check.first'));
  } else {
    const prev = await getJSON(rec.previous.record);
    const sameHead = prev.checkpoint.size === rec.previous.size && prev.checkpoint.root === rec.previous.root;
    const ok = sameHead && await verifyConsistency(rec.previous.size, rec.checkpoint.size,
      fromB64(rec.previous.root), fromB64(rec.checkpoint.root), rec.consistency.map(fromB64));
    add(ok, t('check.consistency'), `${rec.previous.size} → ${rec.checkpoint.size}`);
  }
  return out;
}

/** RFC 8785 for the subject: only ASCII strings, integers, objects, null. */
function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
}

async function checkTimestamp(path) {
  const out = [];
  const add = (ok, label, detail) => out.push({ ok, label, detail });
  const rec = await getJSON(path);

  const imprint = await sha256Hex(enc.encode(jcs(rec.subject)));
  add(imprint === rec.imprint, t('check.imprint'), imprint);

  for (const [log, s] of Object.entries(rec.subject.logs).sort()) {
    const bytes = await getBytes(s.record);
    const w = JSON.parse(dec.decode(bytes));
    add(await sha256Hex(bytes) === s.sha256 && w.checkpoint.size === s.size && w.checkpoint.root === s.root,
      t('check.subject', { log, size: s.size }), s.record);
  }
  if (rec.subject.prev) {
    add(await sha256Hex(await getBytes(rec.subject.prev.record)) === rec.subject.prev.sha256, t('check.prev'), rec.subject.prev.record);
  } else {
    add(true, t('check.prev'), t('hourly.link.first'));
  }
  if (rec.token) {
    add(await sha256Hex(await getBytes(rec.token.file)) === rec.token.sha256, t('check.token'), `${rec.token.file} (TSA signature: openssl)`);
  }
  return out;
}

async function checkFinding(path) {
  const out = [];
  const add = (ok, label, detail) => out.push({ ok, label, detail });
  const f = await getJSON(path);
  const logKey = await loadKey(`keys/logs/${logOf(path)}.vkey`);
  const witKey = await loadKey('keys/witness/auditor.vkey');

  const observed = parseNote(f.observed.note);
  add(await verifyLogSig(observed, logKey), t('check.observed'), `${f.observed.size} · ${f.observed.root}`);
  const witnessed = parseNote(f.witnessed.note);
  add(await verifyLogSig(witnessed, logKey) && (await verifyCosig(witnessed, witKey)) != null, t('check.witnessed'), `${f.witnessed.size} · ${f.witnessed.root}`);

  const o = parseCheckpoint(observed.body);
  const w = parseCheckpoint(witnessed.body);
  const conflict = {
    equivocation: () => o.size === w.size && o.root !== w.root,
    rollback: () => o.size < w.size,
    inconsistent: async () => o.size > w.size &&
      !(await verifyConsistency(w.size, o.size, fromB64(w.root), fromB64(o.root), f.consistency.map(fromB64))),
  }[f.kind];
  add(!!conflict && await conflict(), t('check.conflict'), f.kind);
  return out;
}

/** Runs the checks for a selection {kind, path}; returns [{ok, label, detail}]. */
export async function checkSelection(sel) {
  const run = { witness: checkWitness, timestamp: checkTimestamp, finding: checkFinding }[sel.kind];
  return run(sel.path);
}

