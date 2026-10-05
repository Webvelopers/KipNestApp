import http from 'node:http';
import https from 'node:https';
import { createWriteStream } from 'node:fs';
import { mkdir, open, readFile, readdir, realpath, rm, rename, stat, utimes, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import Busboy from 'busboy';
import { fileTypeFromBuffer } from 'file-type';
import {
  CryptoError, MAX_ENCRYPTED_FILE_BYTES, createKeyring, createRestEncryptor, createUploadDecryptor,
  deriveTokenKey, downloadLayout, encryptDownload, fromBase64Url, maxUploadBytes, openMetadata,
  openRestFile, openSession, requestAuthKey, restFileSize, sealJson, sealMetadata, toBase64Url,
  REQUEST_WINDOW_MS, verifyClientProof, verifyRequestMac,
} from './crypto.js';
import { describeAction, describeOutcome } from './log.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
export const TYPES = new Map([
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.pdf', 'application/pdf'],
  ['.txt', 'text/plain'],
]);
// The web root is the build output of `vite build` (vite.config.js) and the
// only folder the server serves files from. Code, .env, certs/ and the stored
// files all live outside it.
export const WEB_ROOT = path.join(ROOT, 'dist', 'client');
// The only file types the web root may contain. Anything else found there
// (source maps, JSON manifests, dotfiles, symlinks) is never served, and
// scripts/check-dist.js makes `npm run build` fail on it.
export const STATIC_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.ico', 'image/x-icon'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json'],
]);
// Request paths that never reach routing: a segment starting with a dot,
// backslashes, empty segments, and encoded dots, slashes, backslashes, or NUL.
const SUSPICIOUS_PATH = /(?:^|\/)\.|\\|\/\/|%(?:2e|2f|5c|00)|\0/i;
// Stored files are only ever encrypted: <uuid>.bin (content) + <uuid>.meta (details).
const UUID = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}';
const STORED = new RegExp(`^(${UUID})\\.bin$`);
const METADATA = new RegExp(`^(${UUID})\\.meta$`);
const LEGACY = new RegExp(`^${UUID}\\.(png|jpe?g|pdf|txt|json)$`);
const FILE_ROUTE = new RegExp(`^/api/files/(${UUID})(?:/(preview|download))?$`);
const SNIFF_BYTES = 4100; // Enough for file-type to recognize PNG, JPEG and PDF.
const METADATA_ESTIMATE = 1024; // Room kept for a file's encrypted details (.meta) when checking the quota.

/** Whether a path inside the web root (relative, with / separators) may be served. */
export function isPublicFile(relative) {
  const segments = relative.split('/');
  // Plain names only: no dotfiles or dot folders, no spaces, no traversal.
  if (!segments.every((segment) => /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(segment))) return false;
  return STATIC_TYPES.has(path.extname(segments.at(-1)).toLowerCase());
}

/** Whether `child` is `parent` or inside it (case-insensitive on Windows). */
function isInside(child, parent) {
  const fold = (value) => process.platform === 'win32' ? value.toLowerCase() : value;
  const relative = path.relative(fold(parent), fold(child));
  return relative === '' || (relative.split(path.sep)[0] !== '..' && !path.isAbsolute(relative));
}

/**
 * The canonical path of `target`, even when it does not exist yet: the nearest
 * existing ancestor is resolved (links, junctions, Windows 8.3 short names such
 * as RUNNER~1) and the missing part is appended. Comparing an unresolved path
 * with a resolved one would let a link hide an overlap.
 */
async function resolveReal(target) {
  const missing = [];
  let current = path.resolve(target);
  for (;;) {
    try {
      return path.join(await realpath(current), ...missing);
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return path.resolve(target); // Nothing exists, not even the root.
      missing.unshift(path.basename(current));
      current = parent;
    }
  }
}

/**
 * Reads every servable file of the web root into memory, keyed by URL path.
 * Requests are answered from this map only, so no request ever builds a
 * filesystem path. Symlinks and anything isPublicFile() rejects are skipped.
 */
export async function loadWebRoot(webRoot) {
  const files = new Map();
  async function walk(directory, prefix) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relative = prefix + entry.name;
      if (entry.isDirectory() && isPublicFile(`${relative}/x.html`)) {
        await walk(path.join(directory, entry.name), `${relative}/`);
      } else if (entry.isFile() && isPublicFile(relative)) {
        const type = STATIC_TYPES.get(path.extname(entry.name).toLowerCase());
        files.set(`/${relative}`, { body: await readFile(path.join(directory, entry.name)), type });
      } else {
        console.warn(`Web root: not serving ${relative}`);
      }
    }
  }
  try {
    await walk(webRoot, '');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const index = files.get('/index.html');
  if (!index) throw new Error(`The web root ${webRoot} has no index.html. Run npm run build first.`);
  files.delete('/index.html'); // One address for the page: /.
  files.set('/', index);
  return files;
}
// Stored files all carry the same timestamp, so the file system does not
// reveal when something was uploaded (the real date is in the encrypted details).
const STORED_TIME = new Date('2000-01-01T00:00:00Z');

export async function hideTimestamps(...paths) {
  for (const filePath of paths) await utimes(filePath, STORED_TIME, STORED_TIME);
}

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function json(res, status, data) {
  const body = Buffer.from(JSON.stringify(data));
  // An explicit length also lets the request log record the real size.
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length });
  res.end(body);
}

/** Headers sent on every response, whatever the route or outcome. */
function setSecurityHeaders(res, hsts) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // No other site may open this page in a shared window or embed its responses.
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  // Browsers must never fall back to plain HTTP for this site.
  if (hsts) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}

/** Writes one line per finished request to the console and, when set, the log file. */
function logWhenFinished(req, res, requestId, log) {
  const startedAt = Date.now();
  // Read once, now: by the time an aborted or rejected request finishes, its
  // socket can already be gone (req.socket is null).
  const ip = req.socket?.remoteAddress || 'unknown';
  res.on('finish', () => {
    // Logging must never be able to take the server down.
    try {
      const pathname = new URL(req.url, 'http://localhost').pathname;
      // Never log credentials or headers: only these fields are written.
      const entry = {
        requestId,
        action: describeAction(req.method, pathname),
        outcome: describeOutcome(res.statusCode),
        method: req.method,
        path: pathname,
        status: res.statusCode,
        durationMs: Date.now() - startedAt,
        // Body size sent; HEAD answers carry the length but no body.
        bytes: req.method === 'HEAD' ? 0 : Number(res.getHeader('Content-Length')) || 0,
        ip,
      };
      console.log(JSON.stringify({ time: new Date().toISOString(), ...entry }));
      log?.write(entry);
    } catch (error) {
      console.error(`Request log failed: ${error.message}`);
    }
  });
}

const WINDOWS_RESERVED =/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;

export function safeName(name) {
  let cleaned = path.posix.basename(name.replaceAll('\\', '/'))
    // NFC so visually identical names compare equal and metadata is stable.
    .normalize('NFC')
    // eslint-disable-next-line no-control-regex -- strips control characters on purpose
    .replace(/[\x00-\x1f\x7f‪-‮⁦-⁩]/g, '')
    .trim();
  // Trailing dots and spaces are silently stripped by Windows file systems and
  // can turn a saved file into something else when restored from metadata.
  cleaned = cleaned.replace(/[. ]+$/, '') || 'file';
  if (WINDOWS_RESERVED.test(cleaned)) cleaned = `_${cleaned}`;
  if (cleaned.length <= 180) return cleaned;
  // Long names keep their extension (it decides the allowed type), and the cut
  // never splits an emoji or other character made of two UTF-16 units.
  const extension = path.extname(cleaned).length <= 16 ? path.extname(cleaned) : '';
  return cleaned.slice(0, 180 - extension.length).replace(/[\uD800-\uDBFF]$/, '').replace(/[. ]+$/, '') + extension;
}

/**
 * Checks content signatures on the decrypted stream, so plaintext never has to
 * touch the disk. `context.extension` is read lazily: for uploads it is only
 * known once the encrypted header has been opened.
 */
export function createValidator(context) {
  const textError = () => new HttpError(415, 'The TXT file must be UTF-8 text without binary content.');
  let head = [];
  let headLength = 0;
  let sniffed = false;
  let decoder;

  async function sniff(buffer) {
    let detected;
    try {
      detected = await fileTypeFromBuffer(buffer);
    } catch {
      throw new HttpError(415, 'The file content is not valid.');
    }
    if (detected?.mime !== TYPES.get(context.extension)) {
      throw new HttpError(415, 'The file content does not match its extension.');
    }
  }

  return new Transform({
    async transform(chunk, encoding, callback) {
      try {
        if (context.extension === '.txt') {
          decoder ||= new TextDecoder('utf-8', { fatal: true });
          let decoded;
          try {
            // stream:true keeps UTF-8 characters split across two chunks.
            decoded = decoder.decode(chunk, { stream: true });
          } catch {
            throw textError();
          }
          // eslint-disable-next-line no-control-regex -- rejects binary control characters on purpose
          if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(decoded)) throw textError();
          callback(null, chunk);
          return;
        }
        if (sniffed) {
          callback(null, chunk);
          return;
        }
        head.push(chunk);
        headLength += chunk.length;
        if (headLength < SNIFF_BYTES) {
          callback();
          return;
        }
        const buffer = Buffer.concat(head);
        head = null;
        await sniff(buffer);
        sniffed = true;
        callback(null, buffer);
      } catch (error) {
        callback(error);
      }
    },
    async flush(callback) {
      try {
        if (context.extension === '.txt') {
          try {
            decoder?.decode(); // Also rejects UTF-8 sequences truncated at the end.
          } catch {
            throw textError();
          }
        } else if (!sniffed) {
          const buffer = Buffer.concat(head);
          await sniff(buffer);
          this.push(buffer);
        }
        callback();
      } catch (error) {
        callback(error);
      }
    },
  });
}

// An upload can be rejected early (for example, as soon as its encrypted header
// shows the file is too big) while the browser is still sending. Discarding the
// rest before answering lets the browser read the real error instead of seeing
// a reset connection. Bounded by a short wait and by `maxBytes` (the request
// size check already bounds authenticated uploads).
async function drain(req, { ms = 10_000, maxBytes = Infinity } = {}) {
  if (req.complete || req.destroyed || req.readableEnded) return;
  await new Promise((resolve) => {
    let received = 0;
    const timer = setTimeout(done, ms);
    function onData(chunk) {
      received += chunk.length;
      if (received > maxBytes) done(); // Too much to read for free: the connection is closed instead.
    }
    function done() {
      clearTimeout(timer);
      req.off('data', onData);
      resolve();
    }
    req.on('data', onData);
    req.once('end', done);
    req.once('close', done);
    req.once('error', done);
    req.resume();
  });
}
// Rejected uploads without a valid signature (for example, an expired session)
// are read this far, so the browser gets the 401 instead of a reset connection.
const UNAUTHENTICATED_DRAIN_BYTES = 1024 * 1024;

/**
 * One brute-force counter per client, not per spelling of its address:
 * IPv4-mapped IPv6 (::ffff:1.2.3.4) counts as IPv4, and IPv6 is grouped by
 * /64, because one home or office network usually owns a whole /64.
 */
export function normalizeAddress(address = '') {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (mapped) return mapped[1];
  if (!net.isIPv6(address)) return address || 'unknown';
  const plain = address.split('%')[0].toLowerCase();
  const [head, tail] = plain.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = plain.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return `${groups.slice(0, 4).map((group) => group.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

// Small JSON bodies only (the session handshake). File content never goes through here.
async function readJson(req, limit = 2048) {
  const parts = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > limit) throw new HttpError(413, 'The request exceeds the allowed size.');
    parts.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(parts).toString('utf8'));
  } catch {
    throw new HttpError(400, 'The request body must be JSON.');
  }
}

export async function createApp({
  token,
  storageKey,
  previousStorageKeys = [],
  kdfSalt,
  kdfIterations = 600_000,
  uploadDir = path.join(ROOT, 'storage', 'uploads'),
  webRoot = WEB_ROOT,
  privatePaths = [], // Extra paths (TLS key, .env) that must stay outside the web root.
  log = null, // Optional interaction log ({ dir, write(entry) }, see log.js); the console always gets every line.
  maxFileBytes = MAX_FILE_BYTES,
  maxTotalBytes = MAX_TOTAL_BYTES,
  uploadTimeoutMs = 300_000,
  maxConcurrentUploads = 1,
  maxFiles = 1000,
  tls,
  hsts = Boolean(tls), // Also set it behind a TLS-terminating reverse proxy.
  authBlockMs = 60_000, // First brute-force block; later blocks double.
  handshakesPerMinute = 30,
} = {}) {
  if (!token) throw new Error('An access token is required.');
  if (!Buffer.isBuffer(storageKey) || storageKey.length !== 32) throw new Error('storageKey must be a 32-byte Buffer.');
  if (!Array.isArray(previousStorageKeys) || previousStorageKeys.some((key) => !Buffer.isBuffer(key) || key.length !== 32)) {
    throw new Error('previousStorageKeys must be 32-byte Buffers.');
  }
  if (!Buffer.isBuffer(kdfSalt) || kdfSalt.length !== 16) throw new Error('kdfSalt must be a 16-byte Buffer.');
  if (!Number.isSafeInteger(kdfIterations) || kdfIterations < 1000 || kdfIterations > 10_000_000) {
    throw new Error('kdfIterations must be an integer between 1000 and 10000000.');
  }
  for (const [name, value] of Object.entries({ maxFileBytes, maxTotalBytes, uploadTimeoutMs })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer.`);
  }
  if (maxFileBytes > MAX_ENCRYPTED_FILE_BYTES || uploadTimeoutMs > 2_147_000_000) {
    throw new Error('The file size limit or timeout is too large.');
  }
  if (!Number.isSafeInteger(maxConcurrentUploads) || maxConcurrentUploads < 1 || maxConcurrentUploads > 16) {
    throw new Error('maxConcurrentUploads must be an integer between 1 and 16.');
  }
  // Bounded so a listing (every .meta is decrypted) stays fast.
  if (!Number.isSafeInteger(maxFiles) || maxFiles < 1 || maxFiles > 1_000_000) {
    throw new Error('maxFiles must be an integer between 1 and 1000000.');
  }
  if (!Number.isSafeInteger(authBlockMs) || authBlockMs < 1 || !Number.isSafeInteger(handshakesPerMinute) || handshakesPerMinute < 1) {
    throw new Error('authBlockMs and handshakesPerMinute must be positive integers.');
  }
  // Nothing private may be inside the web root, and the web root may not be
  // inside a private folder (for example the upload folder).
  const privateTargets = [
    uploadDir, ...privatePaths, ...(log?.dir ? [log.dir] : []),
    ...['.env', 'certs', 'src/server', 'scripts', 'test', 'node_modules', 'server.js', 'package.json'].map((name) => path.join(ROOT, name)),
  ];
  async function checkOverlap() {
    const realWebRoot = await resolveReal(webRoot);
    for (const target of await Promise.all(privateTargets.map(resolveReal))) {
      if (isInside(target, realWebRoot) || isInside(realWebRoot, target)) {
        throw new Error(`The web root (${webRoot}) and ${target} overlap. Keep private files outside the web root.`);
      }
    }
  }
  await checkOverlap(); // Before creating anything.
  const webFiles = await loadWebRoot(webRoot);
  await mkdir(uploadDir, { recursive: true, mode: 0o700 });
  await checkOverlap(); // Again with the real upload folder, in case it is a link or junction.
  const keyring = createKeyring(storageKey, previousStorageKeys);
  // Startup checks. Plaintext files from older versions must be migrated
  // first; the server never serves or lists them.
  const leftovers = await readdir(uploadDir);
  if (leftovers.some((name) => LEGACY.test(name))) {
    throw new Error('The upload folder still contains unencrypted files from an older version. Run npm run encrypt:migrate before starting the server.');
  }
  // Remove unfinished temporaries (.part) and orphaned halves (content without
  // details, or the reverse) so the quota stays accurate.
  for (const name of leftovers) {
    const stored = STORED.exec(name);
    const metadata = METADATA.exec(name);
    let orphan = false;
    if (name.endsWith('.part')) orphan = true;
    else if (stored) orphan = !leftovers.includes(`${stored[1]}.meta`);
    else if (metadata) orphan = !leftovers.includes(`${metadata[1]}.bin`);
    if (!orphan) continue; // Never touch unknown files.
    await rm(path.join(uploadDir, name), { force: true });
    console.log(`Startup cleanup: removed ${name}`);
    log?.write({ event: 'cleanup', removed: name });
  }
  // The token never travels: browsers prove they know this derived key instead.
  const tokenKey = await deriveTokenKey(token, kdfSalt, kdfIterations);
  let uploading = 0;
  // Quota accounting in memory, so concurrent uploads cannot each pass a check
  // made against the same stale disk usage. `storedBytes` is resynced from
  // disk whenever an upload starts with no other upload running.
  let storedBytes = 0; // Committed .bin + .meta files.
  let reservedBytes = 0; // Expected encrypted size of the uploads in progress.

  // Secure sessions from the handshake live only in memory: a restart simply
  // makes the browser open a new one.
  const sessions = new Map();
  const SESSION_TTL_MS = Math.max(15 * 60_000, uploadTimeoutMs + 60_000);
  const SESSION_MAX_AGE_MS = 12 * 60 * 60_000; // Even an active session is renewed twice a day.
  const MAX_SESSIONS = 1000;
  const MAX_NONCES_PER_SESSION = 10_000;
  const sessionExpired = () => new HttpError(401, 'Your secure session expired. Unlock again to continue.', 'session');
  function pruneSessions() {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (session.expiresAt <= now || session.createdAt + SESSION_MAX_AGE_MS <= now) sessions.delete(id);
    }
  }
  function findSession(id) {
    pruneSessions();
    const session = sessions.get(id);
    if (!session) throw sessionExpired();
    return session;
  }
  function touchSession(session) {
    session.expiresAt = Date.now() + SESSION_TTL_MS; // Sliding expiry while in use.
    // Re-insert so the Map stays ordered from least to most recently used.
    sessions.delete(session.id);
    sessions.set(session.id, session);
  }
  /**
   * Every API request after the handshake is signed with the session's request
   * key: X-Session-Id, X-Request-Time, and X-Request-Mac over method, path,
   * and time. An unknown session asks the browser for a new handshake (not
   * counted as a failure); a bad signature counts toward the brute-force block.
   */
  function authenticate(req, res, address) {
    const id = req.headers['x-session-id'];
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(id)) throw sessionExpired();
    const session = findSession(id);
    const { pathname, search } = new URL(req.url, 'http://localhost');
    const nonce = req.headers['x-request-nonce'];
    const valid = verifyRequestMac(session.requestKey, {
      method: req.method,
      target: pathname + search,
      time: req.headers['x-request-time'],
      nonce,
      downloadNonce: req.headers['x-download-nonce'] ?? '',
      range: req.headers.range ?? '',
      mac: req.headers['x-request-mac'],
    });
    if (!valid) {
      // A blocked address cannot keep guessing; a valid signature is never
      // blocked, so an attacker sharing the owner's address cannot lock out
      // an open session.
      rejectIfBlocked(res, address);
      registerFailure(address);
      throw new HttpError(401, 'This request could not be verified.');
    }
    // Each signed request is accepted once: a captured one cannot be replayed.
    const now = Date.now();
    for (const [used, expires] of session.usedNonces) {
      if (expires > now) break; // Insertion order is time order.
      session.usedNonces.delete(used);
    }
    if (session.usedNonces.has(nonce)) throw new HttpError(401, 'This request was already used.');
    if (session.usedNonces.size >= MAX_NONCES_PER_SESSION) throw sessionExpired();
    session.usedNonces.set(nonce, now + 2 * REQUEST_WINDOW_MS);
    touchSession(session);
    return session;
  }

  function rejectIfBlocked(res, address) {
    const blocked = blockedFor(address);
    if (!blocked) return;
    res.setHeader('Retry-After', String(Math.ceil(blocked / 1000)));
    throw new HttpError(429, 'Too many failed attempts. Try again later.');
  }

  // Brute-force protection: 10 failed proofs within the window block the
  // address; each new block doubles (1 min, 2 min, 4 min, … up to 1 h) until
  // the address stays clean for a day. Counters are in-memory only.
  const failedAttempts = new Map();
  const MAX_ATTEMPTS = 10;
  const MAX_BLOCK_MS = 60 * 60_000;
  const STRIKE_MEMORY_MS = 24 * 60 * 60_000;
  function clientAddress(req) {
    return normalizeAddress(req.socket?.remoteAddress);
  }
  /** Milliseconds left in the address's current block (0 when not blocked). */
  function blockedFor(address) {
    const entry = failedAttempts.get(address);
    if (!entry?.until) return 0;
    const left = entry.until - Date.now();
    if (left > 0) return left;
    entry.until = 0; // Block over; the strike count is kept for escalation.
    return 0;
  }
  function registerFailure(address) {
    const now = Date.now();
    const entry = failedAttempts.get(address) || { count: 0, first: now, strikes: 0, lastStrike: 0, until: 0 };
    if (now - entry.first > authBlockMs) { // Sliding window: old failures expire.
      entry.count = 0;
      entry.first = now;
    }
    entry.count += 1;
    if (entry.count >= MAX_ATTEMPTS) {
      if (now - entry.lastStrike > STRIKE_MEMORY_MS) entry.strikes = 0;
      entry.strikes += 1;
      entry.lastStrike = now;
      entry.until = now + Math.min(authBlockMs * 2 ** (entry.strikes - 1), MAX_BLOCK_MS);
      entry.count = 0;
      entry.first = now;
    }
    failedAttempts.set(address, entry);
    if (failedAttempts.size > 10_000) { // Bound memory against address spoofing floods.
      // Drop the oldest entry that is not currently blocked (one linear scan).
      let oldest;
      for (const [key, value] of failedAttempts) {
        if (value.until > now) continue;
        if (!oldest || value.first < oldest[1].first) oldest = [key, value];
      }
      if (oldest) failedAttempts.delete(oldest[0]);
    }
  }
  function registerSuccess(address) {
    failedAttempts.delete(address);
  }

  // Handshakes are cheap to request but create server state, so each address
  // gets a small budget per minute (one token holder cannot flood the table).
  const handshakes = new Map();
  function allowHandshake(address) {
    const now = Date.now();
    const recent = (handshakes.get(address) || []).filter((time) => now - time < 60_000);
    const allowed = recent.length < handshakesPerMinute;
    if (allowed) recent.push(now);
    handshakes.delete(address);
    handshakes.set(address, recent);
    if (handshakes.size > 10_000) handshakes.delete(handshakes.keys().next().value);
    return allowed;
  }
  // A captured handshake cannot be replayed: each proof is accepted once
  // while its timestamp is still fresh.
  const usedProofs = new Map();
  function claimProof(proof) {
    const now = Date.now();
    for (const [key, expires] of usedProofs) if (expires <= now) usedProofs.delete(key);
    const key = proof.toString('hex');
    if (usedProofs.has(key)) return false;
    usedProofs.set(key, now + 10 * 60_000);
    return true;
  }

  // Sums every entry so orphaned files cannot bypass the quota. A file that
  // disappears between readdir and stat (a concurrent delete, or an antivirus
  // scanner's short-lived marker on Windows) simply no longer counts.
  async function directoryUsage() {
    const entries = await readdir(uploadDir);
    const sizes = await Promise.all(entries.map(async (name) => {
      try {
        return (await stat(path.join(uploadDir, name))).size;
      } catch (error) {
        if (error.code === 'ENOENT') return 0;
        throw error;
      }
    }));
    return { entries, usedBytes: sizes.reduce((sum, size) => sum + size, 0) };
  }

  async function storageUsage() {
    const { entries, usedBytes } = await directoryUsage();
    return { files: entries.filter((name) => METADATA.test(name)).length, usedBytes };
  }

  async function readMetadata(id) {
    const metadata = openMetadata(keyring, id, await readFile(path.join(uploadDir, `${id}.meta`)));
    const extension = path.extname(metadata.name).toLowerCase();
    if (!TYPES.has(extension) || TYPES.get(extension) !== metadata.type) throw new CryptoError();
    return metadata;
  }

  async function listFiles() {
    const entries = await readdir(uploadDir);
    const files = [];
    for (const name of entries) {
      const match = METADATA.exec(name);
      if (!match) continue;
      try {
        files.push(await readMetadata(match[1]));
      } catch (error) {
        if (!(error instanceof CryptoError) && error.code !== 'ENOENT') throw error;
        console.warn(`Skipping ${name}: its details could not be decrypted.`);
        log?.write({ event: 'integrity', file: name, message: 'details could not be decrypted' });
      }
    }
    return files.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  // Streams one encrypted upload: busboy → transit decrypt → validation →
  // rest encryption → <id>.part. Plaintext only exists in memory, chunk by chunk.
  async function receiveFile(req, { id, temporaryPath, reserve, session: authSession }) {
    const sizeError = () => new HttpError(413, `The file exceeds the limit of ${maxFileBytes / 1024 / 1024} MB.`);
    const encryptedLimit = maxUploadBytes(maxFileBytes);
    let parser;
    try {
      parser = Busboy({
        headers: req.headers,
        defParamCharset: 'utf8',
        limits: { fileSize: encryptedLimit + 1, files: 1, fields: 0, parts: 2, headerPairs: 100 },
      });
    } catch {
      throw new HttpError(400, 'Use multipart/form-data with the archivo field.');
    }

    let uploaded;
    let failure;
    let writeTask = Promise.resolve();
    let bytes = 0;
    const fail = (error) => { failure ||= error; };
    const onData = (chunk) => {
      bytes += chunk.length;
      if (bytes > encryptedLimit + 64 * 1024) {
        parser.destroy(new HttpError(413, 'The request exceeds the allowed size.'));
      }
    };
    const onAborted = () => parser.destroy(new HttpError(400, 'The upload was interrupted.'));

    try {
      await new Promise((resolve, reject) => {
        parser.on('file', (field, stream) => {
          if (field !== 'archivo') {
            fail(new HttpError(400, 'Select a PNG, JPG, PDF or TXT file in the archivo field.'));
            stream.resume();
            return;
          }
          const context = {};
          const decryptor = createUploadDecryptor({
            resolveSession(sessionId, fileNonce) {
              // The body must be encrypted for the very session that signed the request.
              if (toBase64Url(sessionId) !== authSession.id) throw new CryptoError();
              const nonce = fileNonce.toString('hex');
              if (authSession.nonces.has(nonce)) throw new HttpError(400, 'This upload was already received.');
              // Bounded memory: a very busy session simply has to open a new one.
              if (authSession.nonces.size >= MAX_NONCES_PER_SESSION) throw sessionExpired();
              authSession.nonces.add(nonce);
              return authSession.key;
            },
            onHeader({ name: rawName, size }) {
              const name = safeName(rawName);
              const extension = path.extname(name).toLowerCase();
              if (!TYPES.has(extension)) throw new HttpError(400, 'Select a PNG, JPG, PDF or TXT file in the archivo field.');
              if (!size) throw new HttpError(400, 'Empty files are not allowed.');
              if (size > maxFileBytes) throw sizeError();
              // Reject before storing anything if the encrypted file cannot fit.
              reserve(restFileSize(size) + METADATA_ESTIMATE);
              context.extension = extension;
              uploaded = { name, extension, size };
            },
          });
          stream.on('limit', () => fail(sizeError()));
          writeTask = pipeline(
            stream,
            decryptor,
            createValidator(context),
            createRestEncryptor({ id, keyring }),
            createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 }),
          ).catch((error) => {
            const reason = error instanceof CryptoError ? new HttpError(400, 'The upload could not be verified.') : error;
            fail(reason);
            parser.destroy(reason);
          });
        });
        parser.on('filesLimit', () => fail(new HttpError(400, 'Only one file per upload is allowed.')));
        parser.on('fieldsLimit', () => fail(new HttpError(400, 'Additional fields are not allowed.')));
        parser.on('partsLimit', () => fail(new HttpError(400, 'The request contains too many parts.')));
        parser.on('error', (error) => {
          req.unpipe(parser);
          req.resume();
          reject(error instanceof HttpError ? error : new HttpError(400, 'Form is incomplete or invalid.'));
        });
        parser.on('close', resolve);
        req.on('data', onData);
        req.on('aborted', onAborted);
        req.on('error', onAborted);
        req.pipe(parser);
      });
    } finally {
      req.off('data', onData);
      req.off('aborted', onAborted);
      req.off('error', onAborted);
      await writeTask;
    }
    if (failure) throw failure;
    if (!uploaded) throw new HttpError(400, 'No file was received.');
    return uploaded;
  }

  // ---------------------------------------------------------------------------
  // Route handlers. Each one answers a single route; expected failures are
  // thrown as HttpError and turned into JSON by the dispatcher below.

  /** POST /api/session: the handshake that opens a secure session. */
  async function handleSession(req, res, address) {
    rejectIfBlocked(res, address);
    if (!allowHandshake(address)) {
      res.setHeader('Retry-After', '60');
      throw new HttpError(429, 'Too many sign-ins. Try again in a minute.');
    }
    const body = await readJson(req);
    let clientPublicKey;
    let proof;
    try {
      clientPublicKey = fromBase64Url(body?.publicKey, 65);
      proof = fromBase64Url(body?.proof, 32);
    } catch {
      throw new HttpError(400, 'The secure session could not be opened.');
    }
    // The browser proves it knows the token key; the token itself never travels.
    if (!verifyClientProof(tokenKey, clientPublicKey, body?.timestamp, proof)) {
      registerFailure(address);
      throw new HttpError(401, 'Incorrect or missing access token.');
    }
    if (!claimProof(proof)) throw new HttpError(400, 'This sign-in was already used.');
    registerSuccess(address);
    let opened;
    try {
      opened = openSession(tokenKey, clientPublicKey);
    } catch (error) {
      if (error instanceof CryptoError) throw new HttpError(400, 'The secure session could not be opened.');
      throw error;
    }
    pruneSessions();
    if (sessions.size >= MAX_SESSIONS) {
      sessions.delete(sessions.keys().next().value); // Least recently used first.
    }
    const id = toBase64Url(opened.id);
    sessions.set(id, {
      id, key: opened.key, requestKey: requestAuthKey(opened.key), createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS, nonces: new Set(), usedNonces: new Map(),
    });
    json(res, 201, {
      sessionId: id,
      publicKey: toBase64Url(opened.serverPublicKey),
      salt: toBase64Url(opened.salt),
      proof: toBase64Url(opened.proof),
      expiresIn: Math.floor(SESSION_TTL_MS / 1000),
    });
  }

  /** DELETE /api/files/<id> */
  async function handleDelete(res, id) {
    try {
      await stat(path.join(uploadDir, `${id}.meta`));
    } catch (error) {
      if (error.code === 'ENOENT') throw new HttpError(404, 'File not found.');
      throw error;
    }
    let freed = 0;
    // Details first: if the process stops in between, the leftover .bin
    // is never listed and startup cleanup removes it.
    for (const name of [`${id}.meta`, `${id}.bin`]) {
      const target = path.join(uploadDir, name);
      freed += await stat(target).then((info) => info.size, () => 0);
      await rm(target, { force: true });
    }
    storedBytes = Math.max(0, storedBytes - freed); // Frees the quota for uploads already running.
    json(res, 200, { message: 'File deleted.', id });
  }

  /**
   * Parses a Range header against the encrypted body size. Returns
   * { start, end, partial }, or null when the range cannot be satisfied.
   * Only a single range is supported: bytes=start-end, bytes=start-, bytes=-N.
   */
  function parseRange(range, total) {
    let start = 0;
    let end = total - 1;
    if (!range) return { start, end, partial: false };
    const match = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    const from = match ? Number(match[1]) : NaN;
    const to = match && match[2] !== '' ? Number(match[2]) : end;
    if (!match || Number.isNaN(from) || (match[1] === '' && match[2] === '')
      || from > to || from >= total || (match[1] === '' && Number(match[2]) === 0)) {
      return null;
    }
    if (match[1] === '') { // Suffix range: bytes=-N returns the last N bytes.
      const length = Math.min(Number(match[2]), total);
      start = total - length;
    } else {
      start = from;
      end = Math.min(to, end);
    }
    return { start, end, partial: true };
  }

  /** GET /api/files/<id>/download and /preview: the stored file re-encrypted for the session (KND1). */
  async function handleFileStream(req, res, session, id, purpose) {
    const download = purpose === 'download';
    let nonce;
    try {
      nonce = fromBase64Url(req.headers['x-download-nonce'], 16);
    } catch {
      throw new HttpError(400, 'A download nonce is required.');
    }
    const notFound = download ? 'File not found.' : 'Image not found.';
    let handle;
    try {
      let metadata;
      try {
        metadata = await readMetadata(id);
      } catch (error) {
        if (error instanceof CryptoError) throw new HttpError(404, notFound);
        throw error;
      }
      if (!download && !['image/png', 'image/jpeg'].includes(metadata.type)) {
        throw new HttpError(415, 'Previews are only available for PNG and JPG images.');
      }
      handle = await open(path.join(uploadDir, `${id}.bin`), 'r');
      let rest;
      try {
        rest = await openRestFile(handle, { id, size: metadata.size, keyring });
      } catch (error) {
        if (error instanceof CryptoError) throw new HttpError(404, notFound);
        throw error;
      }
      const { total } = downloadLayout(metadata.size);
      // Resumable downloads: a single range over the encrypted body is served
      // as 206. The format is deterministic for a given nonce, so the browser
      // can resume from its last verified record.
      const range = parseRange(download ? req.headers.range : undefined, total);
      if (!range) {
        res.writeHead(416, { 'Content-Range': `bytes */${total}` });
        res.end();
        return;
      }
      const { start, end, partial } = range;
      res.writeHead(partial ? 206 : 200, {
        // Only KipNest can turn this back into the original file: the name,
        // type and content are all inside the encrypted body.
        'Content-Type': 'application/octet-stream',
        'Content-Length': end - start + 1,
        'Content-Disposition': `attachment; filename="${id}.knd"`,
        ...(download ? { 'Accept-Ranges': 'bytes' } : {}),
        ...(partial ? { 'Content-Range': `bytes ${start}-${end}/${total}` } : {}),
      });
      await pipeline(Readable.from(encryptDownload({
        rest, metadata, purpose, sessionKey: session.key, nonce, start, end,
      })), res);
    } catch (error) {
      if (error.code === 'ENOENT') throw new HttpError(404, notFound);
      if (error instanceof CryptoError && res.headersSent) {
        console.error(`Stored file ${id} failed verification while downloading.`);
        log?.write({ event: 'integrity', file: id, message: 'failed verification while downloading' });
        res.destroy();
        return;
      }
      if (error.code !== 'ERR_STREAM_PREMATURE_CLOSE') throw error;
    } finally {
      await handle?.close();
    }
  }

  /** POST /api/upload: one encrypted file (KNU1), stored encrypted at rest (KNR1 + KNM1). */
  async function handleUpload(req, res, session, context) {
    if (Number(req.headers['content-length']) > maxUploadBytes(maxFileBytes) + 64 * 1024) {
      throw new HttpError(413, 'The request exceeds the allowed size.');
    }
    context.drainBytes = Infinity; // Authenticated: worth reading to the end so the browser sees the error.
    if (uploading >= maxConcurrentUploads) {
      throw new HttpError(429, `Another upload is in progress. Up to ${maxConcurrentUploads} concurrent ${maxConcurrentUploads === 1 ? 'upload is' : 'uploads are'} allowed. Try again in a few seconds.`);
    }
    uploading += 1;
    const alone = uploading === 1; // No other upload can have files half-written.
    const id = randomUUID();
    const temporaryPath = path.join(uploadDir, `${id}.part`);
    const storedPath = path.join(uploadDir, `${id}.bin`);
    const metadataPath = path.join(uploadDir, `${id}.meta`);
    const temporaryMetadataPath = path.join(uploadDir, `${id}.meta.part`);
    let renamed = false;
    let committed = false;
    let reserved = 0;
    let metadata;
    try {
      const { entries, usedBytes } = await directoryUsage();
      if (alone) storedBytes = usedBytes; // Also picks up files changed outside the server.
      if (storedBytes + reservedBytes >= maxTotalBytes) throw new HttpError(507, 'Storage is full.');
      // Stored files plus the other uploads in progress.
      if (entries.filter((name) => METADATA.test(name)).length + uploading - 1 >= maxFiles) {
        throw new HttpError(507, `You reached the limit of ${maxFiles} files. Delete some files to upload more.`, 'files');
      }
      // Called once the encrypted header reveals the size; synchronous, so
      // the check and the reservation cannot interleave with another upload.
      const reserve = (bytes) => {
        if (storedBytes + reservedBytes + bytes > maxTotalBytes) {
          throw new HttpError(507, 'The file exceeds the available storage quota.');
        }
        reservedBytes += bytes;
        reserved = bytes;
      };
      const file = await receiveFile(req, { id, temporaryPath, reserve, session });
      metadata = { id, name: file.name, size: file.size, type: TYPES.get(file.extension), createdAt: new Date().toISOString() };
      const sealed = sealMetadata(keyring, metadata);
      const stored = (await stat(temporaryPath)).size;
      if (stored !== restFileSize(file.size)) throw new Error('Encrypted file size mismatch.');
      // Exact check with the real details size, against everything else stored or reserved.
      if (storedBytes + reservedBytes - reserved + stored + sealed.length > maxTotalBytes) {
        throw new HttpError(507, 'The file exceeds the available storage quota.');
      }
      await rename(temporaryPath, storedPath);
      renamed = true;
      await writeFile(temporaryMetadataPath, sealed, { flag: 'wx', mode: 0o600 });
      await rename(temporaryMetadataPath, metadataPath);
      await hideTimestamps(storedPath, metadataPath);
      committed = true;
      storedBytes += stored + sealed.length;
    } finally {
      reservedBytes -= reserved;
      try {
        await rm(temporaryPath, { force: true });
        await rm(temporaryMetadataPath, { force: true });
        if (!committed) {
          if (renamed) await rm(storedPath, { force: true });
          await rm(metadataPath, { force: true });
        }
      } finally {
        uploading -= 1;
      }
    }
    // The receipt is encrypted too: it carries the file name.
    json(res, 201, sealJson(session.key, 'receipt', { message: 'File uploaded successfully.', file: metadata }));
  }

  /** Picks the handler for a request. `context.drainBytes` is how much of the body to read and discard on errors. */
  async function route(req, res, context) {
    // Suspicious paths get the same 404 as any unknown resource (no oracle).
    if (SUSPICIOUS_PATH.test(req.url.split('?')[0])) throw new HttpError(404, 'Resource not found.');
    const pathname = new URL(req.url, 'http://localhost').pathname;
    // HEAD behaves like GET for public routes; Node omits the body itself.
    const readOnly = req.method === 'GET' || req.method === 'HEAD';
    // Static files come from memory (loadWebRoot), never from a path built from the request.
    const file = readOnly && webFiles.get(pathname);
    if (file) {
      res.writeHead(200, { 'Content-Type': file.type, 'Content-Length': file.body.length });
      res.end(file.body);
      return;
    }
    if (pathname === '/healthz' && readOnly) {
      json(res, 200, { status: 'ok' });
      return;
    }
    if (!pathname.startsWith('/api/')) throw new HttpError(404, 'Resource not found.');
    // The brute-force block is checked where proofs are verified (sign-in and
    // invalid request signatures), so a blocked address never blocks
    // /api/config or requests correctly signed by an open session.
    const address = clientAddress(req);

    // No cookies are used and CORS is not enabled. Every request carries an explicit proof.
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      throw new HttpError(403, 'Requests from other sites are not allowed.');
    }
    if (pathname === '/api/config' && readOnly) {
      // The KDF salt is not secret: it only makes the token key unique to this
      // installation. The server time lets browsers with a wrong clock sign requests.
      json(res, 200, { maxFileBytes, maxTotalBytes, uploadTimeoutMs, kdf: { salt: toBase64Url(kdfSalt), iterations: kdfIterations }, serverTime: Date.now() });
      return;
    }
    if (pathname === '/api/session' && req.method === 'POST') {
      await handleSession(req, res, address);
      return;
    }

    // An upload rejected by the signature check is still read a little, so the
    // browser can see the 401 (and open a new session) instead of a reset.
    if (pathname === '/api/upload' && req.method === 'POST') context.drainBytes = UNAUTHENTICATED_DRAIN_BYTES;
    // Everything else needs a signed request from an open session.
    const session = authenticate(req, res, address);
    if (pathname === '/api/session' && req.method === 'DELETE') {
      // Sign out: the session stops working right away, not when it expires.
      sessions.delete(session.id);
      json(res, 200, { message: 'Signed out.' });
      return;
    }
    if (pathname === '/api/files' && req.method === 'GET') {
      json(res, 200, sealJson(session.key, 'list', { files: await listFiles() }));
      return;
    }
    if (pathname === '/api/stats' && req.method === 'GET') {
      json(res, 200, sealJson(session.key, 'stats', { ...(await storageUsage()), maxTotalBytes, maxFileBytes }));
      return;
    }
    const fileMatch = FILE_ROUTE.exec(pathname);
    if (fileMatch && req.method === 'DELETE' && !fileMatch[2]) {
      await handleDelete(res, fileMatch[1]);
      return;
    }
    if (fileMatch && req.method === 'GET' && fileMatch[2]) {
      await handleFileStream(req, res, session, fileMatch[1], fileMatch[2]);
      return;
    }
    if (pathname === '/api/upload' && req.method === 'POST') {
      await handleUpload(req, res, session, context);
      return;
    }
    throw new HttpError(404, 'Route or method not available.');
  }

  const createServer = tls ? https.createServer : http.createServer;
  const options = {
    maxHeaderSize: 16 * 1024,
    // Checks for stalled requests every 5 s instead of Node's default 30 s, so
    // slow-header connections are cut close to headersTimeout.
    connectionsCheckingInterval: 5000,
    ...(tls ? { ...tls, minVersion: 'TLSv1.3' } : {}),
  };
  const server = createServer(options, async (req, res) => {
    const requestId = randomUUID();
    const context = { drainBytes: 0 }; // Only uploads are worth draining (see UNAUTHENTICATED_DRAIN_BYTES).
    res.setHeader('X-Request-Id', requestId);
    logWhenFinished(req, res, requestId, log);
    setSecurityHeaders(res, hsts);
    try {
      await route(req, res, context);
    } catch (error) {
      if (!error.status) {
        console.error(error);
        log?.write({ event: 'error', requestId, message: error.message });
      }
      if (context.drainBytes) await drain(req, { maxBytes: context.drainBytes });
      if (!res.headersSent && !res.destroyed) {
        res.setHeader('Connection', 'close');
        json(res, error.status || 500, {
          error: error.status ? error.message : 'Internal server error.',
          ...(error.code && error.status ? { code: error.code } : {}),
        });
      }
      req.resume();
    }
  });
  server.requestTimeout = uploadTimeoutMs;
  server.headersTimeout = Math.min(10_000, uploadTimeoutMs);
  server.keepAliveTimeout = 5000;
  server.maxRequestsPerSocket = 100;
  // Also limits connections that stop sending data in the middle of an upload.
  server.setTimeout(uploadTimeoutMs, (socket) => socket.destroy());
  return server;
}
