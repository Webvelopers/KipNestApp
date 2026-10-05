// Optional interaction log on disk (LOG_DIR). One JSON line per request or
// server event, in one file per UTC day (kipnest-YYYY-MM-DD.log), private to
// the account running the server. Files older than the retention period are
// deleted. Writes are synchronous so nothing is lost when the process exits
// after a fatal error; the volume of a single-user file server keeps that cheap.
// Never pass credentials, keys, session ids, nonces, or file names here.
import { closeSync, mkdirSync, openSync, readdirSync, rmSync, writeSync } from 'node:fs';
import path from 'node:path';

const LOG_FILE = /^kipnest-(\d{4}-\d{2}-\d{2})\.log$/;
const DAY_MS = 24 * 60 * 60_000;

/** Human-readable name of what a request did, from its method and path (never from user input beyond the route). */
export function describeAction(method, pathname) {
  if (method === 'GET' || method === 'HEAD') {
    if (pathname === '/' || pathname.startsWith('/assets/')) return 'page';
    if (pathname === '/healthz') return 'health';
    if (pathname === '/api/config') return 'config';
    if (pathname === '/api/files') return 'list';
    if (pathname === '/api/stats') return 'stats';
    if (/^\/api\/files\/[^/]+\/download$/.test(pathname)) return 'download';
    if (/^\/api\/files\/[^/]+\/preview$/.test(pathname)) return 'preview';
  }
  if (method === 'POST' && pathname === '/api/session') return 'sign-in';
  if (method === 'DELETE' && pathname === '/api/session') return 'sign-out';
  if (method === 'POST' && pathname === '/api/upload') return 'upload';
  if (method === 'DELETE' && /^\/api\/files\/[^/]+$/.test(pathname)) return 'delete';
  return 'other';
}

/** How a request ended, from its status code. */
export function describeOutcome(status) {
  if (status < 400) return 'ok';
  if (status === 401 || status === 403) return 'denied';
  if (status === 429) return 'limited';
  if (status >= 500) return 'error';
  return 'rejected';
}

/**
 * Creates a logger that appends JSON lines to `dir`. `now` can be replaced in
 * tests. Returns { write(entry), close() }; write never throws.
 */
export function createFileLogger({ dir, retentionDays = 30, now = () => new Date() }) {
  if (!dir) throw new Error('A log folder is required.');
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new Error('retentionDays must be an integer between 1 and 3650.');
  }
  let day = null;
  let fd = null;
  let failed = false;

  function prune(today) {
    const oldest = Date.parse(`${today}T00:00:00Z`) - (retentionDays - 1) * DAY_MS;
    for (const name of readdirSync(dir)) {
      const match = LOG_FILE.exec(name);
      // Only this logger's own files are ever deleted.
      if (match && Date.parse(`${match[1]}T00:00:00Z`) < oldest) rmSync(path.join(dir, name), { force: true });
    }
  }

  function open(today) {
    if (fd !== null) closeSync(fd);
    fd = null;
    // Created on first use, so the server can first check the folder is not
    // inside the web root (createApp) before anything is written.
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    fd = openSync(path.join(dir, `kipnest-${today}.log`), 'a', 0o600);
    day = today;
    prune(today);
  }

  return {
    dir,
    write(entry) {
      try {
        const time = now();
        const today = time.toISOString().slice(0, 10);
        if (today !== day) open(today);
        writeSync(fd, `${JSON.stringify({ time: time.toISOString(), ...entry })}\n`);
        failed = false;
      } catch (error) {
        // Logging must never take the server down; report the first failure only.
        if (!failed) console.error(`Could not write the log file: ${error.message}`);
        failed = true;
      }
    },
    close() {
      if (fd !== null) closeSync(fd);
      fd = null;
      day = null;
    },
  };
}
