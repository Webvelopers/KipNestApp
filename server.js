import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createApp } from './src/server/app.js';
import { decodeKey } from './src/server/crypto.js';
import { createFileLogger } from './src/server/log.js';
import { findLoosePermissions, restrictToOwner } from './scripts/permissions.js';

try {
  process.loadEnvFile(fileURLToPath(new URL('.env', import.meta.url)));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

const host = process.env.HOST || '127.0.0.1';
const port = Number(process.env.PORT || 3000);
const token = process.env.UPLOAD_TOKEN || randomBytes(32).toString('hex');

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be a number between 1 and 65535.');
}
if (token.length < 32 || !/^[\x21-\x7e]+$/.test(token)) {
  throw new Error('UPLOAD_TOKEN must contain at least 32 ASCII characters without spaces.');
}

function positiveInteger(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer.`);
  return value;
}

// Encryption keys (see docs/ENCRYPTION.md). Unlike the token, they are never
// generated on the fly: a random STORAGE_KEY per start would make every stored
// file unreadable.
const storageKey = decodeKey('STORAGE_KEY', process.env.STORAGE_KEY, 32);
const previousStorageKeys = (process.env.STORAGE_KEY_PREVIOUS || '').split(',').map((value) => value.trim()).filter(Boolean)
  .map((value) => decodeKey('STORAGE_KEY_PREVIOUS', value, 32));
const kdfSalt = decodeKey('KDF_SALT', process.env.KDF_SALT, 16);

const maxFileMb = positiveInteger('MAX_FILE_MB', 100);
const maxStorageMb = positiveInteger('MAX_STORAGE_MB', 1024);
const uploadTimeoutSeconds = positiveInteger('UPLOAD_TIMEOUT_SECONDS', 300);
const maxConcurrentUploads = positiveInteger('MAX_CONCURRENT_UPLOADS', 1);
if (maxConcurrentUploads > 16) throw new Error('MAX_CONCURRENT_UPLOADS must be 16 or less.');
const maxFiles = positiveInteger('MAX_FILES', 1000);
if (maxFiles > 1_000_000) throw new Error('MAX_FILES must be 1000000 or less.');
const root = fileURLToPath(new URL('./', import.meta.url));
const envFile = fileURLToPath(new URL('.env', import.meta.url));
const certFile = path.resolve(root, process.env.TLS_CERT_FILE || 'certs/local-cert.pem');
const keyFile = path.resolve(root, process.env.TLS_KEY_FILE || 'certs/local-key.pem');
// Stored files can live outside the code checkout (recommended in production).
const uploadDir = path.resolve(root, process.env.UPLOAD_DIR || 'storage/uploads');
// Optional interaction log on disk: off unless LOG_DIR is set.
const logDir = process.env.LOG_DIR?.trim() ? path.resolve(root, process.env.LOG_DIR.trim()) : null;
const logRetentionDays = positiveInteger('LOG_RETENTION_DAYS', 30);
if (logRetentionDays > 3650) throw new Error('LOG_RETENTION_DAYS must be 3650 or less.');
const log = logDir ? createFileLogger({ dir: logDir, retentionDays: logRetentionDays }) : null;
let cert;
let key;
try {
  [cert, key] = await Promise.all([readFile(certFile), readFile(keyFile)]);
} catch (error) {
  if (error.code === 'ENOENT') throw new Error('HTTPS certificate is missing. Run npm run cert before starting the server.', { cause: error });
  throw error;
}
// Other local accounts must not be able to read the token, the encryption keys,
// the TLS private key, or the stored files. Checked once the server is
// listening, so the (advisory) check never delays startup.
function warnAboutLoosePermissions() {
  const loose = findLoosePermissions([envFile, keyFile, uploadDir, ...(logDir ? [logDir] : [])]);
  if (loose.length) {
    console.warn(`Warning: other users on this computer can access: ${loose.map((target) => path.relative(root, target) || target).join(', ')}.`);
    console.warn('Run npm run setup to restrict them to your account.');
  }
}
const server = await createApp({
  token,
  storageKey,
  previousStorageKeys,
  kdfSalt,
  tls: { cert, key },
  uploadDir,
  // createApp refuses to start if any of these is inside the web root.
  privatePaths: [envFile, certFile, keyFile],
  log,
  maxFileBytes: maxFileMb * 1024 * 1024,
  maxTotalBytes: maxStorageMb * 1024 * 1024,
  uploadTimeoutMs: uploadTimeoutSeconds * 1000,
  maxConcurrentUploads,
  maxFiles,
});
if (log) {
  // Only now, after createApp checked it is outside the web root. The log holds
  // client addresses: keep it private like the stored files.
  try {
    mkdirSync(logDir, { recursive: true, mode: 0o700 });
    restrictToOwner([logDir]);
  } catch (error) {
    console.warn(`Could not restrict the log folder: ${error.message}. Limit access to ${logDir} manually.`);
  }
}
server.on('error', (error) => {
  console.error(`The server could not be started: ${error.message}`);
  log?.write({ event: 'start-failed', message: error.message });
  process.exitCode = 1;
});
server.listen(port, host, () => {
  console.log(`Server available at https://${host.includes(':') ? `[${host}]` : host}:${port}`);
  if (!process.env.UPLOAD_TOKEN) console.log(`Temporary access token: ${token}`);
  console.log('Enter the token on the page to upload and browse files.');
  console.log(`Limits: ${maxFileMb} MB per file, ${maxStorageMb} MB of storage, ${maxFiles} files. ${maxConcurrentUploads === 1 ? 'Uploads are one at a time.' : `Up to ${maxConcurrentUploads} uploads at a time.`}`);
  if (log) console.log(`Interaction log: ${path.relative(root, logDir) || logDir} (kept ${logRetentionDays} days).`);
  log?.write({ event: 'start', host, port, tls: true });
  warnAboutLoosePermissions();
});

let shuttingDown = false;
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    if (shuttingDown) return; // A second signal exits immediately.
    shuttingDown = true;
    console.log('Shutting down: waiting for in-flight requests (press Ctrl+C again to force exit)…');
    log?.write({ event: 'stop', signal });
    server.close(); // Stop accepting new connections.
    // Wait until the server reports no active requests, bounded by the upload
    // timeout plus margin so a stuck stream cannot hang shutdown forever.
    const deadline = Date.now() + uploadTimeoutSeconds * 1000 + 15_000;
    while (Date.now() < deadline) {
      const idle = await new Promise((resolve) => {
        server.getConnections((error, count) => resolve(error ? 0 : count));
      });
      if (idle === 0) break;
      await new Promise((resolve) => {
        setTimeout(resolve, 100);
      });
    }
    console.log('Shutdown complete.');
    log?.write({ event: 'stopped' });
    log?.close();
    process.exit(0);
  });
}

// Last line of defense: an unexpected error is logged (without request data)
// and the process exits with an error code, so a supervisor (a Windows
// service, pm2, systemd, Docker restart policy) can start a clean instance
// instead of leaving a half-broken server running.
for (const event of ['uncaughtException', 'unhandledRejection']) {
  process.on(event, (error) => {
    console.error(`Fatal ${event}: ${error?.stack || error}`);
    log?.write({ event: 'fatal', type: event, message: String(error?.message || error) });
    process.exit(1);
  });
}
