import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { restrictToOwner } from './permissions.js';

const envPath = new URL('../.env', import.meta.url);
const root = fileURLToPath(new URL('../', import.meta.url));
const key = (length) => randomBytes(length).toString('base64url');
const token = randomBytes(32).toString('hex');

// Encryption settings. They are appended to an existing .env when missing,
// so upgrading never touches the token or the other settings.
const encryptionSettings = [
  ['STORAGE_KEY', [
    '# Encrypts stored files and their details (32 random bytes, base64url).',
    '# BACK IT UP: if it is lost, every stored file becomes unreadable.',
  ], () => key(32)],
  ['KDF_SALT', [
    '# Per-installation salt for deriving the token key (16 random bytes, base64url). Not secret.',
  ], () => key(16)],
];

const content = [
  '# Local configuration generated with npm run setup.',
  '',
  '# localhost IP address',
  'HOST=127.0.0.1',
  'PORT=3000',
  '',
  '# Local certificate generated with npm run cert. Paths relative to the project.',
  'TLS_CERT_FILE=certs/local-cert.pem',
  'TLS_KEY_FILE=certs/local-key.pem',
  '',
  '# Sizes in MiB (shown as MB in the interface).',
  'MAX_FILE_MB=100',
  'MAX_STORAGE_MB=1024',
  '# Maximum number of stored files (1-1000000).',
  'MAX_FILES=1000',
  '',
  '# Allowed receive and idle time for each file, in seconds.',
  'UPLOAD_TIMEOUT_SECONDS=300',
  '',
  '# Simultaneous uploads allowed (1 keeps the default one-at-a-time behavior).',
  'MAX_CONCURRENT_UPLOADS=1',
  '',
  '# Optional: folder for the encrypted stored files (default storage/uploads).',
  '# In production, prefer a folder outside the project, for example /var/lib/kipnest.',
  '# UPLOAD_DIR=storage/uploads',
  '',
  '# Optional: save every interaction (one JSON line per request, one file per day).',
  '# Logs hold client IP addresses; old files are deleted after LOG_RETENTION_DAYS.',
  '# LOG_DIR=storage/logs',
  '# LOG_RETENTION_DAYS=30',
  '',
  '# Optional: use at least 32 random characters.',
  '# If omitted, a new token is generated at startup and shown in the console.',
  `UPLOAD_TOKEN=${token}`,
  ...encryptionSettings.flatMap(([name, comments, value]) => ['', ...comments, `${name}=${value()}`]),
].join('\n');

try {
  await writeFile(envPath, `${content}\n`, { flag: 'wx', mode: 0o600 });
  console.log('.env file created with a random 64-character UPLOAD_TOKEN and new encryption keys.');
  console.log('Copy the value of UPLOAD_TOKEN from .env to access the application.');
  console.log('Back up STORAGE_KEY: without it, stored files cannot be decrypted.');
  console.log('Start the server with npm start.');
} catch (error) {
  if (error.code !== 'EEXIST') {
    console.error(`Could not create .env: ${error.message}`);
    process.exitCode = 1;
  } else {
    const existing = await readFile(envPath, 'utf8');
    const missing = encryptionSettings.filter(([name]) => !new RegExp(`^\\s*${name}=`, 'm').test(existing));
    if (missing.length === 0) {
      console.log('The .env file already exists. Its configuration, token, and keys are preserved.');
    } else {
      const addition = missing.flatMap(([name, comments, value]) => ['', ...comments, `${name}=${value()}`]).join('\n');
      await writeFile(envPath, `${existing.replace(/\s*$/, '')}\n${addition}\n`, { mode: 0o600 });
      console.log(`The .env file already exists. Added the missing settings: ${missing.map(([name]) => name).join(', ')}.`);
      console.log('Everything else, including the token, is unchanged. Back up STORAGE_KEY.');
    }
  }
}

// Secrets must be private to this account. On Windows the 0o600 mode above is
// ignored, so this also fixes .env files created by older versions.
if (!process.exitCode) {
  try {
    try {
      process.loadEnvFile(fileURLToPath(envPath));
    } catch {
      // Unreadable .env: fall back to the default folder.
    }
    const uploadDir = path.resolve(root, process.env.UPLOAD_DIR || 'storage/uploads');
    await mkdir(uploadDir, { recursive: true, mode: 0o700 });
    const logDir = process.env.LOG_DIR?.trim() ? path.resolve(root, process.env.LOG_DIR.trim()) : null;
    if (logDir) await mkdir(logDir, { recursive: true, mode: 0o700 });
    const restricted = restrictToOwner([fileURLToPath(envPath), `${root}certs`, uploadDir, ...(logDir ? [logDir] : [])]);
    if (restricted.length) console.log(`Restricted to your account: ${restricted.map((target) => path.relative(root, target) || target).join(', ')}.`);
  } catch (error) {
    console.warn(`Could not restrict file permissions: ${error.message}. Limit access to .env, certs/ and the upload folder (storage/uploads/) manually.`);
  }
}
