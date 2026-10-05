// Storage maintenance for KipNest's encryption at rest (docs/ENCRYPTION.md).
//
//   npm run encrypt:migrate [-- --dry-run]   encrypt plaintext files left by older versions
//   npm run encrypt:rotate                   re-wrap every file with the current STORAGE_KEY
//
// Both commands are idempotent and safe to re-run after an interruption: new
// files are written to .part paths and renamed, and plaintext is only deleted
// after the encrypted copy has been decrypted back and compared.
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { TYPES, createValidator, hideTimestamps, safeName } from '../src/server/app.js';
import {
  createKeyring, createRestEncryptor, decodeKey, openMetadata, openRestFile, restFileSize,
  rewrapRestHeader, sealMetadata,
} from '../src/server/crypto.js';

const UUID = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}';
const LEGACY_FILE = new RegExp(`^(${UUID})(\\.(?:png|jpe?g|pdf|txt))$`);

async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

async function sha256Stored(uploadDir, id, size, keyring) {
  const handle = await open(path.join(uploadDir, `${id}.bin`), 'r');
  try {
    const rest = await openRestFile(handle, { id, size, keyring });
    const hash = createHash('sha256');
    for (let index = 0; index < rest.chunks; index++) hash.update(await rest.readChunk(index));
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

async function exists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

/** Encrypts plaintext pairs (<id>.<ext> + <id>.json) into <id>.bin + <id>.meta. */
export async function migrateStorage({ uploadDir, keyring, dryRun = false, log = console.log }) {
  const summary = { migrated: 0, skipped: 0, failed: 0 };
  const entries = await readdir(uploadDir);
  for (const name of entries) {
    const match = LEGACY_FILE.exec(name);
    if (!match) continue;
    const [, id, extension] = match;
    const plainPath = path.join(uploadDir, name);
    const legacyMetaPath = path.join(uploadDir, `${id}.json`);
    try {
      let legacy;
      try {
        legacy = JSON.parse(await readFile(legacyMetaPath, 'utf8'));
      } catch {
        throw new Error('its .json details are missing or unreadable');
      }
      const fileName = safeName(String(legacy.name || `file${extension}`));
      if (path.extname(fileName).toLowerCase() !== extension.toLowerCase() || !TYPES.has(extension.toLowerCase())) {
        throw new Error('its name and extension do not match');
      }
      const { size } = await stat(plainPath);
      if (!size) throw new Error('it is empty');
      if (dryRun) {
        log(`Would encrypt ${name} (${size} bytes)`);
        summary.migrated += 1;
        continue;
      }
      const metadata = {
        id,
        name: fileName,
        size,
        type: TYPES.get(extension.toLowerCase()),
        createdAt: typeof legacy.createdAt === 'string' ? legacy.createdAt : (await stat(plainPath)).mtime.toISOString(),
      };
      const storedPath = path.join(uploadDir, `${id}.bin`);
      const metaPath = path.join(uploadDir, `${id}.meta`);
      // A previous run may have finished the encrypted copy but not the cleanup.
      if (!(await exists(storedPath) && await exists(metaPath))) {
        const temporaryPath = path.join(uploadDir, `${id}.part`);
        const temporaryMetaPath = path.join(uploadDir, `${id}.meta.part`);
        try {
          await rm(temporaryPath, { force: true });
          await pipeline(
            createReadStream(plainPath),
            createValidator({ extension: extension.toLowerCase() }),
            createRestEncryptor({ id, keyring }),
            createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 }),
          );
          if ((await stat(temporaryPath)).size !== restFileSize(size)) throw new Error('the encrypted copy has an unexpected size');
          await rename(temporaryPath, storedPath);
          await writeFile(temporaryMetaPath, sealMetadata(keyring, metadata), { flag: 'w', mode: 0o600 });
          await rename(temporaryMetaPath, metaPath);
          await hideTimestamps(storedPath, metaPath);
        } finally {
          await rm(temporaryPath, { force: true });
          await rm(temporaryMetaPath, { force: true });
        }
      }
      // Decrypt the stored copy and compare before removing the plaintext.
      const stored = openMetadata(keyring, id, await readFile(metaPath));
      if (stored.size !== size || await sha256Stored(uploadDir, id, size, keyring) !== await sha256File(plainPath)) {
        throw new Error('the encrypted copy does not match the original');
      }
      await rm(plainPath);
      await rm(legacyMetaPath, { force: true });
      log(`Encrypted ${name}`);
      summary.migrated += 1;
    } catch (error) {
      log(`Skipped ${name}: ${error.message}. The original was left untouched.`);
      summary.failed += 1;
    }
  }
  // Details files without their content cannot be migrated.
  for (const name of entries) {
    const match = new RegExp(`^(${UUID})\\.json$`).exec(name);
    if (!match || entries.some((entry) => LEGACY_FILE.test(entry) && entry.startsWith(match[1]))) continue;
    log(`Note: ${name} has no matching file; remove it manually if it is not needed.`);
    summary.skipped += 1;
  }
  return summary;
}

/** Re-wraps every stored file and its details with the current STORAGE_KEY. */
export async function rotateStorage({ uploadDir, keyring, log = console.log }) {
  const summary = { rotated: 0, current: 0, failed: 0 };
  for (const name of await readdir(uploadDir)) {
    const match = new RegExp(`^(${UUID})\\.meta$`).exec(name);
    if (!match) continue;
    const id = match[1];
    const metaPath = path.join(uploadDir, name);
    const storedPath = path.join(uploadDir, `${id}.bin`);
    try {
      const sealedMeta = await readFile(metaPath);
      const metadata = openMetadata(keyring, id, sealedMeta);
      const handle = await open(storedPath, 'r');
      let rest;
      try {
        rest = await openRestFile(handle, { id, size: metadata.size, keyring });
      } finally {
        await handle.close();
      }
      const onCurrentKey = rest.header.subarray(4, 12).equals(keyring.current.id)
        && sealedMeta.subarray(4, 12).equals(keyring.current.id);
      if (onCurrentKey) {
        summary.current += 1;
        continue;
      }
      // Only the 76-byte header changes; the encrypted content is copied as is.
      const temporaryPath = path.join(uploadDir, `${id}.part`);
      const temporaryMetaPath = path.join(uploadDir, `${id}.meta.part`);
      try {
        await rm(temporaryPath, { force: true });
        const output = createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 });
        output.write(rewrapRestHeader(rest.header, { id, dek: rest.dek, keyring }));
        await pipeline(createReadStream(storedPath, { start: rest.header.length }), output);
        await rename(temporaryPath, storedPath);
        await writeFile(temporaryMetaPath, sealMetadata(keyring, metadata), { flag: 'w', mode: 0o600 });
        await rename(temporaryMetaPath, metaPath);
        await hideTimestamps(storedPath, metaPath);
      } finally {
        rest.dek.fill(0);
        await rm(temporaryPath, { force: true });
        await rm(temporaryMetaPath, { force: true });
      }
      summary.rotated += 1;
      log(`Re-wrapped ${id}`);
    } catch (error) {
      summary.failed += 1;
      log(`Could not re-wrap ${id}: ${error.message}`);
    }
  }
  return summary;
}

async function main() {
  const [command, ...flags] = process.argv.slice(2);
  const root = fileURLToPath(new URL('../', import.meta.url));
  try {
    process.loadEnvFile(path.join(root, '.env'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const storageKey = decodeKey('STORAGE_KEY', process.env.STORAGE_KEY, 32);
  const previous = (process.env.STORAGE_KEY_PREVIOUS || '').split(',').map((value) => value.trim()).filter(Boolean)
    .map((value) => decodeKey('STORAGE_KEY_PREVIOUS', value, 32));
  const keyring = createKeyring(storageKey, previous);
  const uploadDir = path.resolve(root, process.env.UPLOAD_DIR || 'storage/uploads');
  if (command === 'migrate') {
    const summary = await migrateStorage({ uploadDir, keyring, dryRun: flags.includes('--dry-run') });
    console.log(`Done: ${summary.migrated} encrypted, ${summary.failed} left untouched${flags.includes('--dry-run') ? ' (dry run, nothing changed)' : ''}.`);
    if (summary.failed) process.exitCode = 1;
  } else if (command === 'rotate') {
    if (!previous.length) console.log('Tip: put the old key in STORAGE_KEY_PREVIOUS and the new one in STORAGE_KEY first.');
    const summary = await rotateStorage({ uploadDir, keyring });
    console.log(`Done: ${summary.rotated} re-wrapped, ${summary.current} already current, ${summary.failed} failed.`);
    if (summary.failed) process.exitCode = 1;
    else if (summary.rotated) console.log('You can now remove STORAGE_KEY_PREVIOUS from .env.');
  } else {
    console.log('Usage: node scripts/encrypt-storage.js migrate [--dry-run] | rotate');
    process.exitCode = 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) await main();
