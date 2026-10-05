import { mkdir, access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { restrictToOwner } from './permissions.js';

const root = fileURLToPath(new URL('../', import.meta.url));
try {
  process.loadEnvFile(path.join(root, '.env'));
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

// Same defaults as server.js and the README.
const certPath = path.resolve(root, process.env.TLS_CERT_FILE || 'certs/local-cert.pem');
const keyPath = path.resolve(root, process.env.TLS_KEY_FILE || 'certs/local-key.pem');
const host = process.env.HOST || '127.0.0.1';
const names = [...new Set(['localhost', '127.0.0.1', '::1', ...(['0.0.0.0', '::'].includes(host) ? [] : [host])])];

function mkcert(args) {
  const result = spawnSync('mkcert', args, { stdio: 'inherit', shell: false });
  if (result.error?.code === 'ENOENT') {
    throw new Error('Install mkcert and add it to the PATH. On Windows with Scoop: scoop install mkcert');
  }
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('mkcert could not complete the operation.');
}

async function exists(filename) {
  try {
    await access(filename);
    return true;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return false;
  }
}

try {
  if (certPath === keyPath) throw new Error('TLS_CERT_FILE and TLS_KEY_FILE must be different files.');
  if (await exists(certPath) || await exists(keyPath)) {
    console.log('A certificate or a key already exists at the configured paths. Those files are preserved.');
    console.log('To renew the certificate or change its addresses, move both files and run npm run cert.');
  } else {
    mkcert(['-install']);
    await mkdir(path.dirname(certPath), { recursive: true, mode: 0o700 });
    await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
    mkcert(['-cert-file', certPath, '-key-file', keyPath, ...names]);
    // The private key must not be readable by other local accounts.
    try {
      restrictToOwner([...new Set([path.dirname(keyPath), keyPath])]);
    } catch (error) {
      console.warn(`Could not restrict the key's permissions: ${error.message}. Run npm run setup or limit access to ${path.dirname(keyPath)} manually.`);
    }
    console.log(`Certificate created for: ${names.join(', ')}.`);
    console.log('Start the HTTPS server with npm start.');
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
