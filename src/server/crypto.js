// Server side of KipNest's three encryption layers (see docs/ENCRYPTION.md).
//
//   Transit (upload)   ECDH P-256 + token-bound HKDF-SHA-256 → AES-256-GCM chunks   (format KNU1)
//   Rest (storage)     STORAGE_KEY → HKDF-SHA-512 wrap/meta keys → per-file DEK, ChaCha20-Poly1305 (KNR1, KNM1)
//   Download / save    same session, HKDF-SHA-384 → AES-256-CTR + HMAC-SHA-512 chunks (KND1)
//
// Only node:crypto is used. The browser counterpart is src/client/crypto.js,
// which uses Web Crypto and must stay byte-for-byte compatible with this file.
import {
  createCipheriv, createDecipheriv, createECDH, createHmac,
  hkdfSync, pbkdf2, randomBytes, timingSafeEqual,
} from 'node:crypto';
import { Transform } from 'node:stream';
import { promisify } from 'node:util';

export const UPLOAD_CHUNK = 1024 * 1024;
export const REST_CHUNK = 64 * 1024; // Also the padding bucket for stored files.
export const DOWNLOAD_CHUNK = 1024 * 1024;
export const DOWNLOAD_HEADER_BYTES = 1024;
export const META_BLOCK = 256;
// Sizes on the wire are rounded up so traffic only reveals a bucket, not the
// exact file size or name length.
export const WIRE_BLOCK = 64 * 1024;
const HEADER_BLOCK = 1024;
const HANDSHAKE_WINDOW_MS = 5 * 60_000; // Accepted clock difference for handshakes and request MACs.
const GCM_TAG = 16;
const CHACHA_TAG = 16;
const MAC_BYTES = 64; // HMAC-SHA-512.
const UPLOAD_PREFIX = 4 + 16 + 16; // magic + sessionId + fileNonce
const MAX_UPLOAD_HEADER = 4096;
const REST_HEADER = 4 + 8 + 12 + 32 + GCM_TAG + 4; // magic, kekId, wrap IV, wrapped DEK + tag, nonce prefix
const REST_RECORD = 1 + REST_CHUNK + CHACHA_TAG; // flag + ciphertext + tag
const BLOCKS_PER_DOWNLOAD_CHUNK = DOWNLOAD_CHUNK / 16;
// AES-CTR uses a 32-bit block counter (see the browser side), which caps a
// download at 65 535 chunks of 1 MiB.
export const MAX_ENCRYPTED_FILE_BYTES = (2 ** 32 / BLOCKS_PER_DOWNLOAD_CHUNK - 1) * DOWNLOAD_CHUNK;

const text = (value) => Buffer.from(value, 'utf8');
const MAGIC = {
  upload: text('KNU1'), rest: text('KNR1'), meta: text('KNM1'), sealed: text('KNL1'), download: text('KND1'),
};

/** A cryptographic check failed. Callers turn it into a generic HTTP error. */
export class CryptoError extends Error {
  constructor(message = 'Encrypted data could not be verified.') {
    super(message);
  }
}

function u32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}

function u64(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value));
  return buffer;
}

function roundUp(value, block) {
  return Math.ceil(value / block) * block;
}

/** JSON padded with spaces (ignored by JSON.parse) to a multiple of `block` bytes. */
function paddedJson(value, block) {
  const json = text(JSON.stringify(value));
  const padded = Buffer.alloc(roundUp(json.length + 1, block), 0x20);
  json.copy(padded);
  return padded;
}

function hkdf(hash, ikm, salt, info, length) {
  return Buffer.from(hkdfSync(hash, ikm, salt, text(info), length));
}

export function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function fromBase64Url(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new CryptoError();
  const bytes = Buffer.from(value, 'base64url');
  if (length !== undefined && bytes.length !== length) throw new CryptoError();
  return bytes;
}

/** Strict decoder for key material read from the environment. */
export function decodeKey(name, value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || Buffer.from(value, 'base64url').length !== length) {
    throw new Error(`${name} must be ${length} random bytes in base64url. Run npm run setup to generate it.`);
  }
  return Buffer.from(value, 'base64url');
}

export function generateKey(length) {
  return toBase64Url(randomBytes(length));
}

// ---------------------------------------------------------------------------
// Keys

export function deriveTokenKey(token, salt, iterations) {
  return promisify(pbkdf2)(token, salt, iterations, 32, 'sha256');
}

// Separate keys for wrapping DEKs and for metadata, plus a public id that
// tells which STORAGE_KEY wrote a file.
function kekEntry(storageKey) {
  const derive = (info, length) => hkdf('sha512', storageKey, Buffer.alloc(0), info, length);
  return { wrapKey: derive('kipnest/v1/kek-wrap', 32), metaKey: derive('kipnest/v1/kek-meta', 32), id: derive('kipnest/v1/kek-id', 8) };
}

/**
 * The current key encrypts everything new; previous keys only decrypt, so a
 * STORAGE_KEY rotation can re-wrap files without losing access to them.
 */
export function createKeyring(storageKey, previousKeys = []) {
  const current = kekEntry(storageKey);
  const all = new Map([[current.id.toString('hex'), current]]);
  for (const key of previousKeys) {
    const entry = kekEntry(key);
    all.set(entry.id.toString('hex'), entry);
  }
  return { current, find: (id) => all.get(Buffer.from(id).toString('hex')) };
}

// ---------------------------------------------------------------------------
// Session handshake: ephemeral ECDH, bound to the token-derived key. The
// token itself never travels: the browser proves it knows the token key.

/**
 * Checks the browser's proof: HMAC-SHA-256(token key, "kipnest/v1/client-proof"
 * | clientPublicKey | u64 timestamp). The timestamp must be within 5 minutes.
 */
export function verifyClientProof(tokenKey, clientPublicKey, timestamp, proof, now = Date.now()) {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || Math.abs(now - timestamp) > HANDSHAKE_WINDOW_MS) return false;
  const expected = createHmac('sha256', tokenKey)
    .update(Buffer.concat([text('kipnest/v1/client-proof'), clientPublicKey, u64(timestamp)]))
    .digest();
  return safeEqual(expected, proof);
}

/** Key for per-request MACs, separate from every encryption key. */
export function requestAuthKey(sessionKey) {
  return hkdf('sha256', sessionKey, Buffer.alloc(0), 'kipnest/v1/request-auth', 32);
}

/** The exact text both sides sign for one request (see docs/ENCRYPTION.md). */
export function requestMacInput({ method, target, time, nonce, downloadNonce = '', range = '' }) {
  return ['kipnest/v1/request', method, target, time, nonce, downloadNonce, range].join('\n');
}

/**
 * Checks X-Request-Mac = HMAC-SHA-256(request key, requestMacInput(...)): the
 * method, path with query, time (within 5 minutes), a one-time request nonce,
 * and the X-Download-Nonce and Range headers when present.
 */
export function verifyRequestMac(requestKey, { mac, ...fields }, now = Date.now()) {
  const { time, nonce } = fields;
  if (typeof time !== 'string' || !/^\d{1,16}$/.test(time) || Math.abs(now - Number(time)) > HANDSHAKE_WINDOW_MS) return false;
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(nonce)) return false;
  let provided;
  try {
    provided = fromBase64Url(mac, 32);
  } catch {
    return false;
  }
  const expected = createHmac('sha256', requestKey).update(requestMacInput(fields)).digest();
  return safeEqual(expected, provided);
}

export const REQUEST_WINDOW_MS = HANDSHAKE_WINDOW_MS;

export function openSession(tokenKey, clientPublicKey) {
  if (!Buffer.isBuffer(clientPublicKey) || clientPublicKey.length !== 65 || clientPublicKey[0] !== 4) throw new CryptoError();
  const ecdh = createECDH('prime256v1');
  const serverPublicKey = ecdh.generateKeys();
  let secret;
  try {
    secret = ecdh.computeSecret(clientPublicKey);
  } catch {
    throw new CryptoError();
  }
  const salt = randomBytes(32);
  // Only someone who knows the token can derive the same session key.
  const mixedSalt = createHmac('sha256', tokenKey).update(salt).digest();
  const key = hkdf('sha256', secret, mixedSalt, 'kipnest/v1/session', 32);
  // Lets the browser check that it is talking to a server that knows the token.
  const proof = createHmac('sha256', tokenKey)
    .update(Buffer.concat([text('kipnest/v1/server-proof'), clientPublicKey, serverPublicKey, salt]))
    .digest();
  return { id: randomBytes(16), key, serverPublicKey, salt, proof };
}

/** Encrypts a JSON value for one session (file lists, stats, upload receipts). */
export function sealJson(sessionKey, label, value) {
  const nonce = randomBytes(16);
  const key = hkdf('sha256', sessionKey, nonce, `kipnest/v1/${label}`, 32);
  const cipher = createCipheriv('aes-256-gcm', key, Buffer.alloc(12));
  cipher.setAAD(Buffer.concat([MAGIC.sealed, text(label)]));
  // Padded to 1 KiB blocks so reply sizes do not reveal name lengths.
  const data = Buffer.concat([cipher.update(paddedJson(value, HEADER_BLOCK)), cipher.final(), cipher.getAuthTag()]);
  return { nonce: toBase64Url(nonce), data: toBase64Url(data) };
}

// ---------------------------------------------------------------------------
// Transit layer (upload, format KNU1)
//
//   "KNU1" | sessionId(16) | fileNonce(16) | headerLength u32 | header (AES-GCM)
//   then records: flag(1) | length u32 | AES-GCM ciphertext + tag
//
// Key: HKDF-SHA-256(sessionKey, fileNonce, "kipnest/v1/upload"); IV = 4 zero
// bytes + u64 index (0 = header, 1..n = chunks); AAD = prefix | u64 index | flag.
// The header JSON is space-padded to 1 KiB blocks, and the final record is
// zero-padded to a 64 KiB multiple; the real size is in the header.

function gcmIv(index) {
  return Buffer.concat([Buffer.alloc(4), u64(index)]);
}

export function maxUploadBytes(maxFileBytes) {
  const chunks = Math.max(1, Math.ceil(maxFileBytes / UPLOAD_CHUNK));
  return UPLOAD_PREFIX + 4 + MAX_UPLOAD_HEADER + GCM_TAG + maxFileBytes + WIRE_BLOCK + chunks * (1 + 4 + GCM_TAG);
}

/**
 * Streams plaintext out of an encrypted upload. `resolveSession(id, fileNonce)`
 * returns the session key (or throws, also on a replayed nonce); `onHeader(details)` sees the decrypted file details
 * before any content and may throw to reject the upload early.
 */
export function createUploadDecryptor({ resolveSession, onHeader }) {
  let buffered = Buffer.alloc(0);
  let stage = 'prefix';
  let prefix;
  let key;
  let headerLength;
  let details;
  let index = 0;
  let received = 0;
  let record;

  function decrypt(iv, aad, sealed) {
    if (sealed.length < GCM_TAG) throw new CryptoError();
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.subarray(sealed.length - GCM_TAG));
    try {
      return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - GCM_TAG)), decipher.final()]);
    } catch {
      throw new CryptoError();
    }
  }

  function take(length) {
    const part = buffered.subarray(0, length);
    buffered = buffered.subarray(length);
    return part;
  }

  return new Transform({
    transform(chunk, encoding, callback) {
      try {
        buffered = buffered.length ? Buffer.concat([buffered, chunk]) : chunk;
        for (;;) {
          if (stage === 'prefix') {
            if (buffered.length < UPLOAD_PREFIX + 4) break;
            prefix = Buffer.from(take(UPLOAD_PREFIX));
            if (!prefix.subarray(0, 4).equals(MAGIC.upload)) throw new CryptoError();
            const sessionKey = resolveSession(prefix.subarray(4, 20), prefix.subarray(20, 36));
            key = hkdf('sha256', sessionKey, prefix.subarray(20, 36), 'kipnest/v1/upload', 32);
            headerLength = take(4).readUInt32BE();
            if (headerLength <= GCM_TAG || headerLength > MAX_UPLOAD_HEADER + GCM_TAG) throw new CryptoError();
            stage = 'header';
          } else if (stage === 'header') {
            if (buffered.length < headerLength) break;
            const plain = decrypt(gcmIv(0), Buffer.concat([prefix, text('header')]), take(headerLength));
            try {
              details = JSON.parse(plain.toString('utf8'));
            } catch {
              throw new CryptoError();
            }
            if (typeof details?.name !== 'string' || !Number.isSafeInteger(details.size) || details.size < 0
              || details.chunkSize !== UPLOAD_CHUNK) {
              throw new CryptoError();
            }
            onHeader({ name: details.name, size: details.size });
            stage = 'record';
          } else if (stage === 'record') {
            if (!record) {
              if (buffered.length < 5) break;
              const flag = buffered[0];
              const length = buffered.readUInt32BE(1);
              const remaining = details.size - received;
              // A record is final exactly when the rest of the file fits in it,
              // and then it carries that rest padded to a 64 KiB multiple.
              const expected = remaining > UPLOAD_CHUNK ? UPLOAD_CHUNK : roundUp(remaining, WIRE_BLOCK);
              if (remaining <= 0 || flag !== (remaining > UPLOAD_CHUNK ? 0 : 1) || length !== expected + GCM_TAG) {
                throw new CryptoError();
              }
              take(5);
              record = { flag, length };
            }
            if (buffered.length < record.length) break;
            index += 1;
            const plain = decrypt(gcmIv(index), Buffer.concat([prefix, u64(index), Buffer.of(record.flag)]), take(record.length));
            const useful = plain.subarray(0, Math.min(plain.length, details.size - received)); // Drops the padding.
            received += useful.length;
            this.push(useful);
            stage = record.flag === 1 ? 'done' : 'record';
            record = null;
          } else {
            if (buffered.length) throw new CryptoError(); // Data after the final chunk.
            break;
          }
        }
        callback();
      } catch (error) {
        callback(error);
      }
    },
    flush(callback) {
      // A missing final chunk means the upload was truncated.
      if (stage !== 'done' || buffered.length || received !== details?.size) callback(new CryptoError());
      else callback();
    },
  });
}

// ---------------------------------------------------------------------------
// Rest layer (stored content, format KNR1)
//
//   "KNR1" | kekId(8) | wrapIv(12) | DEK wrapped with AES-256-GCM (32 + 16) | noncePrefix(4)
//   (wrap AAD = "KNR1" | id | kekId | noncePrefix)
//   then fixed-size records: flag(1) | ChaCha20-Poly1305(64 KiB) | tag(16)
//
// The last chunk is zero-padded to 64 KiB, so stored sizes reveal only the
// 64 KiB bucket. The real size lives in the encrypted metadata.

// The wrap covers the file id, the key id and the nonce prefix, so none of
// them can be changed or moved to another file. Returns wrapIv | sealed DEK.
function wrapDek({ id, dek, noncePrefix, keyring }) {
  const wrapIv = randomBytes(12);
  const wrap = createCipheriv('aes-256-gcm', keyring.current.wrapKey, wrapIv);
  wrap.setAAD(Buffer.concat([MAGIC.rest, text(id), keyring.current.id, noncePrefix]));
  return Buffer.concat([wrapIv, wrap.update(dek), wrap.final(), wrap.getAuthTag()]);
}

function restAad(id, index, flag) {
  return Buffer.concat([MAGIC.rest, text(id), u64(index), Buffer.of(flag)]);
}

export function restFileSize(size) {
  return REST_HEADER + Math.ceil(size / REST_CHUNK) * REST_RECORD;
}

export function createRestEncryptor({ id, keyring }) {
  const dek = randomBytes(32);
  const noncePrefix = randomBytes(4);
  const wrapped = wrapDek({ id, dek, noncePrefix, keyring });
  let headerSent = false;
  let pending = Buffer.alloc(0);
  let index = 0;

  function record(plain, final) {
    const flag = final ? 1 : 0;
    const cipher = createCipheriv('chacha20-poly1305', dek, Buffer.concat([noncePrefix, u64(index)]), { authTagLength: CHACHA_TAG });
    cipher.setAAD(restAad(id, index, flag), { plaintextLength: plain.length });
    const sealed = Buffer.concat([Buffer.of(flag), cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
    index += 1;
    return sealed;
  }

  function header() {
    headerSent = true;
    return Buffer.concat([MAGIC.rest, keyring.current.id, wrapped, noncePrefix]);
  }

  return new Transform({
    transform(chunk, encoding, callback) {
      if (!headerSent) this.push(header());
      pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
      // Keep the latest full chunk back: only flush knows which one is final.
      while (pending.length > REST_CHUNK) {
        this.push(record(pending.subarray(0, REST_CHUNK), false));
        pending = pending.subarray(REST_CHUNK);
      }
      callback();
    },
    flush(callback) {
      if (!headerSent) this.push(header());
      const last = Buffer.alloc(REST_CHUNK); // Zero padding up to the bucket size.
      pending.copy(last);
      this.push(record(last, true));
      dek.fill(0);
      callback();
    },
  });
}

/** Random access to a stored file: decrypts and verifies one 64 KiB chunk at a time. */
export async function openRestFile(handle, { id, size, keyring }) {
  const info = await handle.stat();
  if (!info.isFile() || info.size !== restFileSize(size) || size <= 0) throw new CryptoError();
  const header = Buffer.alloc(REST_HEADER);
  await handle.read(header, 0, REST_HEADER, 0);
  if (!header.subarray(0, 4).equals(MAGIC.rest)) throw new CryptoError();
  const kekId = header.subarray(4, 12);
  const entry = keyring.find(kekId);
  if (!entry) throw new CryptoError('Stored file was encrypted with an unknown STORAGE_KEY.');
  const unwrap = createDecipheriv('aes-256-gcm', entry.wrapKey, header.subarray(12, 24));
  unwrap.setAAD(Buffer.concat([MAGIC.rest, text(id), kekId, header.subarray(72, 76)]));
  unwrap.setAuthTag(header.subarray(56, 72));
  let dek;
  try {
    dek = Buffer.concat([unwrap.update(header.subarray(24, 56)), unwrap.final()]);
  } catch {
    throw new CryptoError();
  }
  const noncePrefix = Buffer.from(header.subarray(72, 76));
  const chunks = Math.ceil(size / REST_CHUNK);

  async function readChunk(index) {
    if (index < 0 || index >= chunks) throw new CryptoError();
    const sealed = Buffer.alloc(REST_RECORD);
    const { bytesRead } = await handle.read(sealed, 0, REST_RECORD, REST_HEADER + index * REST_RECORD);
    if (bytesRead !== REST_RECORD) throw new CryptoError();
    const flag = index === chunks - 1 ? 1 : 0;
    if (sealed[0] !== flag) throw new CryptoError(); // Reordered or truncated records.
    const decipher = createDecipheriv('chacha20-poly1305', dek, Buffer.concat([noncePrefix, u64(index)]), { authTagLength: CHACHA_TAG });
    decipher.setAAD(restAad(id, index, flag), { plaintextLength: REST_CHUNK });
    decipher.setAuthTag(sealed.subarray(1 + REST_CHUNK));
    let plain;
    try {
      plain = Buffer.concat([decipher.update(sealed.subarray(1, 1 + REST_CHUNK)), decipher.final()]);
    } catch {
      throw new CryptoError();
    }
    const end = index === chunks - 1 ? size - index * REST_CHUNK : REST_CHUNK;
    return plain.subarray(0, end);
  }

  /** Plaintext bytes [start, end) — assembled from the chunks that cover them. */
  async function readRange(start, end) {
    const parts = [];
    for (let index = Math.floor(start / REST_CHUNK); index * REST_CHUNK < end; index++) {
      const plain = await readChunk(index);
      const from = Math.max(start - index * REST_CHUNK, 0);
      const to = Math.min(end - index * REST_CHUNK, plain.length);
      parts.push(plain.subarray(from, to));
    }
    return Buffer.concat(parts);
  }

  return { readChunk, readRange, chunks, dek, header: Buffer.from(header) };
}

/** Rewraps a stored file's DEK with the current key (STORAGE_KEY rotation). */
export function rewrapRestHeader(header, { id, dek, keyring }) {
  const noncePrefix = header.subarray(72, 76);
  return Buffer.concat([MAGIC.rest, keyring.current.id, wrapDek({ id, dek, noncePrefix, keyring }), noncePrefix]);
}

// ---------------------------------------------------------------------------
// Encrypted metadata (format KNM1)
//
//   "KNM1" | kekId(8) | iv(12) | ChaCha20-Poly1305(JSON padded to 256-byte blocks) | tag(16)
//
// Key: HKDF-SHA-512(metadata root key, salt = file id, "kipnest/v1/meta").

function metaKey(root, id) {
  return hkdf('sha512', root, text(id), 'kipnest/v1/meta', 32);
}

export function sealMetadata(keyring, metadata) {
  const json = text(JSON.stringify(metadata));
  const padded = Buffer.alloc(Math.ceil((json.length + 1) / META_BLOCK) * META_BLOCK, 0x20);
  json.copy(padded);
  const iv = randomBytes(12);
  const cipher = createCipheriv('chacha20-poly1305', metaKey(keyring.current.metaKey, metadata.id), iv, { authTagLength: CHACHA_TAG });
  cipher.setAAD(Buffer.concat([MAGIC.meta, text(metadata.id), keyring.current.id]), { plaintextLength: padded.length });
  return Buffer.concat([MAGIC.meta, keyring.current.id, iv, cipher.update(padded), cipher.final(), cipher.getAuthTag()]);
}

export function openMetadata(keyring, id, sealed) {
  if (sealed.length < 4 + 8 + 12 + META_BLOCK + CHACHA_TAG || !sealed.subarray(0, 4).equals(MAGIC.meta)) throw new CryptoError();
  const kekId = sealed.subarray(4, 12);
  const entry = keyring.find(kekId);
  if (!entry) throw new CryptoError('Metadata was encrypted with an unknown STORAGE_KEY.');
  const body = sealed.subarray(24, sealed.length - CHACHA_TAG);
  const decipher = createDecipheriv('chacha20-poly1305', metaKey(entry.metaKey, id), sealed.subarray(12, 24), { authTagLength: CHACHA_TAG });
  decipher.setAAD(Buffer.concat([MAGIC.meta, text(id), kekId]), { plaintextLength: body.length });
  decipher.setAuthTag(sealed.subarray(sealed.length - CHACHA_TAG));
  let metadata;
  try {
    metadata = JSON.parse(Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8'));
  } catch {
    throw new CryptoError();
  }
  if (metadata?.id !== id) throw new CryptoError(); // Swapped between files.
  return metadata;
}

// ---------------------------------------------------------------------------
// Download layer (format KND1)
//
//   "KND1" | header: AES-CTR(JSON padded to 1024) | HMAC(64)
//   then records j = 1..n: AES-CTR(1 MiB; the last one zero-padded to a 64 KiB multiple) | HMAC(64)
//
// Keys: HKDF-SHA-384(sessionKey, downloadNonce, "kipnest/v1/download/<purpose>/<id>")
// → encKey(32) | macKey(32) | ivBase(12). Counter block for record j is
// ivBase | u32(j * 65536), so every record has its own keystream and any record
// can be produced (or resumed) on its own. HMAC-SHA-512 covers
// "KND1" | id | purpose | nonce | u32 j | flag (2 = header, 1 = final, 0 = other) | ciphertext.

export function downloadLayout(size) {
  const chunks = Math.ceil(size / DOWNLOAD_CHUNK);
  const headerEnd = 4 + DOWNLOAD_HEADER_BYTES + MAC_BYTES;
  // The last record is zero-padded to a 64 KiB multiple (the header has the real size).
  const lastLength = roundUp(size - (chunks - 1) * DOWNLOAD_CHUNK, WIRE_BLOCK);
  const recordLength = (j) => (j < chunks ? DOWNLOAD_CHUNK : lastLength);
  return { chunks, headerEnd, recordLength, total: headerEnd + (chunks - 1) * DOWNLOAD_CHUNK + lastLength + chunks * MAC_BYTES };
}

/**
 * Produces bytes [start, end] (inclusive) of the encrypted download. Plaintext
 * exists only one 1 MiB record at a time.
 */
export async function* encryptDownload({ rest, metadata, purpose, sessionKey, nonce, start, end }) {
  const { id, size } = metadata;
  const material = hkdf('sha384', sessionKey, nonce, `kipnest/v1/download/${purpose}/${id}`, 76);
  const encKey = material.subarray(0, 32);
  const macKey = material.subarray(32, 64);
  const ivBase = material.subarray(64, 76);
  const { chunks, headerEnd, recordLength } = downloadLayout(size);
  const purposeByte = Buffer.of(purpose === 'preview' ? 0x70 : 0x64);

  function seal(index, flag, plain) {
    const cipher = createCipheriv('aes-256-ctr', encKey, Buffer.concat([ivBase, u32(index * BLOCKS_PER_DOWNLOAD_CHUNK)]));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    const mac = createHmac('sha512', macKey)
      .update(Buffer.concat([MAGIC.download, text(id), purposeByte, nonce, u32(index), Buffer.of(flag), ciphertext]))
      .digest();
    return Buffer.concat([ciphertext, mac]);
  }

  const segments = [{ from: 0, to: headerEnd, make: () => {
    const json = text(JSON.stringify({ name: metadata.name, type: metadata.type, size, chunkSize: DOWNLOAD_CHUNK }));
    const padded = Buffer.alloc(DOWNLOAD_HEADER_BYTES, 0x20);
    json.copy(padded);
    return Buffer.concat([MAGIC.download, seal(0, 2, padded)]);
  } }];
  for (let j = 1; j <= chunks; j++) {
    const plainStart = (j - 1) * DOWNLOAD_CHUNK;
    const plainEnd = Math.min(size, j * DOWNLOAD_CHUNK);
    const from = headerEnd + (j - 1) * (DOWNLOAD_CHUNK + MAC_BYTES);
    const length = recordLength(j);
    segments.push({ from, to: from + length + MAC_BYTES, make: async () => {
      const plain = Buffer.alloc(length); // Zero padding after the real bytes.
      (await rest.readRange(plainStart, plainEnd)).copy(plain);
      return seal(j, j === chunks ? 1 : 0, plain);
    } });
  }
  for (const segment of segments) {
    if (segment.to <= start || segment.from > end) continue;
    const bytes = await segment.make();
    yield bytes.subarray(Math.max(start - segment.from, 0), Math.min(end + 1 - segment.from, bytes.length));
  }
}

export function safeEqual(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}
