# KipNest

A friendly, secure file server: upload, browse, and download your files privately.

This folder is a **ready-to-run KipNest release**: the server, the prebuilt web interface, and the scripts needed to install, run, and maintain it. It has no sources, tests, or development tools; those live in the KipNest repository. The version is the `version` field in `package.json`, and what changed in each version is in [CHANGELOG.md](CHANGELOG.md).

**Contents**

- [Install](#install)
- [Commands](#commands)
- [Using KipNest](#using-kipnest)
- [Configuration](#configuration)
- [Running it as a service](#running-it-as-a-service)
- [Logs](#logs)
- [Backups](#backups)
- [Updating to a new release](#updating-to-a-new-release)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [API](#api)
- [License](#license)

## Install

**Requirements:** Node.js **22 or higher** and npm. For a local certificate, [mkcert](https://github.com/FiloSottile/mkcert) on the `PATH` (on Windows with Scoop: `scoop install mkcert`); you can use your own certificate instead.

Run every command inside this folder, as the account that will run the server:

```sh
npm ci --omit=dev   # runtime dependencies only (busboy and file-type)
npm run setup       # creates .env with a random access key and the encryption keys
npm run cert        # creates the HTTPS certificate in certs/ (skip it if you bring your own)
npm start           # starts the server
```

1. Open **https://127.0.0.1:3000**, or the address printed in the console if you changed `HOST` or `PORT`.
2. Copy the value of `UPLOAD_TOKEN` from `.env`, paste it into the page, and press **Unlock**.
3. Pick one or more files (PNG, JPG/JPEG, PDF, or TXT) and press **Upload**.

> **Back up `.env` now.** Its `STORAGE_KEY` encrypts every stored file. If it is lost, nobody can recover the files.

Moving an existing installation? Copy its `.env` here instead of running `npm run setup`, and point `UPLOAD_DIR` at its files (see [Updating to a new release](#updating-to-a-new-release)).

## Commands

These are the only scripts in this release:

| Command | What it does |
| --- | --- |
| `npm run setup` | Creates `.env` with a 64-character access key and new encryption keys. On an existing `.env` it only adds missing keys and never replaces one. It also makes `.env`, `certs/`, and the storage and log folders private to your account. |
| `npm run cert` | Creates `certs/local-cert.pem` and `certs/local-key.pem` with mkcert. Existing files are kept. |
| `npm start` | Starts the HTTPS server. |
| `npm run start:supervised` | Same as `npm start`, but restarts the server automatically after a crash. |
| `npm run build` | Checks the prebuilt interface in `dist/client/`. It does not compile anything: the interface comes ready in this release. |
| `npm run encrypt:migrate` | Encrypts files left by an older, unencrypted version. Preview first with `npm run encrypt:migrate -- --dry-run`. |
| `npm run encrypt:rotate` | Re-wraps stored files after changing `STORAGE_KEY` (see [Rotating STORAGE_KEY](#rotating-storage_key)). |

## Using KipNest

The page works like a phone app, with three tabs at the bottom: **Account**, **Upload**, and **Your files**.

- **Unlock** with the access key (`UPLOAD_TOKEN`). The key is never stored by the browser and never sent to the server: reloading or closing the page locks it again. **Sign out** ends the session on the server at once.
- **Upload** encrypts each file in the page before sending it. Only PNG, JPG/JPEG, PDF, and TXT are accepted, and the server checks that the content really matches the type.
- **Your files** lets you view photos, download any file with its original name, and delete files to free space.

Everyone who has the access key sees the same files: KipNest has one shared key and no user accounts.

## Configuration

All settings live in `.env` in this folder. `npm run setup` creates it; [.env.example](.env.example) lists every setting with a comment. The server reads `.env` only at startup, so **restart it after any change**. Missing values use the defaults below, and an invalid value stops the server with a message that names the setting.

| Variable | Default | Description |
| --- | --- | --- |
| **Network** | | |
| `HOST` | `127.0.0.1` | Address to listen on. The default only accepts connections from this computer; use a LAN address (or `0.0.0.0`) to allow other devices. |
| `PORT` | `3000` | HTTPS port. |
| `TLS_CERT_FILE` | `certs/local-cert.pem` | Certificate in PEM format, absolute or relative to this folder. |
| `TLS_KEY_FILE` | `certs/local-key.pem` | Private key in PEM format, absolute or relative to this folder. |
| **Access and keys** | | |
| `UPLOAD_TOKEN` | New one at each start | Shared access key: at least 32 ASCII characters, no spaces. Without it, a temporary key is printed at every start. |
| `STORAGE_KEY` | Required | 32 random bytes in base64url (`npm run setup`). Encrypts stored files and their details. The server refuses to start without it and never invents one. |
| `STORAGE_KEY_PREVIOUS` | Empty | Only while rotating keys: old `STORAGE_KEY` values, comma-separated. |
| `KDF_SALT` | Required | 16 random bytes in base64url (`npm run setup`). Per-installation salt for the access key; not secret. |
| **Folders and logs** | | |
| `UPLOAD_DIR` | `storage/uploads` | Folder for the encrypted files, absolute or relative to this folder. Prefer a folder outside the application (for example `/var/lib/kipnest` or `C:\ProgramData\KipNest`), so updates never touch it. |
| `LOG_DIR` | Empty (off) | Folder for the [interaction log](#logs), for example `storage/logs`. |
| `LOG_RETENTION_DAYS` | `30` | Days of log files to keep (1–3650). |
| **Limits** | | |
| `MAX_FILE_MB` | `100` | Maximum size of each file, in MiB. |
| `MAX_STORAGE_MB` | `1024` | Total storage, in MiB, including each file's encrypted details. |
| `MAX_FILES` | `1000` | Maximum number of stored files (1–1000000). |
| `UPLOAD_TIMEOUT_SECONDS` | `300` | Maximum receive and idle time per upload. |
| `MAX_CONCURRENT_UPLOADS` | `1` | Simultaneous uploads (1–16). |

**File permissions.** `.env`, the private key, the stored files, and the logs must be readable only by the account that runs the server. `npm run setup` and `npm run cert` restrict them for you (on Windows with `icacls`), and the server warns at startup if other local users can still read any of them.

## Running it as a service

- **HTTPS certificate.** `npm run cert` creates a certificate for `localhost`, `127.0.0.1`, `::1`, and the `HOST` from `.env`. Other devices must trust mkcert's authority (`rootCA.pem`, in the folder shown by `mkcert -CAROOT`; never share `rootCA-key.pem`). For access from the Internet, use a certificate from a public authority (`TLS_CERT_FILE`/`TLS_KEY_FILE`) or put HTTPS on a reverse proxy.
- **Supervision.** Run `npm run start:supervised`, or wrap `npm start` in a Windows service, pm2, systemd, or a Docker restart policy, as the account that owns `.env` and `certs/`. After an unexpected error the server exits with code 1 so it can be started clean; if it fails 3 times in a row right at startup, the supervisor stops and leaves the error on screen.
- **Stopping.** `Ctrl+C` waits for requests in progress (up to the upload timeout); a second `Ctrl+C` exits immediately.
- **Health check.** `GET /healthz` answers `{ "status": "ok" }` without authentication.
- **Reverse proxy** (nginx, IIS, Caddy): forward every request to the Node server, raise its maximum request size and timeouts to match `MAX_FILE_MB` and `UPLOAD_TIMEOUT_SECONDS`, and never let it serve this folder itself (no `root` directive or physical path pointing here).

## Logs

Every request is written to the console as one JSON line (`time`, `requestId`, `action`, `outcome`, `method`, `path`, `status`, `durationMs`, `bytes`, `ip`). Paths contain file ids, never file names; keys, signatures, and request headers are never logged.

Set `LOG_DIR` (for example `LOG_DIR=storage/logs`) and restart to also keep them on disk: one file per UTC day, `kipnest-YYYY-MM-DD.log`, plus server events (`start`, `stop`, `error`, `integrity`, …). Files older than `LOG_RETENTION_DAYS` are deleted automatically. Client IP addresses can be personal data, so choose a retention period your privacy rules allow.

## Backups

Back up **both** of these, together:

- `.env`, above all `STORAGE_KEY` and `KDF_SALT`. Without them the files cannot be decrypted.
- The upload folder (`storage/uploads/` or `UPLOAD_DIR`), keeping each file's `.bin` and `.meta` halves together.

Stop the server, or back up while no upload is running. Keep `.env` apart from the file backup, because anyone who has both can read everything. Logs and certificates are optional: certificates can be recreated.

## Updating to a new release

1. Stop the server and back up (see [Backups](#backups)).
2. Unzip the new release into a **new** folder.
3. Copy your `.env` into it, and your `certs/` if you use the generated certificate. If your files are in this folder's `storage/uploads/`, move that folder too, or set `UPLOAD_DIR` to where they are.
4. In the new folder, run `npm ci --omit=dev`, then `npm run setup` (it only adds settings that are new in this version and keeps your keys).
5. Start the server. Keep the old folder until everything works.

Read [CHANGELOG.md](CHANGELOG.md) first: a new major version (for example 5.x to 6.0) can need an extra step, and it is described there.

### Upgrading from an unencrypted version

The server refuses to start while the upload folder still holds files from an older, unencrypted version. Run `npm run setup` (adds the keys), then:

```sh
npm run encrypt:migrate -- --dry-run
npm run encrypt:migrate
```

Each file is checked, encrypted, decrypted back, and compared before its plaintext copy is deleted. Files that fail are left untouched and listed, and the command is safe to run again.

### Rotating STORAGE_KEY

1. Stop the server.
2. Move the current key to `STORAGE_KEY_PREVIOUS`, and put a new 32-byte base64url key in `STORAGE_KEY`.
3. Run `npm run encrypt:rotate`. Only each file's small key header is rewritten.
4. Remove `STORAGE_KEY_PREVIOUS` and start the server.

## Security

Files and their details (name, type, size, date) are encrypted in the page before upload, stored encrypted with a per-file key locked by `STORAGE_KEY`, and re-encrypted for your session on download, all on top of TLS 1.3. The access key itself never travels: signing in is a proof made with a key derived from it, and every request is signed. Repeated wrong keys from one address are blocked for a while. The full design is in [docs/ENCRYPTION.md](docs/ENCRYPTION.md).

Not covered: someone who controls the running server process, a weak access key (use the 64-character one from `npm run setup`), and malicious code inside the page. The content checks are not an antivirus.

Found a vulnerability? Report it privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## Troubleshooting

| Message or symptom | What to do |
| --- | --- |
| `HTTPS certificate is missing. Run npm run cert…` | Run `npm run cert`, or check `TLS_CERT_FILE`/`TLS_KEY_FILE`. |
| `Install mkcert and add it to the PATH` | Install mkcert (`scoop install mkcert` on Windows) and open a new terminal, or use your own certificate. |
| `The web root … has no index.html…` | This folder is incomplete: unzip the release again. `npm run build` tells you what is missing. |
| `STORAGE_KEY must be 32 random bytes in base64url…` (or `KDF_SALT`) | Run `npm run setup`. It adds missing keys without touching the others. Never replace an existing `STORAGE_KEY`, or stored files become unreadable. |
| `UPLOAD_TOKEN must contain at least 32 ASCII characters…` | Use a longer key, or remove the line to get a temporary one. |
| `… must be a positive integer` / `… must be 16 or less` | Fix the named setting in `.env`. |
| `The web root (…) and … overlap` | Move `UPLOAD_DIR`, `LOG_DIR`, or the certificate outside `dist/client/`. |
| `The upload folder still contains unencrypted files…` | See [Upgrading from an unencrypted version](#upgrading-from-an-unencrypted-version). |
| `Warning: other users on this computer can access: …` | Run `npm run setup` as the account that runs the server. |
| `The server could not be started: … EADDRINUSE` | Another program, or another KipNest, uses the port. Stop it or change `PORT`. |
| The list is empty after updating | The new folder does not see your files: move them or set `UPLOAD_DIR` (see [Updating to a new release](#updating-to-a-new-release)). |
| The browser warns about the certificate on another device | That device must trust mkcert's authority (`rootCA.pem`); see [Running it as a service](#running-it-as-a-service). |
| Unlock keeps failing after several wrong keys | The address is blocked for a while: 1 minute, doubling up to 1 hour. Wait, then use the right key; restarting the server also clears the block. |
| No log files appear | Check that `LOG_DIR` is set in `.env` and restart; the console should show `Interaction log: …`. |

## API

The full HTTP reference is the OpenAPI 3.1 spec in [docs/openapi.yaml](docs/openapi.yaml); open it in Swagger UI, [Swagger Editor](https://editor.swagger.io), Redoc, or Postman. Only `/api/config`, the sign-in handshake (`POST /api/session`), and `/healthz` work without a signed request, and file contents and lists are always encrypted for the session, so plain uploads such as `curl -F` are rejected. Scripts need the KipNest client code, which is in the repository (`src/client/crypto.js`), not in this release.

## License

[MIT](LICENSE.md) © 2026 Webvelopers, INC.
