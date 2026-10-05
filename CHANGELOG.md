# Changelog

All notable changes to KipNest are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The version in `package.json` is the source of truth.

How versions are chosen:

- **Major**: a change that breaks an existing installation or the API. Examples: a new storage format that needs a migration, a different authentication scheme, or a different default folder.
- **Minor**: new features or settings that keep existing installations working.
- **Patch**: fixes and documentation.

Versions before 4.1.1 were assigned after the fact, one per milestone in the Git history. Each entry lists the commits it covers, and every version has a Git tag `vX.Y.Z` on its last commit.

How to release: move the `[Release]` entries under a new `## [X.Y.Z] - date` heading, set the same `version` in `package.json` (`npm version X.Y.Z --no-git-tag-version`) and in `info.version` of `docs/openapi.yaml`, commit, then tag that commit `vX.Y.Z` and push the tag. The Release workflow (`.github/workflows/release.yml`) checks that the tag matches `package.json`, builds and tests, and publishes a GitHub release with the `release/` folder as `kipnest-X.Y.Z.zip` and the changelog entry as its notes.

## [Release]

### Added

- The release package has its own installation guide as `README.md` (source: `docs/RELEASE-README.md`), instead of a copy of the developer README that mentioned `npm test`, `npm run dev`, `npm run package`, and other commands a release does not have. It covers installing, the release commands, every setting, running as a service, logs, backups, updating to a new release, and troubleshooting. `SECURITY.md` and `docs/ENCRYPTION.md` now ship too, so its links work.
- `npm run package` fails if the release README mentions a command the release does not have, or if any shipped document links to a file the release does not include.
- GitHub rulesets in `.github/rulesets/`, to import once in Settings → Rules → Rulesets: `master` can never be deleted or force-pushed; changes reach it through a pull request whose CI jobs (`test` on Node.js 22 and 24 for Linux and Windows, `quality`, `e2e`) passed, with a bypass for repository admins; and `v*` release tags can never be moved or deleted. `test/checks.test.js` fails if the required checks no longer match the CI job names.

### Fixed

- CodeQL: the analysis job can read its own workflow run (`actions: read`), so uploading the results no longer fails with "Resource not accessible by integration".
- Release: a tag pushed twice, or a re-run, no longer fails because the GitHub release already exists. Runs for the same tag wait for each other, and the archive is only added when it is missing, never replaced.
- CI, CodeQL, and dependency review cancel a run when a newer push to the same branch or pull request arrives, so superseded jobs stop waiting in the runner queue.

## [5.2.0] - 2026-10-05

### Added

- `docs/openapi.yaml`: an OpenAPI 3.1 (Swagger) reference of the HTTP API, with every route, signed-request header, status code, and JSON shape, readable in Swagger UI, Redoc, or Postman. `test/openapi.test.js` checks it against the running server and against the version in `package.json`. It ships in every release package (`npm run package` and `kipnest-X.Y.Z.zip`) as `docs/openapi.yaml`.

### Changed

- GitHub Actions run on Node.js 24: the `quality`, `e2e`, and release jobs use Node.js 24 (the test matrix keeps 22 and 24), and `actions/checkout` (v4.4.0 to v7.0.1) and `actions/setup-node` (v4.4.0 to v7.0.0) moved off the retired Node.js 20 action runtime. Still pinned to commits, with automatic dependency caching turned off.

### Fixed

- `npm run test:coverage` failed on Node.js 22 and 24 (and so did the CI `quality` job): the 5.1.0 floors were measured on Node.js 20 with the test files counted in. They now match the real coverage of `src/`, `scripts/`, and `server.js`: 90% lines, 87% branches, 91% functions.

## [5.1.0] - 2026-10-05

### Added

- Code validation: `npm run check` runs `check:syntax` (`node --check` on every project file), `lint` ([ESLint](https://eslint.org), configured in `eslint.config.js`; `npm run lint:fix` fixes what it can) and `check:code` (`scripts/check-code.js`, the project's own security rules). `npm run test:coverage` runs the tests with coverage floors (93% lines, 88% branches, 93% functions). CI runs both in a new `quality` job.
- Tests for the startup settings in `server.js`: invalid settings stop the server with a clear message and never print secrets. Another test checks that unexpected errors answer a generic 500 without internal details.
- `test/crypto.test.js`: the page and server encryption code checked against each other for every layer, plus pinned test vectors (`test/fixtures/`), so a change that would make stored files unreadable fails the tests.
- `SECURITY.md`: supported versions, how to report a vulnerability privately, response times, and scope.
- Security automation on GitHub: CodeQL analysis (`security-extended`), dependency review on pull requests (vulnerable packages and licenses not compatible with MIT), and weekly Dependabot updates for npm and the pinned GitHub Actions. CI also runs `npm audit` and `npm audit signatures`.
- `npm run check` fails if Git tracks a `.env`, a key or certificate, stored files, or logs.
- Tests: fuzzing of paths, headers, and damaged uploads (`test/fuzz.test.js`, with a reproducible seed), the same generic 401 for every kind of bad signature, the security headers on every route and outcome, no keys, nonces, MACs, session ids, or file names in the console or the log file, and `server.js` started for real over TLS (TLS 1.2 refused, clean shutdown).

### Changed

- **Sign out** now also ends the session on the server (new signed route `DELETE /api/session`), so it stops working at once instead of when it expires.
- Every response also carries `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`.
- `npm run package` refuses to run while `release/` holds an installation (a `.env`, certificates, stored files, or logs), because it rebuilds that folder from scratch. It also checks the finished copy (`scripts/check-release.js`) and fails if anything private got in.

### Fixed

- File names longer than 180 characters lost their extension when shortened, so a valid file was rejected as the wrong type. They now keep the extension, and the cut never splits an emoji or other two-part character.

## [5.0.1] - 2026-10-05

### Added

- `LICENSE.md`: KipNest is released under the MIT License, © 2026 Webvelopers, INC. (`license` and `author` in `package.json`).
- Every release package (`npm run package`, and the `kipnest-X.Y.Z.zip` attached to GitHub releases) now includes `README.md`, `CHANGELOG.md`, and `LICENSE.md`.

### Changed

- The root `CLAUDE.md` (assistant instructions) is no longer versioned, like `.claude/` and `.opencode/`: it stays local and is gitignored.
- The changelog section for changes not yet in a version is called `[Release]`.

### Fixed

- `npm run build` inside the release folder failed (`Cannot resolve entry module index.html`): the release copied the development `package.json`, whose scripts need the interface sources and Vite. The release `package.json` now keeps only the runtime scripts, and its `build` checks the prebuilt `dist/client/` instead of compiling it.

## [5.0.0] - 2026-10-05

**Upgrading from 4.x:** install Node.js 22 or higher before updating. Nothing else changes for an existing installation: `.env`, the stored files, and their format stay the same. In the browser, the key now has to be pasted again after every page reload.

### Added

- `MAX_FILES` setting (default 1000) for the maximum number of stored files. It replaces a hidden limit; when reached, uploads get `507` with a clear message, and the page says "Too many files" instead of "Out of space".
- Browser tests with Playwright (`npm run test:e2e`, `e2e/`): unlock, wrong key, upload, preview, download, delete, a rejected fake image, sign out, and that the key is never stored. CI runs them in a separate job.
- Git tags `v1.0.0` to `v4.1.2` for every version in this file, and a Release workflow that publishes a GitHub release with `kipnest-X.Y.Z.zip` (the `npm run package` folder) when a `vX.Y.Z` tag is pushed.

### Changed

- **The access key is never stored in the browser.** It used to stay in `sessionStorage` as plain text; now only the non-extractable key derived from it is kept, in the page's memory. Reloading or closing the page locks it again, so you paste the key once more. A key left in `sessionStorage` by an older version is removed on load.
- **Node.js 22 or higher** is required (`engines`); Node.js 20 is no longer supported upstream. CI tests Node.js 22 and 24.
- Success notifications close on their own after 6 seconds (errors stay until closed). They float over the top of the content and used to cover the **Refresh** button until closed by hand.
- The request log records the real size of every response (`bytes`), JSON replies included; it used to log `0` for them.
- `npm run setup` also writes `MAX_CONCURRENT_UPLOADS` and `MAX_FILES`.
- The package is named `kipnest`.
- Internal: one handler per route in `src/server/app.js`, and the integration tests are split by area in `test/`.
- The AI assistant folders `.claude/` and `.opencode/` (skills, agents, and their settings, about 1,675 files) are no longer versioned: they stay installed locally and are gitignored.
- CI runs with read-only permissions, and its actions are pinned to commits.
- Machine-specific files (`FIX_FREEBUFF_CA_CERT.md`, `certs/kaspersky-root-ca.pem`) are no longer part of the repository; README has a generic note on HTTPS inspection instead.

### Fixed

- With `MAX_CONCURRENT_UPLOADS` above 1, simultaneous uploads could together exceed `MAX_STORAGE_MB`, because each one was checked against the same disk usage. Space is now reserved in memory as soon as an upload's size is known, and deleting a file frees it right away.
- `npm run package` no longer deletes the committed `release/.gitignore`, so the release files cannot be committed by mistake.
- An upload rejected for its signature (for example, with an expired session) could reach the browser as a reset connection instead of `401`, so the page could not tell it to open a new session. The server now reads up to 1 MiB of such a request before answering. Seen on Node.js 24 in CI.
- On Linux and macOS, `npm run setup` (and the startup permission check) restricted only the folders themselves: files already inside `storage/uploads/`, `certs/`, or the log folder kept their default mode (usually readable by other users). Their whole contents are now set to owner-only (folders `700`, files `600`), as on Windows; symbolic links are not followed. Seen in CI on Linux (pentest F2 test).
- The startup check that keeps private folders (`UPLOAD_DIR`, `LOG_DIR`, the TLS key, `.env`) out of the web root could miss an overlap when the private path did not exist yet and was spelled through a link, a junction, or a Windows short name (`C:\Users\RUNNER~1\…`). Paths are now compared after resolving their nearest existing folder. Seen in CI on Windows.

## [4.1.2] - 2026-10-05

### Fixed

- `package-lock.json` is committed again. It had been removed and ignored, which broke `npm ci` in CI, `npm run package` on a clean checkout, and the documented deployment (`npm ci --omit=dev`), and undid pentest fix F6.
- CI runs again on pushes: it only listened to `main`, while the repository's branch is `master`. It now runs on both.
- `.env.example` can be copied as `.env` again: its first line (`[TEMPLATE]`) made Node ignore every setting in the file.

### Changed

- `TODO.md` lists the improvement plan from the 2026-10-05 code and documentation review.

## [4.1.1] - 2026-10-02

### Added

- `CHANGELOG.md` (this file), with versions for the whole history; `package.json` is now versioned with it.

### Changed

- README reorganized for readers: contents, quick start, interface guide, a commands table, settings grouped by topic with a full `.env` example, logs, security, production, maintenance, troubleshooting, development, and API.
- New README sections:
  - Backups: what to keep and why `.env` must be stored apart from the files.
  - Upgrading from the previous folder layout.
  - A troubleshooting table based on the real error messages.
  - Notes for FreeBuff behind HTTPS inspection.

### Fixed

- The build output `public/` was committed again by mistake in 4.1.0. It is removed from the repository and now ignored, so it cannot come back.

## [4.1.0] - 2026-10-02

Commit `1a26e89`.

### Added

- **Interaction log** (optional): set `LOG_DIR` to also save every request to disk.
  - One file per UTC day (`kipnest-YYYY-MM-DD.log`), with one JSON line per request.
  - Each line has a readable `action` (`sign-in`, `upload`, `list`, `download`, `preview`, `delete`, …) and `outcome` (`ok`, `denied`, `limited`, `rejected`, `error`).
  - Server events are recorded too: start, stop, fatal errors, internal errors, startup cleanup, and integrity failures.
- `LOG_RETENTION_DAYS` (default 30) deletes older log files automatically. Other files in the folder are never touched.
- The log folder is private to the server's account and refused inside the web root. `npm run setup` adds the settings (commented out) and restricts the folder.
- The console request log now includes `action` and `outcome`.

### Security

- Logs never contain tokens, keys, signatures, session ids, nonces, request headers, or file names (tested).

## [4.0.0] - 2026-10-02

Commits `0cd0893`, `8a54c8a`.

### Changed (breaking)

- **One web root.** The interface is built into `dist/client/`, which is not committed, instead of the committed `public/`. The server only ever publishes that folder. **Run `npm run build` before starting.**
- Source folders moved: `frontend/` became `src/client/`, and `src/app.js` and `src/crypto.js` moved to `src/server/`.
- The default storage folder moved from `uploads/` to `storage/uploads/`. Move your files there, or set `UPLOAD_DIR=uploads`.

### Added

- `UPLOAD_DIR` setting, to keep stored files outside the application folder.
- `npm run package` copies only the runtime files into `release/`, so you deploy a copy rather than the repository checkout.
- `scripts/check-dist.js` runs after every build and fails it if anything that must not be published lands in `dist/client/` (source maps, dotfiles, `.env`, keys). CI runs the build check and the release copy.
- Tests for exposure, path traversal, the web root content, and the startup guards.

### Security

- Static files are read into memory at startup and served from that map only. No request ever builds a path on disk.
- Paths with `..`, `//`, backslashes, or encoded dots, slashes, backslashes, or NUL get the same `404` as an unknown file.
- The server refuses to start if `.env`, `certs/`, the storage folder, the server code, `scripts/`, `test/`, `node_modules/`, `server.js`, or `package.json` overlap the web root. The check runs again after the storage folder is created, to catch links and junctions.
- The Vite build never loads `.env` and emits no source maps. The Vite development server may only read `src/client/`, and it denies `.env`, keys, `certs/`, `storage/`, and the server code.

### Documentation

- AGENTS.md rule 9, "One web root". README sections on deployment and reverse proxies.

## [3.0.0] - 2026-10-02

Commit `98c6c51`: penetration test, remediation, and retest.

### Changed (breaking)

- **The token never leaves the browser.** `Authorization: Bearer` is no longer accepted.
  - Sign-in is an HMAC proof made with a key derived from the token, with a timestamp. Each proof works once, within 5 minutes.
  - Every API request is signed with the session: `X-Session-Id`, `X-Request-Time`, `X-Request-Nonce`, and `X-Request-Mac`. The signature also covers the query, `Range`, and `X-Download-Nonce`, and each nonce is accepted once.
- Only TLS 1.3 is accepted.

### Added

- `npm run start:supervised` (`scripts/supervise.js`) restarts the server after a crash.
  - The wait between restarts grows while crashes repeat.
  - It stops after 3 consecutive startup failures.
- `scripts/permissions.js`: `npm run setup` and `npm run cert` make `.env`, the TLS private key, and the storage folder private. On Windows this uses `icacls`.
- The server warns at startup when other local users can read any of them.
- `HEAD` works on `/`, the assets, `/healthz`, and `/api/config`.

### Security

- **F1 (Medium).** An oversized sign-in request could crash the server. Fixed.
  - Unexpected errors are now logged, and the process exits with code 1 so a supervisor can restart it.
- **F2 (Medium).** On Windows, every local user could read the secrets. Fixed with owner-only permissions.
- **F3.** HSTS is sent on every HTTPS response.
- **F4.** The brute-force block was per IP only, and it could lock the owner out.
  - Blocks now double from 1 minute up to 1 hour, and are remembered for 24 hours.
  - IPv4-mapped IPv6 counts as IPv4, and IPv6 is grouped by /64.
  - The block applies only to sign-ins and invalid signatures, so open sessions keep working.
- **F5.** One user could flood the session table. Sign-ins are now limited to 30 per minute per address.
- **F6.** `package-lock.json` is committed, and CI installs with `npm ci`.
- **F8.** Stalled connections are checked every 5 s. Logging is documented. The local certificate files are named `local-cert.pem`/`local-key.pem`.
- Retest findings N1–N3 fixed: a shared-address block no longer blocks open sessions, and signed requests can no longer be replayed.
- Exact sizes are hidden on the wire: the last upload and download records are padded to 64 KiB, and the headers and sealed replies to 1 KiB blocks.
- The graphify version is pinned, and the third-party developer tools were audited (F7).

### Fixed

- Large downloads (50 MB or more) in Chromium are written straight to disk. A download is restarted cleanly if the session expires mid-transfer.

## [2.0.0] - 2026-10-01

Commit `55065e9`.

### Changed (breaking)

- **Files and their details are encrypted in transit, at rest, and on download**, on top of HTTPS. Plain `multipart` uploads are rejected.
- Stored files became `<uuid>.bin` (content) and `<uuid>.meta` (details), and nothing in them is readable. The server refuses to start while unencrypted files from 1.x remain; run `npm run encrypt:migrate`.

### Added

- **Upload layer:**
  - Session handshake `POST /api/session`: ECDH P-256 mixed with a PBKDF2 key derived from the token.
  - Files are encrypted in the page before they are sent (AES-256-GCM, 1 MiB pieces).
- **At-rest layer:**
  - Each file has its own random key (ChaCha20-Poly1305, 64 KiB pieces), wrapped with the new `STORAGE_KEY`.
  - Details are encrypted separately, and sizes are padded to 64 KiB.
- **Download layer:**
  - Downloads are re-encrypted per session (AES-256-CTR plus HMAC-SHA-512 per 1 MiB piece).
  - Every piece is verified in the page before the file is saved in its original format and name.
  - Downloads resume from the last verified piece.
- The file list, storage stats, and upload receipts are encrypted for the session.
- `STORAGE_KEY`, `STORAGE_KEY_PREVIOUS`, and `KDF_SALT` settings. `npm run setup` adds missing keys and keeps the existing ones.
- `npm run encrypt:migrate` (with `--dry-run`) and `npm run encrypt:rotate` (re-wraps keys without re-encrypting content).
- `docs/ENCRYPTION.md`: formats, key schedule, and threat model.
- "Encrypting…" and "Decrypting…" steps in the interface.
- A README section "How your files are protected".

## [1.2.0] - 2026-10-01

Commit `16406cb`.

### Changed

- The product is renamed **KipNest**, "a friendly, secure file server".
- New interface text in a friendlier voice.
  - "Unlock your space" and "You're in!" on sign-in.
  - Blame-free error messages that say what to do next.
- The top-bar state is now a padlock: grey and closed when locked, green and open when unlocked, red when the key is not working. It is also exposed to screen readers.
- Visual refinements to the layout, the cards, and the image previews.

## [1.1.0] - 2026-10-01

Commits `e49508e`, `94aa918`, `d9dbeab`.

### Changed

- The interface was redesigned as three screens behind a bottom navigation bar: **Account** (unlock), **Upload**, and **Your files**. The flat teal design is kept.
- The upload and file screens stay hidden until the key is verified, and **Sign out** returns to the unlock screen.

### Added

- Developer tooling for AI assistants: the ECC agents and skills for Claude Code and OpenCode, and the graphify knowledge graph (`graphify-out/`, which is not committed). These have no effect on the server or the published interface.

### Fixed

- The missing `.eyebrow` style in the top bar.

## [1.0.0] - 2026-10-01

Commit `9c37682`: first version.

### Added

- **Server:**
  - A native Node.js HTTPS server without a framework.
  - Streamed uploads with `busboy`, and content checks with `file-type`.
- **File handling:**
  - PNG, JPG/JPEG, PDF, and UTF-8 TXT only, checked by content and never by the type the browser sends.
  - UUID storage names, with names that are safe on Windows and in Unicode.
  - Temporary writes with cleanup on failure.
- **Access:**
  - A shared access token (`Authorization: Bearer`, compared in constant time).
  - A temporary block after repeated failures.
  - Cross-site requests are rejected, and there is no CORS.
- **Limits:**
  - 100 MiB per file and 1 GiB in total by default.
  - One upload at a time by default, configurable with `MAX_CONCURRENT_UPLOADS`.
  - Upload timeout.
- **API:**
  - `/api/config`, `/api/files`, `/api/upload`, `/api/stats`, and `/healthz`.
  - Image preview and resumable download (`Range`).
  - `DELETE /api/files/:id`.
- **Response headers:** CSP, `nosniff`, `X-Frame-Options`, `no-store`, and `X-Request-Id`, plus JSON request logs without credentials.
- **Interface:**
  - A mobile-app-style page built with Tailwind CSS 4 and Vite.
  - Upload queue with progress and per-file retry.
  - Thumbnails and enlarged previews.
  - Downloads that keep the original name.
  - Light and dark themes.
- **Commands:** `npm run setup` (`.env` with a random token) and `npm run cert` (local certificate with mkcert).
- Integration tests with `node:test`, and CI on Node.js 20 and 22 on Linux and Windows.
- The UI/UX Pro Max design skill for Claude Code and OpenCode.

