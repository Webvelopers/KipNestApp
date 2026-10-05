# Security policy

KipNest stores private files, so security reports are welcome and handled first.

## Supported versions

Only the latest release gets security fixes. Update before reporting, and check whether the problem is already fixed in [CHANGELOG.md](CHANGELOG.md).

| Version | Supported |
| ------- | --------- |
| 5.x     | Yes       |
| < 5.0   | No        |

KipNest needs a supported Node.js release (22 or higher). Problems that only happen on an end-of-life Node.js version are out of scope.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a vulnerability.**

Report it privately through GitHub: open the repository's **Security** tab, choose **Report a vulnerability**, and fill in the form ([GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)). Only the maintainers can see it.

Please include:

- the KipNest version (`version` in `package.json`), the Node.js version, and the operating system;
- the affected part (sign-in, uploads, downloads, storage, the page, the scripts);
- steps to reproduce, or a proof of concept, and what an attacker gains;
- whether the problem is already public.

Never include a real `UPLOAD_TOKEN`, `STORAGE_KEY`, `.env` file, stored file, or log from an installation: test values are enough.

What happens next:

- We confirm we received the report within 5 working days.
- We confirm or reject the problem within 14 days, and keep you updated.
- A fix ships in a new release, recorded under **Security** in `CHANGELOG.md`, followed by a GitHub security advisory. We credit you unless you prefer otherwise.
- Please keep the problem private until the fixed release is published, or for 90 days if no fix is ready by then.

## Scope

The full threat model, with what each encryption layer protects, is in [docs/ENCRYPTION.md](docs/ENCRYPTION.md#threat-model).

**In scope**, for example:

- getting into files, file details, the file list, or a session without the access token;
- reading content or details from the upload folder or its backups without `STORAGE_KEY`;
- changing, swapping, or replaying data in transit or on disk without it being detected;
- uploading content that does not match its type, getting past the size, quota, file count, or sign-in limits, or reading files outside the web root (`dist/client/`);
- crashing or stalling the server with requests (beyond plain traffic volume);
- the page running injected code (XSS), or secrets showing up in logs, error messages, URLs, or browser storage;
- the setup, migration, rotation, and release scripts exposing keys or files.

**Out of scope**, as documented limits:

- someone who controls the running server process, or has both the upload folder and `STORAGE_KEY`;
- guessing a weak, hand-chosen token (use the 256-bit token from `npm run setup`);
- what traffic volume reveals: the number of files, the 64 KiB size bucket, and when requests happen;
- a compromised browser, operating system, or browser extension;
- the content of a valid PDF or image being harmful: content checks are not an antivirus;
- volumetric denial of service, and reports from automated scanners without a working impact.

## Safe harbor

Testing your own installation, with your own data, in good faith and within this policy, is welcome. Do not access other people's installations or data, and do not degrade a service you do not own.
