// Keeps secrets private to the account that runs KipNest: .env (token and
// encryption keys), the TLS private key, and the upload folder. POSIX file modes such as
// 0o600 are ignored on Windows, so there the ACL is set with icacls instead.
import { execFileSync } from 'node:child_process';
import { chmodSync, lstatSync, readdirSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Well-known Windows SIDs that mean "other people on this machine", so the
// check works whatever the system language is.
const BROAD_SIDS = new Set([
  'S-1-1-0', // Everyone
  'S-1-5-7', // Anonymous
  'S-1-5-11', // Authenticated Users
  'S-1-5-32-545', // Users
  'S-1-5-32-546', // Guests
]);
const SYSTEM_SID = 'S-1-5-18';

function windowsAccount() {
  return process.env.USERDOMAIN && process.env.USERNAME
    ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
    : os.userInfo().username;
}

function existing(paths) {
  return paths.filter((target) => {
    try {
      statSync(target);
      return true;
    } catch {
      return false;
    }
  });
}

/**
 * Removes inherited and broad access: only the current user (and SYSTEM on
 * Windows, for backups and antivirus) can read or change these paths. Folder
 * contents get the same restriction, on every platform.
 */
export function restrictToOwner(paths) {
  const restricted = [];
  for (const target of existing(paths)) {
    const directory = statSync(target).isDirectory();
    if (process.platform === 'win32') {
      const rights = directory ? '(OI)(CI)F' : 'F';
      execFileSync('icacls', [target, '/inheritance:r', '/grant:r', `${windowsAccount()}:${rights}`, '/grant:r', `*${SYSTEM_SID}:${rights}`], { stdio: 'ignore' });
      // Children follow the folder. An empty folder has nothing to reset (icacls
      // fails on the empty wildcard), but any other failure must surface.
      if (directory && readdirSync(target).length) {
        execFileSync('icacls', [`${target}\\*`, '/reset', '/T', '/Q'], { stdio: 'ignore' });
      }
    } else {
      restrictPosix(target);
    }
    restricted.push(target);
  }
  return restricted;
}

// POSIX modes are not inherited: files already inside a folder keep their own
// (usually 0o644), so the whole tree is set, like icacls /T does on Windows.
// Symbolic links are never followed, so nothing outside the target changes.
function restrictPosix(target) {
  const info = lstatSync(target);
  if (info.isSymbolicLink()) return;
  chmodSync(target, info.isDirectory() ? 0o700 : 0o600);
  if (info.isDirectory()) {
    for (const name of readdirSync(target)) restrictPosix(path.join(target, name));
  }
}

/** Returns the paths that other local users can access. Never throws. */
export function findLoosePermissions(paths) {
  const targets = existing(paths);
  if (!targets.length) return [];
  try {
    if (process.platform !== 'win32') {
      return targets.filter((target) => (statSync(target).mode & 0o077) !== 0);
    }
    const quoted = targets.map((target) => `'${target.replaceAll("'", "''")}'`).join(',');
    const script = `foreach ($p in @(${quoted})) { foreach ($a in (Get-Acl -LiteralPath $p).Access) { if ($a.AccessControlType -eq 'Allow') { try { $p + [char]9 + $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {} } } }`;
    const output = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
    const loose = new Set();
    for (const line of output.split(/\r?\n/)) {
      const [target, sid] = line.split('\t');
      if (sid && BROAD_SIDS.has(sid.trim())) loose.add(target);
    }
    return [...loose];
  } catch {
    return []; // The check is advisory; it must never stop the server.
  }
}
