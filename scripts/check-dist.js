// Post-build check (run by npm run build and in CI): the web root dist/client
// must only contain files the server is allowed to serve. A source map, a
// dotfile, a .env, a key, or source code there means something leaked into
// the build, so the build fails instead of shipping it.
import { lstat, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WEB_ROOT, isPublicFile } from '../src/server/app.js';

/** Returns the problems found in `webRoot` (an empty list means it is clean). */
export async function checkDist(webRoot = WEB_ROOT) {
  const problems = [];
  async function walk(directory, prefix) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relative = prefix + entry.name;
      const stats = await lstat(path.join(directory, entry.name));
      if (stats.isSymbolicLink()) problems.push(`${relative}: symbolic link`);
      else if (stats.isDirectory()) {
        if (isPublicFile(`${relative}/x.html`)) await walk(path.join(directory, entry.name), `${relative}/`);
        else problems.push(`${relative}/: folder name not allowed`);
      } else if (!stats.isFile() || !isPublicFile(relative)) problems.push(`${relative}: file type or name not allowed`);
    }
  }
  try {
    await walk(webRoot, '');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    problems.push('the folder does not exist');
  }
  if (!problems.length) {
    try {
      await lstat(path.join(webRoot, 'index.html'));
    } catch {
      problems.push('index.html is missing');
    }
  }
  return problems;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const webRoot = process.argv[2] ? path.resolve(process.argv[2]) : WEB_ROOT;
  const problems = await checkDist(webRoot);
  const shown = path.relative(fileURLToPath(new URL('../', import.meta.url)), webRoot) || webRoot;
  if (problems.length) {
    console.error(`${shown} must only contain files the server may serve:`);
    for (const problem of problems) console.error(`  - ${problem}`);
    process.exitCode = 1;
  } else {
    console.log(`${shown} only contains servable files.`);
  }
}
