// Keeps KipNest running: starts server.js and starts it again if it exits with
// an error (for example after the fail-fast handler logs an unexpected
// exception). Waits grow from 1 s to 30 s while crashes repeat, and reset
// after a minute of healthy running. If the server keeps failing right at
// startup (a bad .env value, a missing certificate, a busy port), restarting
// cannot help, so the supervisor stops and leaves the error on screen.
//
//   npm run start:supervised
//
// For an always-on install, prefer the operating system's own supervisor (a
// Windows service, systemd, or a Docker restart policy) running npm start.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const serverPath = fileURLToPath(new URL('../server.js', import.meta.url));
const HEALTHY_AFTER_MS = 60_000;
const STARTUP_FAILURE_MS = 10_000; // Exiting this fast means a configuration problem.
const MAX_STARTUP_FAILURES = 3;
let delay = 1000;
let startupFailures = 0;
let child;
let stopping = false;

function start() {
  const startedAt = Date.now();
  child = spawn(process.execPath, [serverPath], { stdio: 'inherit' });
  child.on('exit', (code, signal) => {
    if (stopping || code === 0) {
      process.exit(code ?? 0);
      return;
    }
    const lived = Date.now() - startedAt;
    if (lived > HEALTHY_AFTER_MS) delay = 1000;
    startupFailures = lived < STARTUP_FAILURE_MS ? startupFailures + 1 : 0;
    if (startupFailures >= MAX_STARTUP_FAILURES) {
      console.error(`[supervisor] The server failed to start ${MAX_STARTUP_FAILURES} times in a row. Fix the error above, then start it again.`);
      process.exit(1);
      return;
    }
    console.error(`[supervisor] Server stopped (${signal || `exit code ${code}`}). Restarting in ${delay / 1000} s…`);
    setTimeout(start, delay);
    delay = Math.min(delay * 2, 30_000);
  });
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    stopping = true;
    if (!child || child.exitCode !== null) {
      process.exit(0);
      return;
    }
    // On Windows, Ctrl+C already reaches the server directly, and kill()
    // would terminate it at once instead of letting it finish in-flight
    // requests. Elsewhere, forward the signal so the server shuts down
    // gracefully (see server.js).
    if (process.platform !== 'win32' || signal === 'SIGTERM') child.kill(signal);
  });
}

start();
