import { spawn } from "node:child_process";
import { closeSync, existsSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(realpathSync(fileURLToPath(import.meta.url)));
const repoCli = resolve(here, "..", "..", "..", "bin", "agy-profiles");
const fallbackCli = join(homedir(), ".local", "bin", "agy-profiles");
const cliBin = existsSync(repoCli) ? repoCli : fallbackCli;

let preloadJs = "";
try {
  const resolvedPreload = import.meta.resolve("sidecar_sdk/preload.js");
  preloadJs = resolvedPreload.startsWith("file://")
    ? fileURLToPath(resolvedPreload)
    : resolvedPreload;
} catch {
  const appDataDir =
    process.env.ANTIGRAVITY_APP_DATA_DIR || join(homedir(), ".gemini", "antigravity");
  const candidate = join(appDataDir, "lib", "node_modules", "sidecar_sdk", "preload.js");
  if (existsSync(candidate)) {
    preloadJs = candidate;
  }
}

const pyCandidates = [
  "/opt/homebrew/bin/python3",
  "/usr/local/bin/python3",
  "/usr/bin/python3",
];
const pyBin = pyCandidates.find((p) => existsSync(p)) || "python3";

const extraPath = [
  join(homedir(), ".local", "bin"),
  "/opt/homebrew/bin",
  "/usr/local/bin",
  "/usr/bin",
  "/bin",
  "/usr/sbin",
  "/sbin",
  process.env.PATH || "",
]
  .filter(Boolean)
  .join(":");

const env = {
  ...process.env,
  PATH: extraPath,
};
if (preloadJs) {
  env.AGY_SIDECAR_PRELOAD_JS = preloadJs;
}

const child = spawn(pyBin, [cliBin, "web", "--sidecar", "--no-open"], {
  env,
  stdio: ["ignore", "inherit", "inherit"],
});

const rawRecoveryMs = Number(process.env.AGY_SIDECAR_RECOVERY_INTERVAL_MS || "300000");
const RECOVERY_INTERVAL_MS = Number.isFinite(rawRecoveryMs) ? Math.max(30_000, Math.round(rawRecoveryMs)) : 300_000;
const AUTH_SETTLE_DELAY_MS = 6_000;
const LOG_POLL_INTERVAL_MS = 5_000;
const AUTH_REFRESH_MARKER = "auth succeeded, refreshing features and managers";
const hostLsLogPath = join(homedir(), "Library", "Logs", "Antigravity", "language_server.log");

let recoveryRunning = false;
let authSettleTimer = null;
let lastLsLogOffset = null;

function runRecoveryPass(reason) {
  if (recoveryRunning) {
    return;
  }
  recoveryRunning = true;
  let stdout = "";
  let stderr = "";
  let settled = false;

  const recChild = spawn(pyBin, [cliBin, "recover", "--json"], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const killTimer = setTimeout(() => {
    if (!settled && !recChild.killed) {
      recChild.kill("SIGTERM");
    }
  }, 60_000);

  const finish = () => {
    if (settled) {
      return;
    }
    settled = true;
    clearTimeout(killTimer);
    recoveryRunning = false;
  };

  recChild.stdout?.on("data", (chunk) => {
    stdout += chunk.toString("utf8");
  });
  recChild.stderr?.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  recChild.on("error", (err) => {
    finish();
    console.error(JSON.stringify({ sidecar_recovery: reason, error: String(err?.message || err) }));
  });
  recChild.on("close", (code) => {
    finish();
    if (code !== 0) {
      console.error(JSON.stringify({ sidecar_recovery: reason, exit_code: code, stderr: stderr.trim().slice(0, 240) }));
      return;
    }
    try {
      const parsed = JSON.parse(stdout);
      const resumed = Number(parsed?.resumed_total || 0);
      if (resumed > 0) {
        console.error(
          JSON.stringify({
            sidecar_recovery: reason,
            resumed_total: resumed,
            resumed_conversations: parsed?.resumed_conversations || [],
          })
        );
      }
    } catch {
      // Ignore partial stdout parse issues.
    }
  });
}

function pollHostAuthRefreshLog() {
  if (!existsSync(hostLsLogPath)) {
    lastLsLogOffset = null;
    return;
  }
  let size = 0;
  try {
    size = statSync(hostLsLogPath).size;
  } catch {
    return;
  }
  if (lastLsLogOffset === null) {
    lastLsLogOffset = size;
    return;
  }
  if (size === lastLsLogOffset) {
    return;
  }
  const prevOffset = size < lastLsLogOffset ? Math.max(0, size - 65_536) : lastLsLogOffset;
  const readStart = Math.max(prevOffset, size - 262_144);
  const readLen = size - readStart;
  lastLsLogOffset = size;
  if (readLen <= 0) {
    return;
  }
  let chunk = "";
  let fd = -1;
  try {
    fd = openSync(hostLsLogPath, "r");
    const buf = Buffer.allocUnsafe(readLen);
    const bytesRead = readSync(fd, buf, 0, readLen, readStart);
    chunk = buf.subarray(0, bytesRead).toString("utf8").toLowerCase();
  } catch {
    return;
  } finally {
    if (fd >= 0) {
      try {
        closeSync(fd);
      } catch {
        // Ignore close error.
      }
    }
  }
  if (chunk.includes(AUTH_REFRESH_MARKER)) {
    if (authSettleTimer !== null) {
      clearTimeout(authSettleTimer);
    }
    authSettleTimer = setTimeout(() => {
      authSettleTimer = null;
      runRecoveryPass("auth_refresh");
    }, AUTH_SETTLE_DELAY_MS);
  }
}

pollHostAuthRefreshLog();
const periodicTimer = setInterval(() => runRecoveryPass("periodic_5m"), RECOVERY_INTERVAL_MS);
const logWatchTimer = setInterval(pollHostAuthRefreshLog, LOG_POLL_INTERVAL_MS);

function stopBackgroundLoops() {
  clearInterval(periodicTimer);
  clearInterval(logWatchTimer);
  if (authSettleTimer !== null) {
    clearTimeout(authSettleTimer);
    authSettleTimer = null;
  }
}

const forwardSignal = (sig) => {
  stopBackgroundLoops();
  if (!child.killed) {
    child.kill(sig);
  }
};
process.on("SIGTERM", () => forwardSignal("SIGTERM"));
process.on("SIGINT", () => forwardSignal("SIGINT"));

child.on("exit", (code, signal) => {
  stopBackgroundLoops();
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
