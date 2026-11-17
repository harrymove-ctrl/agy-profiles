import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
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

const forwardSignal = (sig) => {
  if (!child.killed) {
    child.kill(sig);
  }
};
process.on("SIGTERM", () => forwardSignal("SIGTERM"));
process.on("SIGINT", () => forwardSignal("SIGINT"));

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
