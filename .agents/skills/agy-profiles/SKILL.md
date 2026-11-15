---
name: agy-profiles
description: Provision, inspect, launch, stop, repair, clone, and audit isolated Google Antigravity Hub and IDE sandbox profiles via the clean-room agy-profiles CLI or stdio MCP server.
---

# agy-profiles Operator Skill

Use this skill when isolating Google Antigravity workspaces, debugging stale Chromium profile locks, running multiple Antigravity accounts cleanly on macOS, or auditing MCP secret hygiene.

## When to Invoke agy-profiles

1. Running two or more Antigravity Hub or Antigravity IDE sessions concurrently with separate authentication files (`isolated-file` mode).
2. Creating a fresh sandbox for untrusted repository inspection (`--links none`, no host `.ssh`, `.aws`, or `.gemini` symlinks).
3. Inheriting host `GEMINI.md` and `mcp_config.json` into a new sandbox safely using fail-closed secret scrubbing (`--inherit-config`).
4. Repairing crashed Electron lock files (`SingletonLock`, `SingletonSocket`, `SingletonCookie`, `DevToolsActivePort`) without terminating unrelated Antigravity instances.
5. Opening the CSRF-guarded local Web Console (`agy-profiles web`) or running the stdio MCP server (`agy-profiles mcp`).

## Recommended Command Sequence

1. Check host targets and existing profiles first:
   `agy-profiles doctor --json`
   `agy-profiles list --json`
2. Create an isolated sandbox without symlinking host secrets:
   `agy-profiles create audit-box --label "Audit Sandbox" --links none --auth isolated-file --inherit-config --json`
3. Verify permissions (`0o700` / `0o600`), `.zshenv` `HOME` lock, and live obligations:
   `agy-profiles inspect audit-box --json`
   `agy-profiles obligations --json`
4. Launch Hub or IDE inside the sandbox:
   `agy-profiles launch audit-box --target hub`
5. Stop cleanly or repair stale locks when finished:
   `agy-profiles stop audit-box --target all --json`
   `agy-profiles repair audit-box --json`

## Safety Invariants Enforced Automatically

1. Never symlink `~/.gemini`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/Library/Keychains`, or shell startup dotfiles into a sandbox `home/`.
2. Never allow `--root` operations to escape profile containment via relative segments or symlinks.
3. Never fall back to raw file copy if host `mcp_config.json` fails strict JSON validation (`mcp_config_malformed`).
4. Never bind the local Web Console beyond `127.0.0.1` or `::1`.
