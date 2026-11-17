---
name: agy-profiles
description: Provision, inspect, sync, switch, hand off, launch, stop, repair, clone, rename, and audit isolated Google Antigravity Hub and IDE sandbox profiles via the clean-room agy-profiles CLI or 17-tool stdio MCP server.
---

# agy-profiles Operator Skill

Use this skill when isolating Google Antigravity workspaces, debugging stale Chromium profile locks, running multiple Antigravity accounts cleanly on macOS, migrating Automations safely across accounts, or switching quota mid-sprint.

## When to Invoke agy-profiles

1. Running two or more Antigravity Hub or Antigravity IDE sessions concurrently with separate authentication files (`isolated-file` mode).
2. Creating a fresh sandbox for untrusted repository inspection (`--links none --no-inherit-config`, zero host `.ssh`, `.aws`, or `.gemini` symlinks).
3. Inheriting and syncing sanitized host projects, Automations (`paused` standby default, `active` on takeover, or `strip` to omit), plugins, agents, skills, `GEMINI.md`, and `mcp_config.json` with fail-closed secret scrubbing and stale Host pruning (`agy-profiles sync`).
4. Executing one-command quota takeover (`agy-profiles switch <profile>`) that checks Host git workspace status, syncs handoff and setup, enables Automations, copies the resume prompt via `pbcopy`, and launches the backup profile.
5. Generating a bidirectional read-only conversation digest (`agy-profiles handoff --from host` or `--from <profile>`) or cloning a new backup account with `--fresh-auth`.
6. Repairing crashed Electron lock files (`SingletonLock`, `SingletonSocket`, `SingletonCookie`, `DevToolsActivePort`) or verifying Apple Silicon `.app` launcher code signatures via `agy-profiles doctor`.
7. Opening the hardened Astryx Design System local Web Console (`agy-profiles web`) or embedding it inside Antigravity Hub via `antigravity-plugin/` (`./install.sh --with-skill --with-plugin`).

## Recommended Command Sequence

1. Check host targets, `.app` launcher signatures, and existing profiles first:
   `agy-profiles doctor --json`
   `agy-profiles list --json`
2. Create an isolated sandbox (defaults to `--links dev` and inherited setup with paused Automations, or use `--links none --no-inherit-config` for untrusted repos):
   `agy-profiles create audit-box --label "Audit Sandbox" --links none --no-inherit-config --json`
3. Verify permissions (`0o700` / `0o600`), `.zshenv` `HOME` lock, and live obligations:
   `agy-profiles inspect audit-box --json`
   `agy-profiles obligations --json`
4. Sync sanitized host setup and Automations in paused standby (rewriting `.gemini` paths inside `sidecar.json` to the sandbox), activate Automations on quota switchover, or return quota back to Main Antigravity:
   `agy-profiles sync work-backup --automations paused --json`
   `agy-profiles switch work-backup --copy-prompt --json`
   `agy-profiles switch host --from work-backup --copy-prompt --json`
5. Inspect bidirectional handoff digests before resuming work on either account:
   `agy-profiles handoff --from host --json`
   `agy-profiles handoff --from work-backup --json`
6. Stop cleanly or repair stale locks when finished:
   `agy-profiles stop work-backup --target all --json`
   `agy-profiles repair work-backup --json`
7. Keep the 24/7 macOS `launchd` services (`watchdog` wrapped in `/usr/bin/caffeinate -i` plus the persistent Web Console on `127.0.0.1:47920`) active across overnight or multi-day unattended runs:
   `agyp daemon install --json`
   `agyp daemon status --json`
   `agyp daemon open`

## Safety Invariants Enforced Automatically

1. Never symlink `~/.gemini`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/Library/Keychains`, or shell startup dotfiles into a sandbox `home/`.
2. Never leave Host `.gemini` file paths inside synced `sidecar.json` or `config.json["sidecars"]`; rewrite all `.gemini` references to `<sandbox_home>/.gemini`.
3. Never fall back to raw file copy if host `mcp_config.json` fails strict JSON validation (`mcp_config_malformed`).
4. Ad-hoc sign compiled macOS `.app` launchers (`codesign --force --deep --sign -`) after writing `Info.plist` and icon resources so Apple Silicon Gatekeeper verification passes.
5. Keep `agy-profiles web` strictly bound to `127.0.0.1` or `::1` with 365-day sliding signed session cookies backed by `0o600` `.web-secrets.json`, CSRF header validation, and strict `Origin` checks.

## Local Web Console Customization

When editing UI components, themes (`Gothic Studio`, `Gothic`, `Neutral`), or typography inside `web-ui/`, run `cd web-ui && npm run build && npx astryx doctor` to recompile `src/agy_profiles/web_static/` and keep zero external `fonts.googleapis.com` requests.
