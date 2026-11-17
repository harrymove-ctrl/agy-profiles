# Architecture Overview

`agy-profiles` organizes every subsystem into five unidirectional layers (`L0` through `L4`) with zero runtime third-party packages. Higher layers depend only on lower layers, and every interactive capability (`cli`, `mcp`, `web`) invokes the exact same `TOOL_SPECS` handlers in `tools.py`.

## Module Layering

| Layer | Module(s) | Responsibility |
| :--- | :--- | :--- |
| `L0` | `errors.py`, `evidence.py` | Structured `ToolError` exception envelope, SHA-256 helpers, `EvidenceRecord`, and `ObligationReport` types. |
| `L1` | `config.py` | Slug validation, automations mode validation, root resolution, symlink containment checks, atomic `0o600` file writes, host app bundle detection, and `ProfileManifest` persistence. |
| `L2` | `isolation.py`, `process_guard.py`, `macos_launcher.py` | Directory provisioning, `.zshenv` `HOME` rewriting, link blocklists, fail-closed MCP secret scrubbing, Automations migration (`paused`, `active`, `strip`) with sandbox `.gemini` path rewriting, stale entry pruning, bidirectional SQLite handoff, exact PID boundary matching, lock repair, and AppleScript `.app` compilation with Apple Silicon ad-hoc `codesign`. |
| `L3` | `tools.py` | Shared `RuntimeContext`, `ToolSpec` JSON schemas, all 17 operational handlers (including `profile_switch` and `clone --fresh-auth`), 30s disk usage caching, and the six live `obligations_verify` self-checks. |
| `L4` | `cli.py`, `mcp_server.py`, `web_server.py`, `web_static/` | `argparse` CLI, stdio JSON-RPC 2.0 MCP server, and loopback HTTP console (standalone and embedded Antigravity Aux Pane sidecar mode) serving pre-compiled Astryx React assets from `web-ui/` and `antigravity-plugin/`. |

## On-Disk Profile Layout

Each created profile `<root>/<name>/` maintains strict POSIX modes:

1. `profile.json` (`0o600`): Declarative `ProfileManifest` storing slug, display label, 6-digit hex accent, `default_target` (`hub` or `ide`), `link_policy` (`none`, `minimal`, `dev`), `auth_mode` (`isolated-file` or `system-keychain`), `keep_background_alive`, and `last_host_versions`.
2. `home/` (`0o700`): Sandboxed `HOME` directory containing `.zshenv` (`0o600`), isolated `.gemini/` subdirectories, `.config/`, `.local/share/`, `.cache/`, and safe policy symlinks outside forbidden credential directories.
3. `data/` (`0o700`): Isolated Electron `--user-data-dir` for Antigravity Hub plus `app_storage.json` (`0o600`) pinning `"autoCheckForUpdates": "false"` and `"runInBackground"`.
4. `ide-data/` (`0o700`): Isolated Electron `--user-data-dir` for Antigravity IDE plus `User/settings.json` (`0o600`) pinning `"update.mode": "none"`.
5. `logs/` (`0o700`): Appended launch stdout/stderr logs (`hub.log`, `ide.log`).

## Why `.zshenv` HOME Pinning Is Necessary

Desktop Electron hosts on macOS commonly spawn interactive login shells (`$SHELL -ilc env`) to capture user toolchain `PATH` entries. If `~/.zshrc` or global shell profiles mutate or inherit variables from the host home directory, external tokens leak into child language servers. Writing `<profile>/home/.zshenv` with explicit `export HOME=<sandbox_home>` and `export ZDOTDIR=<sandbox_home>` ensures zsh initialization stays anchored inside the active sandbox.

## Authentication Isolation Modes

1. `isolated-file` (default): Launches Antigravity with `SSH_CONNECTION=local` so OAuth credentials store inside `<profile>/home/.gemini/jetski-standalone-oauth-token` (`0o600`) instead of sharing the global macOS login Keychain across profiles.
2. `system-keychain`: Omits `SSH_CONNECTION` for setups that intentionally share Keychain credentials.

## Upgrade Cache Hygiene

Before launching a profile, `purge_stale_caches_if_upgraded` compares the host bundle's `CFBundleShortVersionString` against `manifest.last_host_versions`. When the host binary version changes, volatile Chromium GPU and shader caches (`Cache`, `Code Cache`, `GPUCache`, `DawnGraphiteCache`, `DawnWebGPUCache`, `GraphiteDawnCache`) are cleared cleanly while preserving user configuration, workspace state, and OAuth tokens.

## Web Console Frontend Build Architecture

The user interface served by `web_server.py` originates in `web-ui/`, a TypeScript + React 19 + `@astryxdesign/core` + `@stylexjs/stylex` Vite project using an IIFE bundle (`vite.config.ts`) targeting `src/agy_profiles/web_static/`.

1. **Zero Runtime Footprint**: `node_modules` and `web-ui/.astryx` remain excluded in `.gitignore`. Python packaging in `pyproject.toml` distributes only the compiled `web_static/*` and `web_static/fonts/*` files with `dependencies = []`.
2. **Self-Hosted Font Pipeline**: `@fontsource-variable/fustat`, `@fontsource/manufacturing-consent`, `@fontsource/unifrakturmaguntia`, `@fontsource-variable/figtree`, and `@fontsource-variable/jetbrains-mono` Latin `.woff2` subsets are copied into `src/agy_profiles/web_static/fonts/` via `vite.config.ts` and scoped per `[data-astryx-theme]` in `web-ui/src/styles/self-hosted-fonts.css`, guaranteeing zero external font CDN calls.
3. **Static Route Containment**: `web_server.py` serves `/`, `/app.js`, `/styles.css`, `/mark.svg`, and `/fonts/<name>.woff2` directly from `STATIC_DIR` with strict path containment, 12-hour signed `__agy_session` cookies, 15-second single-use bootstrap token rotation (or Host gateway `X-Sidecar-Token` framing inside Antigravity Aux Pane `--sidecar` mode), `font-src 'self'`, `script-src 'self'`, and `style-src 'self' 'unsafe-inline'`.
