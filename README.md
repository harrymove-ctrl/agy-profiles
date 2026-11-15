# agy-profiles

Clean-room multi-profile sandbox manager, stdio MCP server, and hardened localhost console for Google Antigravity on macOS.

![agy-profiles Web Console Overview](docs/assets/web-console-overview.png)

## Overview

Running multiple accounts, client workspaces, or untrusted repositories inside Google Antigravity Hub and Antigravity IDE risks cross-profile authentication bleed, shell login environment leakage, stale Chromium locks, and unintentional credential exposure. `agy-profiles` solves this through strict directory containment (`0o700` / `0o600`), locked `.zshenv` `HOME` rewriting, fail-closed MCP configuration sanitization, exact `--user-data-dir` process matching, and cryptographic CSRF/Origin isolation on its local web interface.

This repository is built purely on the Python 3 standard library (`>= 3.9`) with zero third-party runtime or test dependencies.

## Key Capabilities

1. **Strict Sandbox Isolation**: Provisions per-profile `data/`, `ide-data/`, `home/`, and `logs/` directories under `/Volumes/Dev/.antigravity-profiles` (when writable on macOS, or `~/.antigravity-profiles`, overridable via `AGY_PROFILES_DIR` or `--root`). Writes an immutable `0o600` `.zshenv` pinning `HOME` and `ZDOTDIR` inside the profile so macOS login shell environment discovery never pulls host credentials.
2. **Dual Target Support (`hub` and `ide`)**: Launches and tracks both `/Applications/Antigravity.app` (Antigravity Hub) and `/Applications/Antigravity IDE.app` (Antigravity IDE) inside isolated `--user-data-dir` and `--extensions-dir` paths, automatically setting `app_storage.json` and IDE `settings.json` flags to disable background auto-updaters.
3. **Fail-Closed Secret Sanitizer**: When creating a profile with `--inherit-config`, copies host `GEMINI.md` and `mcp_config.json` while redacting secrets in nested `env`, `headers`, `args`, URL userinfo, and secret query parameters. Rejects malformed JSON instead of falling back to raw copies.
4. **Symlink Allowlist and Blocklist**: Rejects and strips symlinks pointing to sensitive host locations (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.npmrc`, `.netrc`, `.pypirc`, `Library/Keychains`, `.gemini`, shell startup dotfiles). Offers conservative opt-in link policies (`none`, `minimal`, `dev`) for benign runtime binaries and fonts.
5. **Exact Process Boundary Matching**: Tracks and stops processes only when `--user-data-dir=<resolved_path>` matches at strict token boundaries, including descendant child processes discovered via parent-PID traversal. Escalates cleanly from `SIGTERM` to `SIGKILL` and repairs stale Chromium locks (`SingletonLock`, `SingletonSocket`, `SingletonCookie`, `DevToolsActivePort`).
6. **Evidence and Obligation Ledgers**: Emits structured `EvidenceRecord` metadata (`evidence_id`, `authority`, `confidence`, `facts`, `limitations`) on inspections and exposes six executable security self-checks via `agy-profiles obligations`.
7. **Three Zero-Dependency Surfaces**: Includes an `argparse` CLI (`agy-profiles` / `agyp`), a line-delimited JSON-RPC 2.0 stdio MCP server (`agy-profiles mcp`), a native macOS `.app` launcher compiler (`agy-profiles launcher build`), and a Dark/Light CSP-enforced Web Console (`agy-profiles web`).

## Installation

Install `agy-profiles` and its short alias `agyp` into `~/.local/bin` via symlink:

```bash
git clone https://github.com/harrymove-ctrl/agy-profiles.git /Volumes/Dev/agy-profiles
cd /Volumes/Dev/agy-profiles
./install.sh
```

Useful installer options:

```bash
./install.sh --dry-run
./install.sh --prefix ~/.local/bin --with-skill
./install.sh --uninstall
```

You can also run directly from the repository without modifying `PATH`:

```bash
./bin/agy-profiles doctor --json
```

## Quick Start

1. Check host Antigravity bundles and sandbox health:

```bash
agy-profiles doctor
```

2. Verify built-in security and isolation invariants:

```bash
agy-profiles obligations
```

3. Create an isolated profile with minimal toolchain symlinks and sanitized host MCP config:

```bash
agy-profiles create core-research --label "Core Research" --target hub --links minimal --inherit-config
```

4. Launch Antigravity Hub or IDE for that profile:

```bash
agy-profiles launch core-research
agy-profiles launch core-research --target ide --workspace /Volumes/Dev/my-repo
```

5. Build a native Spotlight and Dock `.app` bundle launcher:

```bash
agy-profiles launcher build core-research --target hub
```

6. Open the local Web Console on `127.0.0.1`:

```bash
agy-profiles web
```

7. Connect an AI coding client to the stdio MCP server:

```json
{
  "mcpServers": {
    "agy-profiles": {
      "command": "agy-profiles",
      "args": ["mcp"]
    }
  }
}
```

## CLI Command Reference

| Command | Purpose |
| :--- | :--- |
| `agy-profiles list [--json]` | List all profiles, runtime states, disk sizes, and detected host targets. |
| `agy-profiles create <name> [flags]` | Provision a new sandbox profile with strict directory modes. |
| `agy-profiles inspect <name> [--json]` | Inspect permissions, symlinks, live PIDs, and `EvidenceRecord` output. |
| `agy-profiles update <name> [flags]` | Update label, accent color, default target, symlink policy, or auth mode. |
| `agy-profiles launch <name> [--target hub\|ide]` | Launch Hub or IDE inside the profile sandbox. |
| `agy-profiles stop <name> [--target hub\|ide\|all]` | Stop verified profile processes with `SIGTERM` and `SIGKILL` escalation. |
| `agy-profiles repair <name> [--target hub\|ide]` | Clean stale Chromium lock files and reconcile `.zshenv` permissions. |
| `agy-profiles clone <source> <target>` | Clone a stopped profile while excluding transient locks and symlinks. |
| `agy-profiles delete <name> [--force-stop] [--yes]` | Delete a profile sandbox safely inside root boundaries. |
| `agy-profiles launcher build\|remove <name>` | Compile or remove a macOS `.app` bundle using `osacompile`. |
| `agy-profiles doctor [--json]` | Inspect host Antigravity binaries, storage root modes, and stale locks. |
| `agy-profiles obligations [--json]` | Execute and report all six live security obligation checks. |
| `agy-profiles mcp` | Serve 13 tools over line-delimited JSON-RPC 2.0 stdio. |
| `agy-profiles web [--host 127.0.0.1] [--port 47920]` | Start the CSRF-guarded local web console. |

## Verification and Testing

Run the full zero-dependency test suite across Python 3.9 and 3.14, plus the secret and contamination scanner:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py
```

## Documentation

1. [Architecture Overview](docs/ARCHITECTURE.md): Five-layer clean-room module design, shell isolation rationale, and lock lifecycle.
2. [Reconstruction Obligations](docs/OBLIGATIONS.md): Live invariant definitions verified on every release.
3. [Security Model](SECURITY.md): Threat model, CSP/CSRF controls, symlink jail, and fail-closed redaction guarantees.

## License

MIT License. See [LICENSE](LICENSE).
