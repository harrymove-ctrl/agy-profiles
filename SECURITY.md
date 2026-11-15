# Security Policy and Threat Model

`agy-profiles` treats local profile directories, OAuth tokens, MCP configurations, and localhost control sockets as high-value assets. Every privilege boundary follows fail-closed defaults using Python standard library primitives.

## 1. Local Filesystem and Symlink Isolation

1. **Strict Permissions**: Profile directories (`<root>/<profile>`, `data/`, `ide-data/`, `home/`) are created and reconciled to mode `0o700`. Manifests (`profile.json`), `.zshenv`, `app_storage.json`, OAuth token files, and copied MCP configurations are enforced at mode `0o600`.
2. **Containment Verification**: Every file read, write, clone, or deletion resolves target paths with `ensure_within_root(root, candidate)` (`config.py`) so dot-dot segments or malicious symlinks cannot escape the active profile root. Managed symlinks use `ensure_symlink_slot_within_root` to verify that parent slots reside strictly inside the sandbox `home/`.
3. **Host Credential Blocklist**: `validate_link_relpath` (`isolation.py`) blocks any relative link intersecting `FORBIDDEN_HOME_RELPATHS`, including `.ssh`, `.gnupg`, `.aws`, `.kube`, `.npmrc`, `.netrc`, `.pypirc`, `Library/Keychains`, `.gemini`, and shell dotfiles (`.zshenv`, `.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`). Re-provisioning strips unauthorized symlinks from those slots before creating real directories.
4. **Login Shell HOME Lock**: Electron apps spawn interactive login shells that source `~/.zshenv` and import variables via `env`. Writing an explicit `export HOME=...` and `export ZDOTDIR=...` inside `<profile>/home/.zshenv` keeps Antigravity environment capture confined to the sandbox.

## 2. Fail-Closed Secret Redaction

When `--inherit-config` is requested during profile creation:

1. Host `mcp_config.json` and `settings.json` files are parsed strictly as UTF-8 JSON objects via `sanitize_mcp_json_text`.
2. Malformed JSON or non-object payloads raise `ToolError("mcp_config_malformed")` and trigger an immediate rollback deleting the partial profile directory. Raw config files containing parse errors are never copied unredacted.
3. Nested `env`, `headers`, `args` flags, URL userinfo (`user:pass@`), URL query parameters matching sensitive keys, and recognized API token prefixes are rewritten in memory to redacted markers before writing `0o600` files to the sandbox.

## 3. Process Boundary Isolation

1. **No Broad Binary Matching**: `command_matches_user_data_dir` (`process_guard.py`) matches `--user-data-dir=<resolved_path>` strictly at start/whitespace token boundaries so sibling profiles (`/profiles/work` versus `/profiles/work-2`) or default host instances never collide.
2. **Verified Ancestor and Child Traversal**: Child helper processes (`language_server`, MCP servers) are discovered by parent-PID traversal starting exclusively from verified `--user-data-dir` root PIDs.
3. **Graceful Escalation**: `stop_profile` issues `SIGTERM`, polls live verified PIDs, and delivers `SIGKILL` only to surviving verified PIDs before clearing lock files.

## 4. Localhost Web Console Hardening

`agy-profiles web` protects local management endpoints against DNS rebinding, CSRF, clickjacking, and cross-origin reads:

1. **Loopback-Only Bind**: `validate_bind_host` permits only `127.0.0.1` and `::1`. Wildcards (`0.0.0.0`, `::`), LAN IPs, and hostnames (`localhost` subject to `/etc/hosts` tampering) are rejected before socket creation.
2. **Host Header Enforcement**: Every HTTP request is validated in constant time against the exact expected `Host:Port` authority (`validate_host_header`), stopping DNS rebinding attacks.
3. **Capability URL + HttpOnly Strict Session**: Startup generates an ephemeral 32-byte bootstrap token (`?token=...`) and an independent 32-byte `csrf_token`. Visiting `/?token=<bootstrap>` sets an `HttpOnly; SameSite=Strict` signed session cookie; client JavaScript immediately strips `?token=` from `window.history`.
4. **Origin and Custom CSRF Header Enforcement**: Every API request requires a valid signed session cookie plus exact `X-AGY-CSRF` header match. Mutating requests (`POST`, `PATCH`, `DELETE`) additionally enforce exact `Origin` header equality with `expected_origin`, blocking `Origin: null` and missing `Origin` headers. Zero `Access-Control-Allow-Origin` headers are emitted.
5. **Strict Content Security Policy and Font Containment**: HTML responses emit `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` alongside `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`. Self-hosted variable font requests under `/fonts/` require single-segment `.woff2` or `.woff` filenames resolved inside `web_static/fonts/`. All UI components render untrusted strings through React JSX auto-escaping with zero `dangerouslySetInnerHTML`.

## Reporting Vulnerabilities

If you discover a boundary bypass, symlink escape, token leakage vector, or web server flaw, open a private GitHub security advisory on `harrymove-ctrl/agy-profiles` or inspect the failing invariant using `agy-profiles obligations --json`.
