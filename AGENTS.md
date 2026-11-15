# agy-profiles Agent Guidelines

This workspace (`/Volumes/Dev/agy-profiles`) builds and maintains `agy-profiles`, a clean-room Python 3 stdlib multi-profile sandbox manager, stdio MCP server, and hardened localhost console for Google Antigravity.

## Architectural Rules

1. **Zero Runtime Dependencies**: Keep `pyproject.toml` `dependencies` strictly `[]` so `agy-profiles` installs and runs with zero PyPI or Node runtime dependencies. Maintain full compatibility with both macOS system Python (`>= 3.9`) and modern Python (`>= 3.14`), using `from __future__ import annotations` at the top of every module under `src/agy_profiles/` and `tests/`. The optional `web-ui/` React/TypeScript workspace uses `@astryxdesign/core` (`0.7.x`) and Vite strictly at dev time and pre-compiles self-hosted static assets (including variable `.woff2` fonts) directly into `src/agy_profiles/web_static/`.
2. **Strict Module Layering**: Respect layer boundaries across `L0` (`errors.py`, `evidence.py`), `L1` (`config.py`), `L2` (`isolation.py`, `process_guard.py`, `macos_launcher.py`), `L3` (`tools.py`), and `L4` (`cli.py`, `mcp_server.py`, `web_server.py`). Never import upward.
3. **Never-Crash Bounds and Fail-Closed Defaults**: All validation failures must raise `ToolError` with clear remediation text. Never fall back to copying unredacted files when JSON parsing fails, never bind `web_server.py` beyond `127.0.0.1` or `::1`, and never follow symlinks outside the active profile root.
4. **Strict CSP and XSS-Safe Web UI**: Keep `web-ui/` compiled cleanly into `src/agy_profiles/web_static/` (`index.html`, `styles.css`, `app.js`, `mark.svg`, `fonts/*.woff2`) with zero external CDNs (`fonts.googleapis.com` forbidden), zero emojis, zero `dangerouslySetInnerHTML`, and React auto-escaped rendering for all untrusted backend values. Maintain `script-src 'self'` and `font-src 'self'` alongside `style-src 'self' 'unsafe-inline'` required by the Astryx runtime theme layer.
5. **Clean-Room Prose and Hygiene**: Write all documentation, UI copy, comments, and commit messages in 100% English without em-dashes, en-dashes, spaced hyphens, horizontal rules, or unordered dash bullets. Run `python3 scripts/check_secrets.py` before committing.

## Verification Gates Before Committing

1. Run unit and integration suites under both macOS Python runtimes:
   `python3 -m unittest discover -s tests -v`
2. Verify all six live security obligations close with zero failures:
   `./bin/agy-profiles obligations --json`
3. Verify zero secrets, upstream artifacts, CJK characters, or personal host paths exist in tracked files:
   `python3 scripts/check_secrets.py`
