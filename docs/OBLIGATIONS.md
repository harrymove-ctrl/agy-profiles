# Reconstruction Obligation Ledger

Every security, filesystem, process, and network boundary in `agy-profiles` is backed by a live executable self-check registered in `obligations_verify` (`src/agy_profiles/tools.py`). Both operators and connected MCP agents can audit live module integrity via `agy-profiles obligations --json` or in the `Obligations` tab of the Web Console.

Each report computes a SHA-256 digest of the owning source module and attaches an `EvidenceRecord` (`ev_<16hex>`) summarizing verified cases and explicit scope limitations.

## Live Verified Obligations

| Obligation ID | Owner Module | Security Guarantee | Cases Verified |
| :--- | :--- | :--- | :--- |
| `isolation.name_validation` | `config.py` | Accepts valid slugs and rejects reserved names, null bytes, dot-dot sequences, and path separators. | `positive`, `negative`, `malformed` |
| `isolation.path_containment` | `config.py` | Resolves symlinks and rejects any path resolving outside the active profiles root. | `positive`, `symlink_escape` |
| `isolation.forbidden_symlinks` | `isolation.py` | Blocks host credential directories (`.ssh`, `.aws`, `Library/Keychains`, `.gemini`, shell rc files) from linking into sandbox homes. | `positive`, `ssh_block`, `keychain_block` |
| `mcp.fail_closed_scrub` | `isolation.py` | Redacts nested secrets across `env`, `headers`, `args`, and URLs while raising `mcp_config_malformed` on invalid JSON without fallback copies. | `env_secret`, `args_secret`, `url_secret`, `malformed_json` |
| `process.exact_userdata_match` | `process_guard.py` | Matches `--user-data-dir=<path>` strictly at argument boundaries so prefix-similar profile directories never collide. | `exact`, `prefix_collision`, `unrelated_instance` |
| `web.csrf_and_origin_guard` | `web_server.py` | Restricts HTTP bind addresses to `127.0.0.1` or `::1` and blocks foreign `Host`, missing `Origin`, and `Origin: null` mutations. | `loopback_bind`, `host_rebind`, `origin_null`, `origin_missing` |

## Full Integration Verification

In addition to lightweight live self-checks inside `obligations_verify`, end-to-end HTTP socket behavior, staged `SIGTERM` to `SIGKILL` escalation, macOS login `.zshenv` hardening, and stdio JSON-RPC 2.0 MCP roundtrips are tested continuously under `tests/`.
