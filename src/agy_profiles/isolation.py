"""Sandbox directory provisioning, symlink blocklist, cache hygiene, and MCP scrubbing."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid

from agy_profiles.config import (
    CACHE_DIR_NAMES,
    ProfileManifest,
    TargetInfo,
    atomic_write_json,
    atomic_write_text,
    ensure_symlink_slot_within_root,
    ensure_within_root,
    validate_automations_mode,
)
from agy_profiles.errors import ToolError
from agy_profiles.evidence import utc_now_iso

FORBIDDEN_HOME_RELPATHS = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".npmrc",
    ".netrc",
    ".pypirc",
    "Library/Keychains",
    ".gemini",
    ".zshenv",
    ".zshrc",
    ".zprofile",
    ".bashrc",
    ".bash_profile",
}

LINK_POLICIES: Dict[str, List[str]] = {
    "none": [],
    "minimal": [
        "Library/Fonts",
        ".local/bin",
        ".cargo/bin",
        ".bun/bin",
    ],
    "dev": [
        "Library/Fonts",
        ".local/bin",
        ".cargo/bin",
        ".bun/bin",
        ".rustup",
        ".nvm",
        ".pyenv",
        ".agents",
    ],
}

ALL_MANAGED_LINKS: List[str] = sorted({item for group in LINK_POLICIES.values() for item in group})

REDACTED_MARKER = "[REDACTED_BY_AGY_PROFILES]"

SECRET_KEY_RE = re.compile(
    r"(?i)(key|token|secret|password|passwd|authorization|bearer|cookie|credential)"
)
ARG_EQ_SECRET_RE = re.compile(
    r"^(--?[A-Za-z0-9._-]*(?:key|token|secret|password|passwd|auth|bearer|credential)[A-Za-z0-9._-]*)=(.+)$",
    re.IGNORECASE,
)
ARG_FLAG_SECRET_RE = re.compile(
    r"^--?[A-Za-z0-9._-]*(?:key|token|secret|password|passwd|auth|bearer|credential)[A-Za-z0-9._-]*$",
    re.IGNORECASE,
)
QUERY_SECRET_RE = re.compile(
    r"(?i)(key|token|secret|password|passwd|auth|sig|signature|credential)"
)
TOKEN_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{10,}|gho_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|xoxb-[A-Za-z0-9-]{10,}|xoxp-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{10,})"
)


def validate_link_relpath(relpath: str) -> str:
    """Enforce that a home-relative symlink target never aliases a forbidden host path."""
    norm = Path(relpath).as_posix().lstrip("/")
    if not norm or norm in (".", "..") or norm.startswith("../") or "/../" in norm:
        raise ToolError(
            "forbidden_symlink",
            "Unsafe relative symlink path {!r}.".format(relpath),
            "Choose a safe relative directory without traversal segments.",
            {"relpath": relpath},
        )
    for forbidden in FORBIDDEN_HOME_RELPATHS:
        if norm == forbidden or norm.startswith(forbidden + "/") or forbidden.startswith(norm + "/"):
            raise ToolError(
                "forbidden_symlink",
                "Symlinking host path {!r} into a sandbox profile is forbidden.".format(norm),
                "Keep credentials, shells, SSH keys, Keychains, and .gemini directories strictly isolated.",
                {"relpath": norm, "forbidden": forbidden},
            )
    return norm


def _chmod_if_exists(path: Path, mode: int) -> None:
    if path.exists() and not path.is_symlink():
        os.chmod(str(path), mode)


def _mkdir_0700(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_symlink():
        os.chmod(str(path), 0o700)


def _write_sandbox_zshenv(sandbox_home: Path, real_home: Path) -> None:
    zshenv_path = ensure_within_root(sandbox_home, sandbox_home / ".zshenv")
    safe_bin_dirs = [
        str(real_home / ".local" / "bin"),
        str(real_home / ".cargo" / "bin"),
        str(real_home / ".bun" / "bin"),
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
    ]
    quoted_bins = " ".join(shlex.quote(p) for p in safe_bin_dirs)
    script = (
        "# Managed by agy-profiles.\n"
        "# Locks HOME and ZDOTDIR inside this sandbox during login shell discovery.\n"
        "export HOME={home}\n"
        "export ZDOTDIR={home}\n"
        "for _agy_bin in {bins}; do\n"
        "  if [ -d \"$_agy_bin\" ]; then\n"
        "    case \":$PATH:\" in\n"
        "      *\":$_agy_bin:\"*) ;;\n"
        "      *) export PATH=\"$_agy_bin:$PATH\" ;;\n"
        "    esac\n"
        "  fi\n"
        "done\n"
        "unset _agy_bin\n"
    ).format(home=shlex.quote(str(sandbox_home)), bins=quoted_bins)
    atomic_write_text(zshenv_path, script, mode=0o600)


def create_safe_link(src: Path, dst: Path) -> bool:
    """Create a symlink, falling back to NTFS junction/hardlink/copy on Windows without symlink privilege."""
    is_dir = src.is_dir()
    try:
        os.symlink(str(src), str(dst), target_is_directory=is_dir)
        return True
    except OSError as exc:
        if sys.platform != "win32" or getattr(exc, "winerror", None) != 1314:
            raise
    if is_dir:
        proc = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(dst), str(src)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    try:
        os.link(str(src), str(dst))
        return True
    except OSError:
        shutil.copy2(str(src), str(dst))
        return True


def _reconcile_policy_symlinks(
    sandbox_home: Path,
    real_home: Path,
    link_policy: str,
) -> Dict[str, List[str]]:
    desired = set(LINK_POLICIES.get(link_policy, []))
    linked: List[str] = []
    removed: List[str] = []
    skipped_missing: List[str] = []

    for rel in ALL_MANAGED_LINKS:
        clean_rel = validate_link_relpath(rel)
        slot = ensure_symlink_slot_within_root(sandbox_home, sandbox_home / clean_rel)
        if clean_rel in desired:
            src = real_home / clean_rel
            if src.exists():
                _mkdir_0700(slot.parent)
                if slot.is_symlink():
                    if os.readlink(str(slot)) != str(src):
                        slot.unlink()
                        create_safe_link(src, slot)
                elif not slot.exists():
                    create_safe_link(src, slot)
                linked.append(clean_rel)
            else:
                skipped_missing.append(clean_rel)
        else:
            if slot.is_symlink():
                slot.unlink()
                removed.append(clean_rel)
            elif sys.platform == "win32" and slot.is_dir():
                try:
                    os.rmdir(str(slot))
                    removed.append(clean_rel)
                except OSError:
                    pass
    return {"linked": linked, "removed": removed, "skipped_missing": skipped_missing}


def _read_existing_json_dict(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            return loaded
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def provision_profile_dirs(
    root: Path,
    manifest: ProfileManifest,
    real_home: Optional[Path] = None,
) -> Dict[str, Any]:
    """Create or harden sandbox directories, .zshenv HOME lock, symlinks, and updater config."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    root_resolved = root.resolve()
    root_resolved.mkdir(parents=True, exist_ok=True)
    os.chmod(str(root_resolved), 0o700)

    profile_dir_slot = ensure_symlink_slot_within_root(root_resolved, root_resolved / manifest.name)
    if profile_dir_slot.is_symlink():
        profile_dir_slot.unlink()
    profile_dir = ensure_within_root(root_resolved, profile_dir_slot)
    subdirs = [
        profile_dir,
        profile_dir / "data",
        profile_dir / "ide-data",
        profile_dir / "ide-data" / "User",
        profile_dir / "home",
        profile_dir / "home" / ".gemini",
        profile_dir / "home" / ".gemini" / "antigravity",
        profile_dir / "home" / ".gemini" / "antigravity-ide",
        profile_dir / "home" / ".gemini" / "config",
        profile_dir / "home" / ".gemini" / "config" / "projects",
        profile_dir / "home" / ".config",
        profile_dir / "home" / ".local",
        profile_dir / "home" / ".local" / "share",
        profile_dir / "home" / ".cache",
        profile_dir / "home" / "Desktop",
        profile_dir / "home" / "Downloads",
        profile_dir / "home" / "Documents",
        profile_dir / "logs",
    ]
    for d in subdirs:
        if d.is_symlink():
            d.unlink()
        _mkdir_0700(d)

    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    for forbidden in FORBIDDEN_HOME_RELPATHS:
        forbidden_slot = sandbox_home / forbidden
        if forbidden_slot.is_symlink():
            forbidden_slot.unlink()
    oauth_slot = sandbox_home / ".gemini" / "jetski-standalone-oauth-token"
    if oauth_slot.is_symlink():
        oauth_slot.unlink()
    inst_id_path = ensure_within_root(sandbox_home, sandbox_home / ".gemini" / "installation_id")
    if inst_id_path.is_symlink():
        inst_id_path.unlink()
    if not inst_id_path.is_file():
        atomic_write_text(inst_id_path, str(uuid.uuid4()), mode=0o600)
    _write_sandbox_zshenv(sandbox_home, host_home)
    link_result = _reconcile_policy_symlinks(sandbox_home, host_home, manifest.link_policy)

    # Suppress Hub auto-updater and enforce requested background tray behavior for Mobile RemoteControl.
    app_storage_path = ensure_within_root(profile_dir, profile_dir / "data" / "app_storage.json")
    app_storage = _read_existing_json_dict(app_storage_path)
    app_storage["autoCheckForUpdates"] = "false"
    app_storage["runInBackground"] = "true" if manifest.keep_background_alive else "false"
    app_storage["keepComputerAwake"] = True
    atomic_write_json(app_storage_path, app_storage, mode=0o600)

    # Suppress Antigravity IDE auto-updater.
    ide_settings_path = ensure_within_root(profile_dir, profile_dir / "ide-data" / "User" / "settings.json")
    ide_settings = _read_existing_json_dict(ide_settings_path)
    ide_settings["update.mode"] = "none"
    atomic_write_json(ide_settings_path, ide_settings, mode=0o600)

    # Harden any existing sensitive runtime artifacts to 0600.
    sensitive_files = [
        profile_dir / "profile.json",
        profile_dir / "data" / "DevToolsActivePort",
        profile_dir / "ide-data" / "DevToolsActivePort",
        sandbox_home / ".gemini" / "installation_id",
        sandbox_home / ".gemini" / "jetski-standalone-oauth-token",
        sandbox_home / ".gemini" / "antigravity" / "mcp_config.json",
        sandbox_home / ".gemini" / "config" / "mcp_config.json",
        sandbox_home / ".gemini" / "mcp_config.json",
        sandbox_home / ".gemini" / "HANDOFF_CONTEXT.md",
    ]
    for sf in sensitive_files:
        _chmod_if_exists(sf, 0o600)

    return {
        "profile_dir": str(profile_dir),
        "sandbox_home": str(sandbox_home),
        "symlinks": link_result,
    }


def purge_stale_caches_if_upgraded(
    profile_dir: Path,
    manifest: ProfileManifest,
    targets: Dict[str, TargetInfo],
) -> List[str]:
    """Purge volatile Chromium bytecode/GPU caches when the host binary version changes."""
    purged: List[str] = []
    mapping = (("hub", "data"), ("ide", "ide-data"))
    for key, subdir in mapping:
        info = targets.get(key)
        if not info or not info.installed or not info.version:
            continue
        prev = manifest.last_host_versions.get(key)
        if prev and prev != info.version:
            base = ensure_within_root(profile_dir, profile_dir / subdir)
            for cache_name in CACHE_DIR_NAMES:
                cache_path = base / cache_name
                if cache_path.exists() and not cache_path.is_symlink():
                    verified = ensure_within_root(base, cache_path)
                    shutil.rmtree(str(verified), ignore_errors=True)
                    purged.append("{}/{}".format(subdir, cache_name))
        manifest.last_host_versions[key] = info.version
    return purged


def _scrub_url_secrets(text: str) -> Tuple[str, int]:
    """Redact userinfo and secret query parameters from URLs inside string values."""
    redacted = 0
    if "://" not in text:
        return text, 0
    try:
        parts = urlsplit(text)
    except ValueError:
        return text, 0
    if not parts.scheme or not parts.netloc:
        return text, 0

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if userinfo:
            netloc = "[REDACTED]@{}".format(hostport)
            redacted += 1

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        new_pairs: List[Tuple[str, str]] = []
        changed_query = False
        for k, v in pairs:
            if QUERY_SECRET_RE.search(k) and v != "":
                new_pairs.append((k, "REDACTED"))
                redacted += 1
                changed_query = True
            else:
                new_pairs.append((k, v))
        if changed_query:
            query = urlencode(new_pairs)

    if redacted == 0:
        return text, 0
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)), redacted


def _scrub_string(value: str) -> Tuple[str, int]:
    """Redact inline URL credentials, Bearer headers, and known token prefixes."""
    count = 0
    current = value
    if current.lower().startswith("bearer "):
        return "Bearer {}".format(REDACTED_MARKER), 1
    current, url_hits = _scrub_url_secrets(current)
    count += url_hits
    if TOKEN_PREFIX_RE.search(current):
        current = TOKEN_PREFIX_RE.sub(REDACTED_MARKER, current)
        count += 1
    return current, count


def _scrub_args_list(args: List[Any]) -> Tuple[List[Any], int]:
    """Scrub secret values embedded in MCP CLI args (--key=val or --token val)."""
    out: List[Any] = []
    redacted = 0
    idx = 0
    total = len(args)
    while idx < total:
        item = args[idx]
        if not isinstance(item, str):
            scrubbed_item, hits = _scrub_structure(item, force_redact=False)
            out.append(scrubbed_item)
            redacted += hits
            idx += 1
            continue

        eq_match = ARG_EQ_SECRET_RE.match(item)
        if eq_match:
            flag_prefix = eq_match.group(1)
            out.append("{}={}".format(flag_prefix, REDACTED_MARKER))
            redacted += 1
            idx += 1
            continue

        if ARG_FLAG_SECRET_RE.match(item) and idx + 1 < total:
            next_item = args[idx + 1]
            if isinstance(next_item, str) and not next_item.startswith("-"):
                out.append(item)
                out.append(REDACTED_MARKER)
                redacted += 1
                idx += 2
                continue

        scrubbed_str, hits = _scrub_string(item)
        out.append(scrubbed_str)
        redacted += hits
        idx += 1
    return out, redacted


def _scrub_structure(node: Any, force_redact: bool = False) -> Tuple[Any, int]:
    """Recursively scrub secrets across JSON objects, lists, and strings."""
    if isinstance(node, dict):
        cleaned: Dict[str, Any] = {}
        hits = 0
        for key, val in node.items():
            key_str = str(key)
            key_sensitive = force_redact or bool(SECRET_KEY_RE.search(key_str))
            if key_str == "args" and isinstance(val, list):
                scrubbed_args, arg_hits = _scrub_args_list(val)
                cleaned[key_str] = scrubbed_args
                hits += arg_hits
            elif key_sensitive and isinstance(val, (str, int, float)):
                cleaned[key_str] = REDACTED_MARKER
                hits += 1
            elif key_sensitive and isinstance(val, dict):
                sub, sub_hits = _scrub_structure(val, force_redact=True)
                cleaned[key_str] = sub
                hits += sub_hits
            elif key_sensitive and isinstance(val, list):
                sub, sub_hits = _scrub_structure(val, force_redact=True)
                cleaned[key_str] = sub
                hits += sub_hits
            else:
                sub, sub_hits = _scrub_structure(val, force_redact=False)
                cleaned[key_str] = sub
                hits += sub_hits
        return cleaned, hits

    if isinstance(node, list):
        out_list: List[Any] = []
        hits = 0
        for item in node:
            sub, sub_hits = _scrub_structure(item, force_redact=force_redact)
            out_list.append(sub)
            hits += sub_hits
        return out_list, hits

    if isinstance(node, str):
        if force_redact:
            return REDACTED_MARKER, 1
        return _scrub_string(node)

    if force_redact and isinstance(node, (int, float)):
        return REDACTED_MARKER, 1

    return node, 0


def sanitize_mcp_json_text(raw_text: str, source_path: str = "mcp_config.json") -> Tuple[Dict[str, Any], int]:
    """Strictly parse MCP JSON and scrub secrets; never fall back to raw file copying."""
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ToolError(
            "mcp_config_malformed",
            "Refusing to copy {} because JSON parsing failed: {}.".format(source_path, exc.msg),
            "Fix the JSON syntax error in {} or omit '--inherit-config'.".format(source_path),
            {"source": source_path, "line": exc.lineno, "column": exc.colno},
        ) from exc
    if not isinstance(parsed, dict):
        raise ToolError(
            "mcp_config_malformed",
            "Refusing to copy {} because its root value is not a JSON object.".format(source_path),
            "Ensure {} contains a valid top-level JSON object.".format(source_path),
            {"source": source_path},
        )
    scrubbed, count = _scrub_structure(parsed, force_redact=False)
    return scrubbed, count


HANDOFF_START_MARKER = "<!-- AGY_PROFILES_HANDOFF_START -->"
HANDOFF_END_MARKER = "<!-- AGY_PROFILES_HANDOFF_END -->"
_HANDOFF_BLOCK_RE = re.compile(
    r"\n*" + re.escape(HANDOFF_START_MARKER) + r".*?" + re.escape(HANDOFF_END_MARKER) + r"\n*",
    re.DOTALL,
)
_PBTXT_TITLE_RE = re.compile(r'(?:^|\n)\s*title\s*:\s*"((?:[^"\\]|\\.)*)"')
_XML_BLOCK_RE = re.compile(
    r"<(?:CONTEXT_SUMMARY|system-reminder|local-command-[a-z-]+)>.*?</(?:CONTEXT_SUMMARY|system-reminder|local-command-[a-z-]+)>",
    re.DOTALL | re.IGNORECASE,
)
_XML_TAG_RE = re.compile(r"<[^>]+>")
_INLINE_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{8,}")
_SPACED_HYPHEN_RE = re.compile(r"\s+-\s+")
_SKIP_TREE_NAMES = {
    ".DS_Store",
    ".git",
    "__pycache__",
    "node_modules",
    "web-ui",
    "tests",
    "dist",
    "build",
    ".astryx",
}
_SKIP_SECRET_FILENAMES = {
    ".env",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    "google_accounts.json",
    "jetski-standalone-oauth-token",
}
_TRANSCRIPT_TAIL_BYTES = 32768


def _clean_prose_text(raw: str, max_len: int = 220) -> str:
    """Normalize snippet text, strip XML wrappers, scrub tokens, and avoid dash punctuation."""
    text = _XML_BLOCK_RE.sub(" ", raw or "")
    text = _XML_TAG_RE.sub(" ", text)
    text = text.replace("\u2014", ", ").replace("\u2013", ", ")
    text = _SPACED_HYPHEN_RE.sub(", ", text)
    text = _INLINE_BEARER_RE.sub("Bearer " + REDACTED_MARKER, text)
    text, _ = _scrub_string(text)
    collapsed = " ".join(text.split())
    if len(collapsed) > max_len:
        return collapsed[: max_len - 3].rstrip() + "..."
    return collapsed


def _read_json_safe(path: Path) -> Optional[Any]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _decode_jwt_email(id_token: str) -> Optional[str]:
    if not id_token or "." not in id_token:
        return None
    parts = id_token.split(".")
    if len(parts) < 2 or not parts[1]:
        return None
    payload_b64 = parts[1]
    padded = payload_b64 + ("=" * ((4 - (len(payload_b64) % 4)) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8", errors="replace"))
    except (ValueError, OSError):
        return None
    if isinstance(claims, dict):
        email = claims.get("email")
        if isinstance(email, str) and "@" in email:
            return email.strip()
    return None


def _read_oauth_identity(gemini_dir: Path) -> Dict[str, Any]:
    """Read non-secret email and auth method metadata; never return raw credentials."""
    token_path = gemini_dir / "jetski-standalone-oauth-token"
    if not token_path.is_file():
        return {"email": None, "auth_method": None, "oauth_present": False}
    payload = _read_json_safe(token_path)
    email: Optional[str] = None
    auth_method: Optional[str] = None
    if isinstance(payload, dict):
        raw_email = payload.get("id_token_email")
        if isinstance(raw_email, str) and raw_email.strip():
            email = raw_email.strip()
        elif isinstance(payload.get("id_token"), str):
            email = _decode_jwt_email(payload["id_token"])
        raw_method = payload.get("auth_method") or payload.get("type")
        if isinstance(raw_method, str) and raw_method.strip():
            auth_method = raw_method.strip()
    return {"email": email, "auth_method": auth_method, "oauth_present": True}


def _read_storage_username(app_storage_path: Path) -> Optional[str]:
    payload = _read_json_safe(app_storage_path)
    if not isinstance(payload, dict):
        return None
    direct = payload.get("agy.onboarding.lastLoginUsername")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    for key, val in payload.items():
        if str(key).endswith("lastLoginUsername") and isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _count_visible_entries(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    count = 0
    try:
        for entry in directory.iterdir():
            if not entry.name.startswith("."):
                count += 1
    except OSError:
        return 0
    return count


def _resolve_profile_mcp_file(sandbox_home: Path) -> Path:
    candidates = (
        sandbox_home / ".gemini" / "config" / "mcp_config.json",
        sandbox_home / ".gemini" / "antigravity" / "mcp_config.json",
        sandbox_home / ".gemini" / "mcp_config.json",
    )
    for cand in candidates:
        if cand.exists():
            return cand
    return candidates[0]


def _collect_live_sidecars(gemini_dir: Path, host_home: Optional[Path] = None) -> Dict[str, Path]:
    """Return mapping of sidecar ID -> sidecar.json path inside <gemini>/config/sidecars."""
    sidecars_dir = gemini_dir / "config" / "sidecars"
    if not sidecars_dir.is_dir():
        return {}
    live: Dict[str, Path] = {}
    try:
        entries = sorted(sidecars_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return {}
    for entry in entries:
        if entry.name.startswith("."):
            continue
        if host_home is not None and entry.is_symlink():
            try:
                resolved = entry.resolve(strict=True)
            except OSError:
                continue
            if _is_forbidden_host_target(resolved, host_home):
                continue
        if not entry.is_dir():
            continue
        sc_json = entry / "sidecar.json"
        if sc_json.is_file():
            live[entry.name] = sc_json
    return live


def _count_automations(gemini_dir: Path) -> Tuple[int, int]:
    """Count total defined scheduled Automations and how many are currently enabled."""
    live = _collect_live_sidecars(gemini_dir)
    if not live:
        return 0, 0
    cfg = _read_json_safe(gemini_dir / "config" / "config.json")
    sc_map = cfg.get("sidecars") if isinstance(cfg, dict) and isinstance(cfg.get("sidecars"), dict) else {}
    enabled = 0
    for sid in live:
        entry = sc_map.get(sid)
        if isinstance(entry, dict) and bool(entry.get("enabled")):
            enabled += 1
    return len(live), enabled


def _rewrite_gemini_paths(
    node: Any,
    src_gemini: Path,
    dst_gemini: Path,
    extra_src_prefixes: Optional[List[Path]] = None,
) -> Any:
    """Rewrite Host ~/.gemini paths inside automation configs to the sandbox .gemini directory."""
    dst_str = str(dst_gemini)
    raw_prefixes: List[str] = []
    for cand in [src_gemini, *(extra_src_prefixes or [])]:
        for variant in (str(cand),):
            if variant and variant not in raw_prefixes:
                raw_prefixes.append(variant)
        try:
            res_str = str(cand.resolve())
            if res_str and res_str not in raw_prefixes:
                raw_prefixes.append(res_str)
        except OSError:
            pass
    raw_prefixes.sort(key=len, reverse=True)
    if not raw_prefixes:
        return node

    patterns = [
        (
            re.compile(re.escape("file://" + p) + r"(?=/|$|[\s\"'`,;:\)\]}])"),
            "file://" + dst_str,
        )
        for p in raw_prefixes
    ] + [
        (
            re.compile(re.escape(p) + r"(?=/|$|[\s\"'`,;:\)\]}])"),
            dst_str,
        )
        for p in raw_prefixes
    ]

    def _walk(val: Any) -> Any:
        if isinstance(val, str):
            out = val
            for pat, repl in patterns:
                if pat.search(out):
                    out = pat.sub(lambda _m, r=repl: r, out)
            return out
        if isinstance(val, list):
            return [_walk(item) for item in val]
        if isinstance(val, dict):
            return {k: _walk(v) for k, v in val.items()}
        return val

    return _walk(node)


def _count_top_level_sessions(gemini_dir: Path) -> int:
    """Count top-level clickable sidebar sessions inside conversation_summaries.db read-only."""
    db_path = gemini_dir / "antigravity" / "conversation_summaries.db"
    if not db_path.is_file():
        return 0
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = _open_sqlite_readonly(db_path)
        tables = {
            str(r[0])
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "conversation_summaries" not in tables:
            return 0
        cols = {
            str(r[1])
            for r in conn.execute("PRAGMA table_info(conversation_summaries)").fetchall()
        }
        if "parent_conversation_id" in cols:
            row = conn.execute(
                "SELECT COUNT(*) FROM conversation_summaries "
                "WHERE parent_conversation_id IS NULL OR parent_conversation_id = ''"
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM conversation_summaries").fetchone()
        return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0
    finally:
        if conn is not None:
            conn.close()


def inspect_profile_sync_state(profile_dir: Path) -> Dict[str, Any]:
    """Summarize synced customizations inside a profile sandbox without inspecting secrets."""
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    gemini_dir = sandbox_home / ".gemini"
    projects_dir = gemini_dir / "config" / "projects"
    handoff_file = gemini_dir / "HANDOFF_CONTEXT.md"
    mcp_file = _resolve_profile_mcp_file(sandbox_home)
    auto_total, auto_enabled = _count_automations(gemini_dir)
    return {
        "projects_count": (
            sum(1 for p in projects_dir.glob("*.json") if p.is_file())
            if projects_dir.is_dir()
            else 0
        ),
        "sessions_count": _count_top_level_sessions(gemini_dir),
        "agents_count": _count_visible_entries(gemini_dir / "config" / "agents"),
        "plugins_count": _count_visible_entries(gemini_dir / "config" / "plugins"),
        "skills_count": _count_visible_entries(gemini_dir / "config" / "skills")
        + _count_visible_entries(gemini_dir / "antigravity" / "skills"),
        "automations_count": auto_total,
        "automations_enabled": auto_enabled,
        "hooks_present": (gemini_dir / "config" / "hooks.json").is_file(),
        "mcp_present": mcp_file.is_file(),
        "gemini_md_present": (gemini_dir / "GEMINI.md").is_file(),
        "handoff_present": handoff_file.is_file(),
    }


def detect_profile_account(profile_dir: Path) -> Dict[str, Any]:
    """Identify the signed-in Google account email inside a sandbox without exposing tokens."""
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    oauth_info = _read_oauth_identity(sandbox_home / ".gemini")
    storage_user = _read_storage_username(profile_dir / "data" / "app_storage.json")
    if not storage_user:
        storage_user = _read_storage_username(profile_dir / "ide-data" / "app_storage.json")

    email = oauth_info["email"] or storage_user
    if oauth_info["email"]:
        source = "oauth_token"
    elif storage_user:
        source = "app_storage"
    else:
        source = "unsigned"
    return {
        "email": email,
        "source": source,
        "auth_method": oauth_info["auth_method"],
        "oauth_present": oauth_info["oauth_present"],
    }


def detect_host_account(real_home: Optional[Path] = None) -> Dict[str, Any]:
    """Identify the active Host Antigravity account and customization counts."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    host_gemini = host_home / ".gemini"
    oauth_info = _read_oauth_identity(host_gemini)
    host_storage = _read_storage_username(
        host_home / "Library" / "Application Support" / "Antigravity" / "app_storage.json"
    )
    google_payload = _read_json_safe(host_gemini / "google_accounts.json")
    google_active: Optional[str] = None
    if isinstance(google_payload, dict):
        raw_active = google_payload.get("active") or google_payload.get("email")
        if isinstance(raw_active, str) and raw_active.strip():
            google_active = raw_active.strip()

    email = oauth_info["email"] or host_storage or google_active
    if oauth_info["email"]:
        source = "oauth_token"
    elif host_storage:
        source = "app_storage"
    elif google_active:
        source = "google_accounts"
    else:
        source = "unsigned"

    projects_dir = host_gemini / "config" / "projects"
    projects_count = (
        sum(1 for p in projects_dir.glob("*.json") if p.is_file())
        if projects_dir.is_dir()
        else 0
    )
    mcp_present = (
        (host_gemini / "config" / "mcp_config.json").is_file()
        or (host_gemini / "antigravity" / "mcp_config.json").is_file()
        or (host_gemini / "mcp_config.json").is_file()
    )
    auto_total, auto_enabled = _count_automations(host_gemini)
    return {
        "email": email,
        "source": source,
        "auth_method": oauth_info["auth_method"],
        "oauth_present": oauth_info["oauth_present"],
        "app_storage_email": host_storage,
        "google_accounts_active": google_active,
        "projects_count": projects_count,
        "sessions_count": _count_top_level_sessions(host_gemini),
        "plugins_count": _count_visible_entries(host_gemini / "config" / "plugins"),
        "agents_count": _count_visible_entries(host_gemini / "config" / "agents"),
        "skills_count": _count_visible_entries(host_gemini / "config" / "skills")
        + _count_visible_entries(host_gemini / "antigravity" / "skills"),
        "automations_count": auto_total,
        "automations_enabled": auto_enabled,
        "hooks_present": (host_gemini / "config" / "hooks.json").is_file(),
        "mcp_present": mcp_present,
        "handoff_present": (host_gemini / "HANDOFF_CONTEXT.md").is_file(),
    }


def _open_sqlite_readonly(db_path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect("file:{}?mode=ro".format(db_path), uri=True, timeout=2.0)
        conn.execute("SELECT 1").fetchone()
        return conn
    except sqlite3.OperationalError:
        conn = sqlite3.connect("file:{}?immutable=1".format(db_path), uri=True, timeout=2.0)
        conn.execute("SELECT 1").fetchone()
        return conn


def _load_host_project_map(host_gemini: Path) -> Dict[str, str]:
    projects_dir = host_gemini / "config" / "projects"
    pid_map: Dict[str, str] = {}
    if not projects_dir.is_dir():
        return pid_map
    for jf in sorted(projects_dir.glob("*.json")):
        if not jf.is_file():
            continue
        payload = _read_json_safe(jf)
        if not isinstance(payload, dict):
            continue
        pname = str(payload.get("name") or jf.stem).strip() or jf.stem
        pid = str(payload.get("id") or jf.stem).strip()
        if pid:
            pid_map[pid] = pname
        pid_map[jf.stem] = pname
    return pid_map


def _read_pbtxt_title(host_gemini: Path, conv_id: str) -> Optional[str]:
    annotations_dir = host_gemini / "antigravity" / "annotations"
    if not annotations_dir.is_dir():
        return None
    try:
        ann_path = ensure_within_root(annotations_dir, annotations_dir / "{}.pbtxt".format(conv_id))
    except ToolError:
        return None
    if not ann_path.is_file():
        return None
    try:
        raw = ann_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _PBTXT_TITLE_RE.search(raw)
    if not match:
        return None
    title = match.group(1).replace('\\"', '"').replace("\\\\", "\\").strip()
    return title or None


def _extract_step_text(step: Dict[str, Any]) -> str:
    for key in ("content", "text", "message"):
        val = step.get(key)
        if isinstance(val, str) and val.strip():
            return val
        if isinstance(val, list):
            chunks: List[str] = []
            for part in val:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
                elif isinstance(part, str):
                    chunks.append(part)
            joined = " ".join(chunks).strip()
            if joined:
                return joined
    return ""


def _read_transcript_tail(host_gemini: Path, conv_id: str) -> Dict[str, str]:
    brain_dir = host_gemini / "antigravity" / "brain"
    result = {"last_user_request": "", "last_agent_summary": ""}
    if not brain_dir.is_dir():
        return result
    try:
        log_path = ensure_within_root(
            brain_dir,
            brain_dir / conv_id / ".system_generated" / "logs" / "transcript.jsonl",
        )
    except ToolError:
        return result
    if not log_path.is_file():
        return result
    try:
        size = log_path.stat().st_size
        with open(log_path, "rb") as fh:
            if size > _TRANSCRIPT_TAIL_BYTES:
                fh.seek(size - _TRANSCRIPT_TAIL_BYTES)
            raw_bytes = fh.read(_TRANSCRIPT_TAIL_BYTES)
    except OSError:
        return result

    lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
    if size > _TRANSCRIPT_TAIL_BYTES and len(lines) > 1:
        lines = lines[1:]

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            step = json.loads(stripped)
        except ValueError:
            continue
        if not isinstance(step, dict):
            continue
        step_type = str(step.get("type") or step.get("role") or "").upper()
        source = str(step.get("source") or "").upper()
        text = _extract_step_text(step)
        if not text:
            continue
        cleaned = _clean_prose_text(text, max_len=240)
        if not cleaned:
            continue
        if step_type in ("USER_INPUT", "USER_REQUEST", "USER") or "USER" in source:
            result["last_user_request"] = cleaned
        elif step_type in ("PLANNER_RESPONSE", "ASSISTANT", "MODEL") or source == "MODEL":
            result["last_agent_summary"] = cleaned
    return result


def _parse_primary_workspace(raw_uris: Any) -> str:
    uri = ""
    if isinstance(raw_uris, list) and raw_uris:
        uri = str(raw_uris[0] or "")
    elif isinstance(raw_uris, str):
        text = raw_uris.strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list) and parsed:
                    uri = str(parsed[0] or "")
            except ValueError:
                uri = text
        else:
            uri = text
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    return uri.strip()


def _normalize_status_label(raw_status: Any) -> str:
    val = str(raw_status or "").strip()
    if not val:
        return "idle"
    upper = val.upper()
    if upper.endswith("RUNNING"):
        return "running"
    if upper.endswith("WAITING"):
        return "waiting"
    if upper.endswith("IDLE"):
        return "idle"
    return _clean_prose_text(val.lower(), max_len=32)


def collect_handoff_from_gemini(
    gemini_dir: Path,
    account_email: Optional[str],
    source_name: str = "host",
    limit: int = 10,
) -> Dict[str, Any]:
    """Read an Antigravity .gemini conversation database and transcripts strictly read-only."""
    capped_limit = max(1, min(30, int(limit)))
    db_path = gemini_dir / "antigravity" / "conversation_summaries.db"
    source_label = source_name or "host"
    source_title = "Host" if source_label == "host" else source_label

    if not db_path.is_file():
        return {
            "available": False,
            "source": source_label,
            "source_account": account_email,
            "db_path": str(db_path),
            "generated_at": utc_now_iso(),
            "host_account": account_email,
            "count": 0,
            "conversations": [],
            "resume_prompt": "",
            "reason": "{} conversation_summaries.db was not found.".format(source_title),
        }

    pid_map = _load_host_project_map(gemini_dir)
    conversations: List[Dict[str, Any]] = []
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = _open_sqlite_readonly(db_path)
        table_rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        tables = {str(r[0]) for r in table_rows}
        if "conversation_summaries" not in tables:
            return {
                "available": False,
                "source": source_label,
                "source_account": account_email,
                "db_path": str(db_path),
                "generated_at": utc_now_iso(),
                "host_account": account_email,
                "count": 0,
                "conversations": [],
                "resume_prompt": "",
                "reason": "{} database has no conversation_summaries table.".format(source_title),
            }

        col_rows = conn.execute("PRAGMA table_info(conversation_summaries)").fetchall()
        col_set = {str(r[1]) for r in col_rows}
        id_col = "conversation_id" if "conversation_id" in col_set else ("id" if "id" in col_set else None)
        if not id_col:
            return {
                "available": False,
                "source": source_label,
                "source_account": account_email,
                "db_path": str(db_path),
                "generated_at": utc_now_iso(),
                "host_account": account_email,
                "count": 0,
                "conversations": [],
                "resume_prompt": "",
                "reason": "{} conversation_summaries table is missing an identifier column.".format(source_title),
            }

        select_cols = [id_col]
        for cand in ("title", "preview", "last_modified_time", "updated_at", "workspace_uris", "status", "project_id"):
            if cand in col_set:
                select_cols.append(cand)
        where_clause = ""
        if "parent_conversation_id" in col_set:
            where_clause = "WHERE (parent_conversation_id IS NULL OR parent_conversation_id = '')"
        order_col = (
            "last_modified_time"
            if "last_modified_time" in col_set
            else ("updated_at" if "updated_at" in col_set else "rowid")
        )
        sql = "SELECT {} FROM conversation_summaries {} ORDER BY {} DESC LIMIT ?".format(
            ", ".join(select_cols),
            where_clause,
            order_col,
        )
        raw_rows = conn.execute(sql, (capped_limit,)).fetchall()
        for row in raw_rows:
            rec = {select_cols[idx]: row[idx] for idx in range(len(select_cols))}
            conv_id = str(rec.get(id_col) or "").strip()
            if not conv_id or "/" in conv_id or "\\" in conv_id or ".." in conv_id:
                continue
            raw_title = (
                str(rec.get("title") or "").strip()
                or _read_pbtxt_title(gemini_dir, conv_id)
                or "Untitled conversation"
            )
            title = _clean_prose_text(raw_title, max_len=120)
            primary_ws = _parse_primary_workspace(rec.get("workspace_uris"))
            proj_id = str(rec.get("project_id") or "").strip()
            proj_name = pid_map.get(proj_id) or (Path(primary_ws).name if primary_ws else "") or "General"
            proj_clean = _clean_prose_text(proj_name, max_len=64)
            tail = _read_transcript_tail(gemini_dir, conv_id)
            preview_clean = _clean_prose_text(str(rec.get("preview") or ""), max_len=240)
            last_user = tail["last_user_request"] or preview_clean
            last_agent = tail["last_agent_summary"]
            updated_at = str(rec.get("last_modified_time") or rec.get("updated_at") or "").strip()
            conversations.append(
                {
                    "conversation_id": conv_id,
                    "title": title,
                    "project": proj_clean,
                    "workspace": primary_ws,
                    "status": _normalize_status_label(rec.get("status")),
                    "updated_at": updated_at,
                    "last_user_request": last_user,
                    "last_agent_summary": last_agent,
                }
            )
    except sqlite3.Error as exc:
        return {
            "available": False,
            "source": source_label,
            "source_account": account_email,
            "db_path": str(db_path),
            "generated_at": utc_now_iso(),
            "host_account": account_email,
            "count": 0,
            "conversations": [],
            "resume_prompt": "",
            "reason": "Unable to read {} conversation database cleanly: {}.".format(source_title, exc),
        }
    finally:
        if conn is not None:
            conn.close()

    if source_label == "host":
        prompt_lines = [
            "Read ~/.gemini/HANDOFF_CONTEXT.md first to recover active Host workspace context.",
            "Recent Host threads:",
        ]
    else:
        acct_suffix = " ({})".format(account_email) if account_email else ""
        prompt_lines = [
            "Read ~/.gemini/HANDOFF_CONTEXT.md first to recover active {}{} workspace context.".format(
                source_label, acct_suffix
            ),
            "Recent {} threads:".format(source_label),
        ]
    for idx, item in enumerate(conversations[:5], start=1):
        summary = item["last_user_request"] or item["last_agent_summary"] or item["title"]
        prompt_lines.append(
            "{idx}. [{proj}] {title} (id {cid}): {summary}".format(
                idx=idx,
                proj=item["project"],
                title=item["title"],
                cid=item["conversation_id"],
                summary=summary,
            )
        )
    if not conversations:
        prompt_lines.append("1. No active {} threads were recorded yet.".format(source_title))

    return {
        "available": True,
        "source": source_label,
        "source_account": account_email,
        "db_path": str(db_path),
        "generated_at": utc_now_iso(),
        "host_account": account_email,
        "count": len(conversations),
        "conversations": conversations,
        "resume_prompt": "\n".join(prompt_lines),
    }


def collect_host_handoff(
    real_home: Optional[Path] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Read Host Antigravity conversation summaries and transcript tails strictly read-only."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    host_gemini = host_home / ".gemini"
    host_acct = detect_host_account(real_home=host_home)
    return collect_handoff_from_gemini(
        host_gemini,
        host_acct.get("email"),
        source_name="host",
        limit=limit,
    )


def _render_handoff_markdown(digest: Dict[str, Any], source_name: str = "host") -> str:
    """Format a sanitized, Zero-Dashes HANDOFF_CONTEXT.md document from a digest."""
    raw_src = str(digest.get("source") or source_name or "host")
    src_title = "Host" if raw_src == "host" else raw_src
    lines: List[str] = [
        "# {} Antigravity Handoff Context".format(src_title),
        "",
        "Generated at: {}".format(digest["generated_at"]),
        "Source account: {}".format(digest.get("source_account") or digest.get("host_account") or "unknown"),
        "Conversations indexed: {}".format(len(digest["conversations"])),
        "",
        "## Recent {} Threads".format(src_title),
        "",
    ]
    for idx, item in enumerate(digest["conversations"], start=1):
        lines.append("### {}. {}".format(idx, item["title"]))
        lines.append("Conversation ID: `{}`".format(item["conversation_id"]))
        lines.append("Project: {}".format(item["project"]))
        if item["workspace"]:
            lines.append("Workspace: `{}`".format(item["workspace"]))
        lines.append("Status: {}".format(item["status"]))
        if item["updated_at"]:
            lines.append("Updated: {}".format(item["updated_at"]))
        if item["last_user_request"]:
            lines.append("Latest request: {}".format(item["last_user_request"]))
        if item["last_agent_summary"]:
            lines.append("Latest assistant state: {}".format(item["last_agent_summary"]))
        lines.append("")

    if not digest["conversations"]:
        lines.append("No active conversations found in {} database.".format(src_title))
        lines.append("")

    lines.extend(["## Suggested Resume Prompt", "", "```text", digest["resume_prompt"], "```", ""])
    return "\n".join(lines)


def write_handoff_context(
    profile_dir: Path,
    real_home: Optional[Path] = None,
    limit: int = 10,
    source_gemini_dir: Optional[Path] = None,
    source_account: Optional[str] = None,
    source_name: str = "host",
) -> Dict[str, Any]:
    """Generate a sanitized, Zero-Dashes HANDOFF_CONTEXT.md inside the sandbox .gemini dir."""
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    if source_gemini_dir is not None:
        digest = collect_handoff_from_gemini(
            source_gemini_dir,
            source_account,
            source_name=source_name,
            limit=limit,
        )
    else:
        digest = collect_host_handoff(real_home=real_home, limit=limit)
    if not digest.get("available") and not digest.get("conversations"):
        return {
            "written": False,
            "path": None,
            "count": 0,
            "source": digest.get("source", source_name),
            "reason": digest.get("reason") or "Host handoff unavailable.",
        }

    dst_path = ensure_within_root(sandbox_home, sandbox_home / ".gemini" / "HANDOFF_CONTEXT.md")
    atomic_write_text(dst_path, _render_handoff_markdown(digest, source_name=source_name), mode=0o600)
    return {
        "written": True,
        "path": str(dst_path),
        "count": len(digest["conversations"]),
        "source": digest.get("source", source_name),
    }


def write_host_handoff_context(
    source_gemini_dir: Path,
    source_account: Optional[str],
    source_name: str,
    real_home: Optional[Path] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Write a backup profile's HANDOFF_CONTEXT.md back into Host ~/.gemini without modifying Host config."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    host_gemini = ensure_within_root(host_home, host_home / ".gemini")
    digest = collect_handoff_from_gemini(
        source_gemini_dir,
        source_account,
        source_name=source_name,
        limit=limit,
    )
    if not digest.get("available") and not digest.get("conversations"):
        return {
            "written": False,
            "path": None,
            "count": 0,
            "source": digest.get("source", source_name),
            "reason": digest.get("reason") or "Backup profile handoff unavailable.",
        }

    _mkdir_0700(host_gemini)
    dst_path = ensure_within_root(host_gemini, host_gemini / "HANDOFF_CONTEXT.md")
    atomic_write_text(dst_path, _render_handoff_markdown(digest, source_name=source_name), mode=0o600)
    return {
        "written": True,
        "path": str(dst_path),
        "count": len(digest["conversations"]),
        "source": digest.get("source", source_name),
    }


def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    tmp_path = path.parent / ".{}.{}.tmp".format(path.name, os.getpid())
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(tmp_path), mode)
        os.replace(str(tmp_path), str(path))
        os.chmod(str(path), mode)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _is_forbidden_host_target(resolved: Path, host_home: Path) -> bool:
    for rel in FORBIDDEN_HOME_RELPATHS:
        forbidden_abs = (host_home / rel).resolve()
        if resolved == forbidden_abs:
            return True
        try:
            resolved.relative_to(forbidden_abs)
            return True
        except ValueError:
            continue
    return False


def _prune_stale_children(target_dir: Path, keep_names: set, sandbox_home: Path) -> int:
    """Remove stale files/directories inside target_dir not present in keep_names."""
    if not target_dir.exists() or target_dir.is_symlink() or not target_dir.is_dir():
        return 0
    pruned = 0
    try:
        children = list(target_dir.iterdir())
    except OSError:
        return 0
    for child in children:
        if child.name in keep_names:
            continue
        if child.is_symlink():
            ensure_symlink_slot_within_root(sandbox_home, child)
            child.unlink()
            pruned += 1
            continue
        verified = ensure_within_root(sandbox_home, child)
        if verified.is_dir():
            shutil.rmtree(str(verified))
        else:
            verified.unlink()
        pruned += 1
    return pruned


def _sync_safe_tree(
    src_root: Path,
    dst_root: Path,
    sandbox_home: Path,
    host_home: Path,
    prune: bool = True,
) -> Dict[str, int]:
    verified_dst = ensure_within_root(sandbox_home, dst_root)
    if not src_root.exists() or not src_root.is_dir():
        pruned_missing = _prune_stale_children(verified_dst, set(), sandbox_home) if prune else 0
        return {"files_copied": 0, "redacted_secrets": 0, "pruned_entries": pruned_missing}

    _mkdir_0700(verified_dst)
    files_copied = 0
    redacted_secrets = 0
    pruned_entries = 0
    seen_dirs: set[Tuple[int, int]] = set()

    def _walk(curr_src: Path, curr_dst: Path, depth: int) -> None:
        nonlocal files_copied, redacted_secrets, pruned_entries
        if depth > 12:
            return
        try:
            st = curr_src.stat()
        except OSError:
            return
        dir_key = (st.st_dev, st.st_ino)
        if dir_key in seen_dirs:
            return
        seen_dirs.add(dir_key)
        _mkdir_0700(curr_dst)

        try:
            entries = sorted(curr_src.iterdir(), key=lambda p: p.name)
        except OSError:
            return

        kept_names: set[str] = set()
        for entry in entries:
            if entry.name in _SKIP_TREE_NAMES:
                continue
            target_node = entry
            if entry.is_symlink():
                try:
                    target_node = entry.resolve(strict=True)
                except OSError:
                    continue
                if _is_forbidden_host_target(target_node, host_home):
                    continue
                if target_node == verified_dst:
                    continue
                try:
                    verified_dst.relative_to(target_node)
                    continue
                except ValueError:
                    pass

            child_dst = ensure_within_root(sandbox_home, curr_dst / entry.name)
            if target_node.is_dir():
                kept_names.add(entry.name)
                _walk(target_node, child_dst, depth + 1)
                continue
            if not target_node.is_file():
                continue

            lower_name = entry.name.lower()
            if (
                lower_name in _SKIP_SECRET_FILENAMES
                or "oauth-token" in lower_name
                or lower_name.endswith(".pem")
                or lower_name.endswith(".key")
            ):
                continue

            try:
                src_mode = target_node.stat().st_mode
                dst_mode = 0o700 if (src_mode & 0o111) else 0o600
                if "mcp" in lower_name and lower_name.endswith(".json"):
                    raw_text = target_node.read_text(encoding="utf-8", errors="replace")
                    parsed = json.loads(raw_text)
                    if isinstance(parsed, (dict, list)):
                        scrubbed, hits = _scrub_structure(parsed, force_redact=False)
                        redacted_secrets += hits
                        atomic_write_json(child_dst, scrubbed, mode=0o600)
                        files_copied += 1
                        kept_names.add(entry.name)
                        continue
                raw_bytes = target_node.read_bytes()
            except (OSError, ValueError):
                continue
            _atomic_write_bytes(child_dst, raw_bytes, mode=dst_mode)
            files_copied += 1
            kept_names.add(entry.name)

        if prune:
            pruned_entries += _prune_stale_children(curr_dst, kept_names, sandbox_home)

    _walk(src_root, verified_dst, 0)
    return {
        "files_copied": files_copied,
        "redacted_secrets": redacted_secrets,
        "pruned_entries": pruned_entries,
    }


def _scrub_json_object_file(src_path: Path) -> Tuple[Dict[str, Any], int]:
    return sanitize_mcp_json_text(
        src_path.read_text(encoding="utf-8"),
        source_path=str(src_path),
    )


def _render_gemini_handoff_block() -> str:
    return "\n".join(
        [
            HANDOFF_START_MARKER,
            "## Host Handoff Context",
            "",
            "Active workspace and thread context from the Host Antigravity account was written to `~/.gemini/HANDOFF_CONTEXT.md`. Read that file before continuing existing tasks.",
            HANDOFF_END_MARKER,
        ]
    )


def _encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf unsigned LEB128 varint."""
    n = max(0, int(value))
    out = bytearray()
    while True:
        chunk = n & 0x7F
        n >>= 7
        if n:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            break
    return bytes(out)


def _build_agyhub_summaries_proto(rows: List[Tuple[str, Optional[bytes]]]) -> bytes:
    """Encode map<string, TrajectorySummary> wire entries for agyhub_summaries_proto.pb."""
    chunks: List[bytes] = []
    for cid, raw_summary in rows:
        if not cid or not raw_summary:
            continue
        key_bytes = cid.encode("utf-8")
        val_bytes = bytes(raw_summary)
        entry = (
            b"\x0a"
            + _encode_varint(len(key_bytes))
            + key_bytes
            + b"\x12"
            + _encode_varint(len(val_bytes))
            + val_bytes
        )
        chunks.append(b"\x0a" + _encode_varint(len(entry)) + entry)
    return b"".join(chunks)


def _backup_sqlite_file(src_db: Path, dst_db: Path) -> bool:
    """Safely snapshot a live or closed WAL SQLite database into dst_db via sqlite3.backup."""
    if not src_db.is_file() or src_db.is_symlink():
        return False
    dst_db.parent.mkdir(parents=True, exist_ok=True)
    tmp_db = dst_db.parent / ".{}.{}.tmp".format(dst_db.name, os.getpid())
    if tmp_db.exists() or tmp_db.is_symlink():
        tmp_db.unlink()

    src_conn: Optional[sqlite3.Connection] = None
    dst_conn: Optional[sqlite3.Connection] = None
    try:
        src_conn = _open_sqlite_readonly(src_db)
        dst_conn = sqlite3.connect(str(tmp_db), timeout=5.0)
        src_conn.backup(dst_conn)
        dst_conn.close()
        dst_conn = None
        src_conn.close()
        src_conn = None
    except sqlite3.Error:
        if dst_conn is not None:
            dst_conn.close()
        if src_conn is not None:
            src_conn.close()
        if tmp_db.exists():
            tmp_db.unlink()
        try:
            shutil.copy2(str(src_db), str(tmp_db))
        except OSError:
            return False

    os.chmod(str(tmp_db), 0o600)
    for wal_suffix in ("-wal", "-shm"):
        side_file = dst_db.parent / (dst_db.name + wal_suffix)
        if side_file.is_file() and not side_file.is_symlink():
            try:
                side_file.unlink()
            except OSError:
                pass
    os.replace(str(tmp_db), str(dst_db))
    return True


def _sync_brain_conversation_dir(src_brain_cid: Path, dst_brain_cid: Path, dst_root: Path) -> int:
    """Incrementally copy user artifacts, media, and compact transcript logs for one thread."""
    if not src_brain_cid.is_dir() or src_brain_cid.is_symlink():
        return 0
    _mkdir_0700(ensure_within_root(dst_root, dst_brain_cid))
    copied_files = 0
    max_artifact_bytes = 12 * 1024 * 1024
    max_transcript_bytes = 8 * 1024 * 1024

    for entry in src_brain_cid.iterdir():
        if entry.is_symlink():
            continue
        if entry.name == ".system_generated":
            src_tr = entry / "logs" / "transcript.jsonl"
            if src_tr.is_file() and not src_tr.is_symlink():
                try:
                    st = src_tr.stat()
                except OSError:
                    continue
                if st.st_size <= max_transcript_bytes:
                    dst_logs = ensure_within_root(dst_root, dst_brain_cid / ".system_generated" / "logs")
                    _mkdir_0700(dst_logs)
                    dst_tr = ensure_within_root(dst_root, dst_logs / "transcript.jsonl")
                    if not dst_tr.is_file() or dst_tr.stat().st_size != st.st_size:
                        raw_tr = src_tr.read_text(encoding="utf-8", errors="replace")
                        if TOKEN_PREFIX_RE.search(raw_tr):
                            raw_tr = TOKEN_PREFIX_RE.sub(REDACTED_MARKER, raw_tr)
                        atomic_write_text(dst_tr, raw_tr, mode=0o600)
                        copied_files += 1
            continue

        if entry.is_file():
            try:
                st = entry.stat()
            except OSError:
                continue
            if st.st_size > max_artifact_bytes:
                continue
            dst_f = ensure_within_root(dst_root, dst_brain_cid / entry.name)
            if not dst_f.is_file() or dst_f.stat().st_size != st.st_size or int(dst_f.stat().st_mtime) < int(st.st_mtime):
                if entry.suffix.lower() in (".md", ".jsonl", ".txt", ".json"):
                    raw_txt = entry.read_text(encoding="utf-8", errors="replace")
                    if TOKEN_PREFIX_RE.search(raw_txt):
                        raw_txt = TOKEN_PREFIX_RE.sub(REDACTED_MARKER, raw_txt)
                    atomic_write_text(dst_f, raw_txt, mode=0o600)
                else:
                    shutil.copy2(str(entry), str(dst_f))
                    os.chmod(str(dst_f), 0o600)
                copied_files += 1
        elif entry.is_dir() and entry.name in (".user_uploaded", "browser_sandbox"):
            dst_sub = ensure_within_root(dst_root, dst_brain_cid / entry.name)
            _mkdir_0700(dst_sub)
            for sub_f in entry.iterdir():
                if not sub_f.is_file() or sub_f.is_symlink():
                    continue
                try:
                    st = sub_f.stat()
                except OSError:
                    continue
                if st.st_size > max_artifact_bytes:
                    continue
                dst_sf = ensure_within_root(dst_root, dst_sub / sub_f.name)
                if not dst_sf.is_file() or dst_sf.stat().st_size != st.st_size:
                    shutil.copy2(str(sub_f), str(dst_sf))
                    os.chmod(str(dst_sf), 0o600)
                    copied_files += 1
    return copied_files


def _sync_single_session_store(
    src_ag: Path,
    dst_ag_raw: Path,
    dst_root_bound: Path,
    host_home: Path,
    proto_filename: str,
    capped_limit: int,
    skip_locked_on_dst: bool,
    rebuild_proto: bool,
    app_data_dir_override: Optional[str] = None,
    extra_presence_dirs: Optional[List[Path]] = None,
) -> Dict[str, Any]:
    """Merge top-level SQLite trajectories, brain artifacts, worktrees, and proto index for one app store."""
    src_sum_db = src_ag / "conversation_summaries.db"
    if not src_sum_db.is_file():
        return {
            "synced_sessions": 0,
            "synced_cids": [],
            "skipped_up_to_date": 0,
            "worktrees_linked": 0,
            "proto_rebuilt": False,
        }

    dst_ag = ensure_within_root(dst_root_bound, dst_ag_raw)
    for sub_name in ("conversations", "annotations", "chapter_titles", "brain", "worktrees"):
        _mkdir_0700(ensure_within_root(dst_root_bound, dst_ag / sub_name))

    wt_linked = 0
    src_wt_dir = src_ag / "worktrees"
    dst_wt_dir = ensure_within_root(dst_root_bound, dst_ag / "worktrees")
    if src_wt_dir.is_dir():
        for wt_entry in sorted(src_wt_dir.iterdir(), key=lambda p: p.name):
            if not wt_entry.is_symlink():
                continue
            try:
                resolved_wt = wt_entry.resolve(strict=True)
            except OSError:
                continue
            if _is_forbidden_host_target(resolved_wt, host_home):
                continue
            dst_slot = ensure_symlink_slot_within_root(dst_wt_dir, dst_wt_dir / wt_entry.name)
            if dst_slot.is_symlink():
                if os.readlink(str(dst_slot)) != str(resolved_wt):
                    dst_slot.unlink()
                    create_safe_link(resolved_wt, dst_slot)
                    wt_linked += 1
            elif not dst_slot.exists():
                create_safe_link(resolved_wt, dst_slot)
                wt_linked += 1

    src_conn: Optional[sqlite3.Connection] = None
    src_cols: List[str] = []
    src_rows: List[Tuple[Any, ...]] = []
    create_sqls: List[str] = []
    try:
        src_conn = _open_sqlite_readonly(src_sum_db)
        tables = {
            str(r[0])
            for r in src_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "conversation_summaries" not in tables:
            return {
                "synced_sessions": 0,
                "synced_cids": [],
                "skipped_up_to_date": 0,
                "worktrees_linked": wt_linked,
                "proto_rebuilt": False,
            }
        for mtype, mname, msql in src_conn.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"
        ).fetchall():
            if mtype in ("table", "index") and not str(mname).startswith("sqlite_"):
                if "conversations_fts_" in str(mname):
                    continue
                create_sqls.append(str(msql))

        src_cols = [
            str(r[1])
            for r in src_conn.execute("PRAGMA table_info(conversation_summaries)").fetchall()
        ]
        if "conversation_id" not in src_cols:
            return {
                "synced_sessions": 0,
                "synced_cids": [],
                "skipped_up_to_date": 0,
                "worktrees_linked": wt_linked,
                "proto_rebuilt": False,
            }
        where_top = (
            "WHERE (parent_conversation_id IS NULL OR parent_conversation_id = '')"
            if "parent_conversation_id" in src_cols
            else ""
        )
        order_by = "last_modified_time DESC" if "last_modified_time" in src_cols else "rowid DESC"
        quoted_cols = ", ".join('"{}"'.format(c) for c in src_cols)
        src_rows = src_conn.execute(
            "SELECT {} FROM conversation_summaries {} ORDER BY {} LIMIT ?".format(
                quoted_cols, where_top, order_by
            ),
            (capped_limit,),
        ).fetchall()
    finally:
        if src_conn is not None:
            src_conn.close()

    dst_sum_db = ensure_within_root(dst_root_bound, dst_ag / "conversation_summaries.db")
    dst_conn = sqlite3.connect(str(dst_sum_db), timeout=5.0)
    synced_count = 0
    synced_cids: List[str] = []
    skipped_count = 0
    proto_rebuilt = False
    presence_dirs = [dst_ag / "presence"] + list(extra_presence_dirs or [])
    try:
        dst_conn.execute("PRAGMA journal_mode=WAL")
        dst_tables = {
            str(r[0])
            for r in dst_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "conversation_summaries" not in dst_tables:
            for stmt in create_sqls:
                try:
                    dst_conn.execute(stmt)
                except sqlite3.Error:
                    pass
            dst_conn.commit()

        dst_cols = [
            str(r[1])
            for r in dst_conn.execute("PRAGMA table_info(conversation_summaries)").fetchall()
        ]
        common_cols = [c for c in src_cols if c in dst_cols]
        col_idx = {c: i for i, c in enumerate(src_cols)}

        existing_map: Dict[str, Tuple[int, str]] = {}
        has_step_col = "step_count" in dst_cols
        has_mod_col = "last_modified_time" in dst_cols
        sel_existing = "SELECT conversation_id, {}, {} FROM conversation_summaries".format(
            "step_count" if has_step_col else "0",
            "last_modified_time" if has_mod_col else "''",
        )
        for erow in dst_conn.execute(sel_existing).fetchall():
            existing_map[str(erow[0])] = (int(erow[1] or 0), str(erow[2] or ""))

        placeholders = ", ".join("?" for _ in common_cols)
        insert_sql = "INSERT OR REPLACE INTO conversation_summaries ({}) VALUES ({})".format(
            ", ".join('"{}"'.format(c) for c in common_cols),
            placeholders,
        )

        for row in src_rows:
            cid = str(row[col_idx["conversation_id"]] or "").strip()
            if not cid or "/" in cid or "\\" in cid or ".." in cid:
                continue
            if skip_locked_on_dst and any((pdir / "{}.lock".format(cid)).exists() for pdir in presence_dirs):
                skipped_count += 1
                continue

            src_steps = int(row[col_idx["step_count"]] or 0) if "step_count" in col_idx else 0
            src_mod = str(row[col_idx["last_modified_time"]] or "") if "last_modified_time" in col_idx else ""
            dst_conv_file = ensure_within_root(dst_root_bound, dst_ag / "conversations" / "{}.db".format(cid))
            src_conv_file = src_ag / "conversations" / "{}.db".format(cid)

            prev = existing_map.get(cid)
            is_newer = (
                prev is None
                or src_steps > prev[0]
                or (src_mod and src_mod > prev[1])
                or (src_conv_file.is_file() and not dst_conv_file.is_file())
            )
            if not is_newer:
                skipped_count += 1
                continue

            if src_conv_file.is_file():
                _backup_sqlite_file(src_conv_file, dst_conv_file)

            src_ann = src_ag / "annotations" / "{}.pbtxt".format(cid)
            if src_ann.is_file() and not src_ann.is_symlink():
                dst_ann = ensure_within_root(dst_root_bound, dst_ag / "annotations" / "{}.pbtxt".format(cid))
                shutil.copy2(str(src_ann), str(dst_ann))
                os.chmod(str(dst_ann), 0o600)

            src_chap = src_ag / "chapter_titles" / "{}.pb".format(cid)
            if src_chap.is_file() and not src_chap.is_symlink():
                dst_chap = ensure_within_root(dst_root_bound, dst_ag / "chapter_titles" / "{}.pb".format(cid))
                shutil.copy2(str(src_chap), str(dst_chap))
                os.chmod(str(dst_chap), 0o600)

            _sync_brain_conversation_dir(src_ag / "brain" / cid, dst_ag / "brain" / cid, dst_root_bound)

            row_vals = [row[col_idx[c]] for c in common_cols]
            if app_data_dir_override is not None and "app_data_dir" in common_cols:
                app_col_pos = common_cols.index("app_data_dir")
                row_vals[app_col_pos] = app_data_dir_override
            dst_conn.execute(insert_sql, tuple(row_vals))
            synced_count += 1
            synced_cids.append(cid)

        dst_conn.commit()

        if rebuild_proto and "raw_summary" in dst_cols:
            order_proto = "ORDER BY last_modified_time DESC" if has_mod_col else ""
            proto_rows = dst_conn.execute(
                "SELECT conversation_id, raw_summary FROM conversation_summaries {}".format(order_proto)
            ).fetchall()
            proto_bytes = _build_agyhub_summaries_proto(
                [(str(r[0]), r[1]) for r in proto_rows if r[0] and r[1]]
            )
            if proto_bytes:
                dst_proto = ensure_within_root(dst_root_bound, dst_ag / proto_filename)
                _atomic_write_bytes(dst_proto, proto_bytes, mode=0o600)
                proto_rebuilt = True
    finally:
        dst_conn.close()

    os.chmod(str(dst_sum_db), 0o600)
    return {
        "synced_sessions": synced_count,
        "synced_cids": synced_cids,
        "skipped_up_to_date": skipped_count,
        "worktrees_linked": wt_linked,
        "proto_rebuilt": proto_rebuilt,
    }


def _read_store_session_versions(gemini_dir: Path) -> Dict[str, Tuple[int, str]]:
    """Read highest (step_count, last_modified_time) per conversation_id across Hub and CLI stores."""
    merged: Dict[str, Tuple[int, str]] = {}
    for sub in ("antigravity", "antigravity-cli"):
        db_p = gemini_dir / sub / "conversation_summaries.db"
        if not db_p.is_file():
            continue
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = _open_sqlite_readonly(db_p)
            cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(conversation_summaries)").fetchall()}
            if "conversation_id" not in cols:
                continue
            step_expr = "step_count" if "step_count" in cols else "0"
            mod_expr = "last_modified_time" if "last_modified_time" in cols else "''"
            for r in conn.execute(
                "SELECT conversation_id, {}, {} FROM conversation_summaries".format(step_expr, mod_expr)
            ).fetchall():
                cid = str(r[0] or "")
                if not cid:
                    continue
                cand = (int(r[1] or 0), str(r[2] or ""))
                prev = merged.get(cid)
                if prev is None or cand[0] > prev[0] or (cand[1] and cand[1] > prev[1]):
                    merged[cid] = cand
        except sqlite3.Error:
            continue
        finally:
            if conn is not None:
                conn.close()
    return merged


def sync_conversation_sessions(
    src_gemini: Path,
    dst_gemini: Path,
    dst_root_bound: Path,
    host_home: Path,
    limit: int = 25,
    skip_locked_on_dst: bool = False,
    rebuild_proto: bool = True,
) -> Dict[str, Any]:
    """Incrementally merge clickable Hub (antigravity) and Terminal CLI (antigravity-cli) sessions."""
    capped_limit = max(1, min(100, int(limit)))
    before_versions = _read_store_session_versions(dst_gemini)
    both_presence = [
        dst_gemini / "antigravity" / "presence",
        dst_gemini / "antigravity-cli" / "presence",
    ]
    hub_res = _sync_single_session_store(
        src_ag=src_gemini / "antigravity",
        dst_ag_raw=dst_gemini / "antigravity",
        dst_root_bound=dst_root_bound,
        host_home=host_home,
        proto_filename="agyhub_summaries_proto.pb",
        capped_limit=capped_limit,
        skip_locked_on_dst=skip_locked_on_dst,
        rebuild_proto=rebuild_proto,
        app_data_dir_override="antigravity",
        extra_presence_dirs=both_presence,
    )
    # Bridge terminal CLI sessions into Hub store too so Desktop Hub and Antigravity Mobile see CLI threads.
    cli_to_hub_res = _sync_single_session_store(
        src_ag=src_gemini / "antigravity-cli",
        dst_ag_raw=dst_gemini / "antigravity",
        dst_root_bound=dst_root_bound,
        host_home=host_home,
        proto_filename="agyhub_summaries_proto.pb",
        capped_limit=min(capped_limit, 15),
        skip_locked_on_dst=skip_locked_on_dst,
        rebuild_proto=rebuild_proto,
        app_data_dir_override="antigravity",
        extra_presence_dirs=both_presence,
    )
    cli_res = _sync_single_session_store(
        src_ag=src_gemini / "antigravity-cli",
        dst_ag_raw=dst_gemini / "antigravity-cli",
        dst_root_bound=dst_root_bound,
        host_home=host_home,
        proto_filename="jetbox_summaries_proto.pb",
        capped_limit=capped_limit,
        skip_locked_on_dst=skip_locked_on_dst,
        rebuild_proto=True,
        app_data_dir_override="antigravity-cli",
        extra_presence_dirs=both_presence,
    )
    # Bridge Hub sessions into CLI store too so 'agyp resume' (-c) in terminal can also continue Hub threads.
    hub_to_cli_res = _sync_single_session_store(
        src_ag=src_gemini / "antigravity",
        dst_ag_raw=dst_gemini / "antigravity-cli",
        dst_root_bound=dst_root_bound,
        host_home=host_home,
        proto_filename="jetbox_summaries_proto.pb",
        capped_limit=min(capped_limit, 15),
        skip_locked_on_dst=skip_locked_on_dst,
        rebuild_proto=True,
        app_data_dir_override="antigravity-cli",
        extra_presence_dirs=both_presence,
    )
    after_versions = _read_store_session_versions(dst_gemini)
    distinct_advanced = [
        cid
        for cid, ver in after_versions.items()
        if cid not in before_versions
        or ver[0] > before_versions[cid][0]
        or (ver[1] and ver[1] > before_versions[cid][1])
    ]
    hub_unique = set(hub_res["synced_cids"]).union(cli_to_hub_res["synced_cids"])
    cli_unique = set(cli_res["synced_cids"]).union(hub_to_cli_res["synced_cids"])
    return {
        "synced_sessions": len(distinct_advanced),
        "hub_synced_sessions": len(hub_unique),
        "cli_synced_sessions": len(cli_unique),
        "skipped_up_to_date": hub_res["skipped_up_to_date"] + cli_res["skipped_up_to_date"],
        "total_dst_sessions": len(after_versions),
        "worktrees_linked": hub_res["worktrees_linked"] + cli_res["worktrees_linked"],
        "proto_rebuilt": bool(
            hub_res["proto_rebuilt"]
            or cli_to_hub_res["proto_rebuilt"]
            or cli_res["proto_rebuilt"]
            or hub_to_cli_res["proto_rebuilt"]
        ),
    }


PAUSED_HOST_SIDECARS_FILE = ".agy_paused_host_sidecars.json"


def _derive_mobile_device_name(base_hostname: str, profile_name: Optional[str]) -> str:
    raw_base = (base_hostname or "").strip()
    if not raw_base:
        raw_base = re.sub(r"[^a-zA-Z0-9-]+", "-", socket.gethostname().split(".")[0].lower()).strip("-") or "mac"
    if not profile_name:
        return raw_base
    suffix = "-{}".format(profile_name)
    if raw_base.lower().endswith(suffix.lower()):
        return raw_base
    return "{}{}".format(raw_base, suffix)


def _apply_turbo_user_settings(user_settings: Any, profile_name: Optional[str] = None) -> Dict[str, Any]:
    """Ensure Hub, IDE, and Antigravity Mobile run in full Turbo bypass and RemoteControl mode."""
    cfg = dict(user_settings) if isinstance(user_settings, dict) else {}
    cfg["permissionPreset"] = "AGENT_PERMISSION_PRESET_TURBO"
    cfg["remotePermissionPreset"] = "AGENT_PERMISSION_PRESET_TURBO"
    cfg["artifactReviewMode"] = "ARTIFACT_REVIEW_MODE_TURBO"
    cfg["autoExecutionPolicy"] = "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER"
    cfg["browserJsExecutionPolicy"] = "BROWSER_JS_EXECUTION_POLICY_TURBO"
    cfg["nonWorkspaceFileAccessPolicy"] = "AGENT_SETTING_POLICY_ALLOW"
    cfg["enableTerminalSandbox"] = False
    cfg["remoteControlEnabled"] = True
    device_name = _derive_mobile_device_name(str(cfg.get("remoteControlHostname") or ""), profile_name)
    cfg["remoteControlHostname"] = device_name
    cfg["cliRemoteControlHostname"] = device_name
    grants = cfg.get("globalPermissionGrants")
    grants_dict = dict(grants) if isinstance(grants, dict) else {}
    allow_list = list(grants_dict.get("allow")) if isinstance(grants_dict.get("allow"), list) else []
    if "command(*)" not in allow_list:
        allow_list.append("command(*)")
    grants_dict["allow"] = allow_list
    cfg["globalPermissionGrants"] = grants_dict
    return cfg


def _apply_turbo_cli_settings(cli_settings: Any) -> Dict[str, Any]:
    """Ensure Antigravity CLI ('agy') runs in always-proceed Turbo mode without manual prompts."""
    cfg = dict(cli_settings) if isinstance(cli_settings, dict) else {}
    cfg["toolPermission"] = "always-proceed"
    cfg["agentMode"] = "auto"
    cfg["artifactReviewPolicy"] = "always-proceed"
    cfg["allowNonWorkspaceAccess"] = True
    cfg["enableTerminalSandbox"] = False
    perms = cfg.get("permissions")
    perms_dict = dict(perms) if isinstance(perms, dict) else {}
    allow_list = list(perms_dict.get("allow")) if isinstance(perms_dict.get("allow"), list) else []
    if "command(*)" not in allow_list:
        allow_list.append("command(*)")
    perms_dict["allow"] = allow_list
    cfg["permissions"] = perms_dict
    return cfg


def _apply_turbo_project_settings(proj: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure project-level overrides never downgrade Turbo auto-execution or command grants."""
    out = dict(proj)
    st = dict(out.get("settings")) if isinstance(out.get("settings"), dict) else {}
    st["artifactReviewMode"] = "ARTIFACT_REVIEW_MODE_TURBO"
    st["autoExecutionPolicy"] = "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER"
    st["nonWorkspaceFileAccessPolicy"] = "AGENT_SETTING_POLICY_ALLOW"
    st["enableTerminalSandbox"] = False
    out["settings"] = st

    pg = out.get("permissionGrants")
    if isinstance(pg, dict):
        pg_copy = dict(pg)
        allow_list = list(pg_copy.get("allow")) if isinstance(pg_copy.get("allow"), list) else []
        if "command(*)" not in allow_list:
            allow_list.append("command(*)")
        pg_copy["allow"] = allow_list
        out["permissionGrants"] = pg_copy
    return out


def _apply_turbo_sidecar_permissions(sc: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure scheduled automation sidecars never hang waiting for manual command approval."""
    out = dict(sc)
    if str(out.get("builtin") or "") == "schedule" and isinstance(out.get("agent_permissions"), dict):
        ap = dict(out["agent_permissions"])
        grants = list(ap.get("access_grants")) if isinstance(ap.get("access_grants"), list) else []
        if "command(*)" not in grants:
            grants.append("command(*)")
        ap["access_grants"] = grants
        out["agent_permissions"] = ap
    return out


def _read_paused_host_sidecar_ids(host_gemini: Path) -> List[str]:
    ledger = host_gemini / "config" / PAUSED_HOST_SIDECARS_FILE
    if not ledger.is_file():
        return []
    parsed = _read_json_safe(ledger)
    if isinstance(parsed, dict) and isinstance(parsed.get("paused_ids"), list):
        return [str(x) for x in parsed["paused_ids"] if str(x).strip()]
    return []


def pause_host_automations(real_home: Optional[Path] = None) -> Dict[str, Any]:
    """Never disable Host schedule sidecars; inspect enabled IDs read-only and leave Host config.json untouched."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    host_gemini = ensure_within_root(host_home, host_home / ".gemini")
    ledger = host_gemini / "config" / PAUSED_HOST_SIDECARS_FILE
    if ledger.is_file() and not ledger.is_symlink():
        ensure_within_root(host_home, ledger).unlink()
    cfg_path = host_gemini / "config" / "config.json"
    if not cfg_path.is_file() or cfg_path.is_symlink():
        return {"paused_count": 0, "paused_ids": [], "observed_enabled_ids": [], "host_automations_preserved": True}
    parsed = _read_json_safe(cfg_path)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("sidecars"), dict):
        return {"paused_count": 0, "paused_ids": [], "observed_enabled_ids": [], "host_automations_preserved": True}

    live_sidecars = _collect_live_sidecars(host_gemini, host_home=host_home)
    raw_sidecars = parsed["sidecars"]
    now_enabled = [
        sid
        for sid in sorted(live_sidecars.keys())
        if isinstance(raw_sidecars.get(sid), dict) and bool(raw_sidecars[sid].get("enabled", False))
    ]
    return {
        "paused_count": 0,
        "paused_ids": [],
        "observed_enabled_ids": now_enabled,
        "host_automations_preserved": True,
    }


def restore_host_automations(real_home: Optional[Path] = None) -> Dict[str, Any]:
    """Clean up legacy paused-sidecar ledger without modifying Host config.json."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    host_gemini = ensure_within_root(host_home, host_home / ".gemini")
    ledger = host_gemini / "config" / PAUSED_HOST_SIDECARS_FILE
    if ledger.is_file() and not ledger.is_symlink():
        ensure_within_root(host_home, ledger).unlink()
    return {"restored_count": 0, "restored_ids": [], "host_automations_preserved": True}


def sync_host_customizations(
    profile_dir: Path,
    real_home: Optional[Path] = None,
    include_sidecars: bool = False,
    automations_mode: Optional[str] = None,
    include_handoff: bool = True,
    handoff_limit: int = 10,
    handoff_source_gemini: Optional[Path] = None,
    handoff_source_account: Optional[str] = None,
    handoff_source_name: str = "host",
    include_sessions: bool = True,
    session_limit: int = 25,
    turbo_bypass: bool = True,
) -> Dict[str, Any]:
    """Sync sanitized Host projects, automations, plugins, agents, skills, rules, MCP JSON, and optional handoff."""
    mode = (
        validate_automations_mode(automations_mode)
        if automations_mode is not None
        else ("active" if include_sidecars else "paused")
    )
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    raw_home_prefix: List[Path] = [(real_home / ".gemini")] if real_home is not None else []
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    host_gemini = host_home / ".gemini"
    sandbox_gemini = ensure_within_root(sandbox_home, sandbox_home / ".gemini")
    for required_dir in (
        sandbox_gemini,
        sandbox_gemini / "antigravity",
        sandbox_gemini / "config",
        sandbox_gemini / "config" / "projects",
    ):
        _mkdir_0700(required_dir)

    copied: List[str] = []
    redacted_total = 0
    stripped_sidecars = 0
    pruned_entries = 0

    host_gemini_md = host_gemini / "GEMINI.md"
    dst_md = ensure_within_root(sandbox_home, sandbox_gemini / "GEMINI.md")
    base_md: Optional[str] = None
    if host_gemini_md.is_file():
        raw_md = host_gemini_md.read_text(encoding="utf-8", errors="replace")
        if TOKEN_PREFIX_RE.search(raw_md):
            raw_md = TOKEN_PREFIX_RE.sub(REDACTED_MARKER, raw_md)
            redacted_total += 1
        base_md = _HANDOFF_BLOCK_RE.sub("", raw_md).rstrip()
    elif dst_md.is_file():
        existing_md = dst_md.read_text(encoding="utf-8", errors="replace")
        base_md = _HANDOFF_BLOCK_RE.sub("", existing_md).rstrip()

    handoff_result = (
        write_handoff_context(
            profile_dir,
            real_home=host_home,
            limit=handoff_limit,
            source_gemini_dir=handoff_source_gemini,
            source_account=handoff_source_account,
            source_name=handoff_source_name,
        )
        if include_handoff
        else {"written": False, "path": None, "count": 0, "reason": "Handoff skipped."}
    )
    if handoff_result.get("written"):
        copied.append("HANDOFF_CONTEXT.md")
        prefix = (base_md + "\n\n") if base_md else ""
        atomic_write_text(dst_md, prefix + _render_gemini_handoff_block() + "\n", mode=0o600)
        copied.append("GEMINI.md")
    elif host_gemini_md.is_file() and base_md is not None:
        atomic_write_text(dst_md, (base_md + "\n") if base_md else "", mode=0o600)
        copied.append("GEMINI.md")

    for src_json, dst_json_raw, label in (
        (host_gemini / "settings.json", sandbox_gemini / "settings.json", "settings.json"),
        (host_gemini / "trustedFolders.json", sandbox_gemini / "trustedFolders.json", "trustedFolders.json"),
    ):
        if not src_json.is_file():
            continue
        scrubbed_obj, hits = _scrub_json_object_file(src_json)
        dst_json = ensure_within_root(sandbox_home, dst_json_raw)
        atomic_write_json(dst_json, scrubbed_obj, mode=0o600)
        copied.append(label)
        redacted_total += hits

    # Sync and enforce Turbo bypass on Antigravity CLI settings.json (even if Host file is absent).
    host_cli_settings = host_gemini / "antigravity-cli" / "settings.json"
    cli_obj: Dict[str, Any] = {}
    if host_cli_settings.is_file():
        scrubbed_cli, cli_hits = _scrub_json_object_file(host_cli_settings)
        redacted_total += cli_hits
        if isinstance(scrubbed_cli, dict):
            cli_obj = dict(scrubbed_cli)
            gw = cli_obj.get("gateway")
            if isinstance(gw, dict) and gw.get("apiKey") == REDACTED_MARKER:
                gw["enabled"] = False
    if turbo_bypass:
        cli_obj = _apply_turbo_cli_settings(cli_obj)
    if cli_obj:
        _mkdir_0700(ensure_within_root(sandbox_home, sandbox_gemini / "antigravity-cli"))
        dst_cli_settings = ensure_within_root(sandbox_home, sandbox_gemini / "antigravity-cli" / "settings.json")
        atomic_write_json(dst_cli_settings, cli_obj, mode=0o600)
        copied.append("antigravity-cli/settings.json")

    host_projects_index = host_gemini / "projects.json"
    if host_projects_index.is_file():
        try:
            parsed_idx = json.loads(host_projects_index.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ToolError(
                "mcp_config_malformed",
                "Refusing to copy {} because JSON parsing failed: {}.".format(host_projects_index, exc.msg),
                "Fix the JSON syntax error in projects.json before syncing.",
                {"source": str(host_projects_index), "line": exc.lineno, "column": exc.colno},
            ) from exc
        if isinstance(parsed_idx, (dict, list)):
            scrubbed_idx, hits = _scrub_structure(parsed_idx, force_redact=False)
            redacted_total += hits
            dst_idx = ensure_within_root(sandbox_home, sandbox_gemini / "projects.json")
            atomic_write_json(dst_idx, scrubbed_idx, mode=0o600)
            copied.append("projects.json")

    # Deduplicate MCP files across Hub symlink targets so secrets and counts never double.
    seen_mcp_sources: Dict[Path, Dict[str, Any]] = {}
    mcp_candidates = (
        (host_gemini / "config" / "mcp_config.json", sandbox_gemini / "config" / "mcp_config.json", "config/mcp_config.json"),
        (host_gemini / "antigravity" / "mcp_config.json", sandbox_gemini / "antigravity" / "mcp_config.json", "antigravity/mcp_config.json"),
        (host_gemini / "mcp_config.json", sandbox_gemini / "mcp_config.json", "mcp_config.json"),
    )
    primary_scrubbed_mcp: Optional[Dict[str, Any]] = None
    for src_mcp, dst_mcp_raw, label in mcp_candidates:
        if not src_mcp.is_file():
            continue
        resolved_src = src_mcp.resolve()
        if resolved_src in seen_mcp_sources:
            scrubbed_mcp = seen_mcp_sources[resolved_src]
        else:
            scrubbed_mcp, hits = _scrub_json_object_file(src_mcp)
            seen_mcp_sources[resolved_src] = scrubbed_mcp
            redacted_total += hits
        if primary_scrubbed_mcp is None:
            primary_scrubbed_mcp = scrubbed_mcp
        dst_mcp = ensure_within_root(sandbox_home, dst_mcp_raw)
        if dst_mcp.is_symlink():
            dst_mcp.unlink()
        atomic_write_json(dst_mcp, scrubbed_mcp, mode=0o600)
        copied.append(label)

    # Ensure both Hub v2.32 config/mcp_config.json and legacy antigravity/mcp_config.json stay populated.
    if primary_scrubbed_mcp is not None:
        for alias_raw, alias_label in (
            (sandbox_gemini / "config" / "mcp_config.json", "config/mcp_config.json"),
            (sandbox_gemini / "antigravity" / "mcp_config.json", "antigravity/mcp_config.json"),
        ):
            if alias_label in copied:
                continue
            alias_dst = ensure_within_root(sandbox_home, alias_raw)
            if not alias_dst.is_symlink():
                atomic_write_json(alias_dst, primary_scrubbed_mcp, mode=0o600)

    # Sync or strip Host scheduled Automations: write config/config.json first so a running
    # sandbox language_server sees enabled=False before new sidecar.json files appear on disk.
    live_sidecars = _collect_live_sidecars(host_gemini, host_home=host_home)
    host_cfg_json = host_gemini / "config" / "config.json"
    parsed_cfg: Optional[Any] = (
        _read_json_safe(host_cfg_json)
        if host_cfg_json.is_file()
        else ({"sidecars": {}} if (live_sidecars and mode in ("paused", "active")) or turbo_bypass else None)
    )
    if isinstance(parsed_cfg, dict):
        if turbo_bypass:
            parsed_cfg["userSettings"] = _apply_turbo_user_settings(
                parsed_cfg.get("userSettings"),
                profile_name=profile_dir.name,
            )
        raw_sidecars = parsed_cfg.get("sidecars")
        if mode == "strip":
            if isinstance(raw_sidecars, dict):
                stripped_sidecars += len(raw_sidecars)
                stripped_sidecars += sum(1 for sid in live_sidecars if sid not in raw_sidecars)
            else:
                if raw_sidecars:
                    stripped_sidecars += 1
                stripped_sidecars += len(live_sidecars)
            parsed_cfg["sidecars"] = {}
        else:
            new_sidecars: Dict[str, Any] = {}
            if isinstance(raw_sidecars, dict):
                for key, val in raw_sidecars.items():
                    key_str = str(key)
                    if "/" in key_str:
                        new_sidecars[key_str] = _rewrite_gemini_paths(
                            val,
                            host_gemini,
                            sandbox_gemini,
                            extra_src_prefixes=raw_home_prefix,
                        )
                    elif key_str in live_sidecars and isinstance(val, dict):
                        rewritten_entry = _rewrite_gemini_paths(
                            val,
                            host_gemini,
                            sandbox_gemini,
                            extra_src_prefixes=raw_home_prefix,
                        )
                        entry_copy = dict(rewritten_entry) if isinstance(rewritten_entry, dict) else {}
                        if mode == "paused":
                            entry_copy["enabled"] = False
                        new_sidecars[key_str] = entry_copy
                    else:
                        stripped_sidecars += 1
            for sid in live_sidecars:
                if sid not in new_sidecars:
                    new_sidecars[sid] = {
                        "enabled": False if mode == "paused" else True,
                        "schemaVersion": 1,
                    }
            parsed_cfg["sidecars"] = new_sidecars
        scrubbed_cfg, hits = _scrub_structure(parsed_cfg, force_redact=False)
        redacted_total += hits
        dst_cfg = ensure_within_root(sandbox_home, sandbox_gemini / "config" / "config.json")
        atomic_write_json(dst_cfg, scrubbed_cfg, mode=0o600)
        copied.append("config/config.json")

    sandbox_sidecars_dir = ensure_within_root(sandbox_home, sandbox_gemini / "config" / "sidecars")
    if mode == "strip":
        pruned_entries += _prune_stale_children(sandbox_sidecars_dir, set(), sandbox_home)
    else:
        _mkdir_0700(sandbox_sidecars_dir)
        pruned_entries += _prune_stale_children(sandbox_sidecars_dir, set(live_sidecars.keys()), sandbox_home)
        sidecar_copied_any = False
        for sid, src_sc_json in live_sidecars.items():
            raw_sc = _read_json_safe(src_sc_json)
            if not isinstance(raw_sc, dict):
                continue
            rewritten_sc = _rewrite_gemini_paths(
                raw_sc,
                host_gemini,
                sandbox_gemini,
                extra_src_prefixes=raw_home_prefix,
            )
            if turbo_bypass and isinstance(rewritten_sc, dict):
                rewritten_sc = _apply_turbo_sidecar_permissions(rewritten_sc)
            scrubbed_sc, hits = _scrub_structure(rewritten_sc, force_redact=False)
            redacted_total += hits
            dst_sc_dir = ensure_within_root(sandbox_sidecars_dir, sandbox_sidecars_dir / sid)
            _mkdir_0700(dst_sc_dir)
            atomic_write_json(ensure_within_root(dst_sc_dir, dst_sc_dir / "sidecar.json"), scrubbed_sc, mode=0o600)
            _mkdir_0700(ensure_within_root(sandbox_home, sandbox_gemini / "antigravity" / "sidecar_data" / sid))
            sidecar_copied_any = True
        if sidecar_copied_any:
            copied.append("config/sidecars")

    for rel_json in (
        "config/plugins.json",
        "config/skills.json",
        "config/hooks.json",
        "config/import_manifest.json",
    ):
        src_rel = host_gemini / rel_json
        dst_rel_raw = sandbox_gemini / rel_json
        if not src_rel.is_file():
            if dst_rel_raw.is_file() and not dst_rel_raw.is_symlink():
                ensure_within_root(sandbox_home, dst_rel_raw).unlink()
                pruned_entries += 1
            continue
        parsed_rel = _read_json_safe(src_rel)
        if isinstance(parsed_rel, (dict, list)):
            rewritten_rel = _rewrite_gemini_paths(
                parsed_rel,
                host_gemini,
                sandbox_gemini,
                extra_src_prefixes=raw_home_prefix,
            )
            scrubbed_rel, hits = _scrub_structure(rewritten_rel, force_redact=False)
            redacted_total += hits
            dst_rel = ensure_within_root(sandbox_home, dst_rel_raw)
            atomic_write_json(dst_rel, scrubbed_rel, mode=0o600)
            copied.append(rel_json)

    for rel_text in ("config/routing.md", "config/registry.yaml"):
        src_txt = host_gemini / rel_text
        if not src_txt.is_file():
            continue
        content = src_txt.read_text(encoding="utf-8", errors="replace")
        if TOKEN_PREFIX_RE.search(content):
            content = TOKEN_PREFIX_RE.sub(REDACTED_MARKER, content)
            redacted_total += 1
        dst_txt = ensure_within_root(sandbox_home, sandbox_gemini / rel_text)
        atomic_write_text(dst_txt, content, mode=0o600)
        copied.append(rel_text)

    projects_synced = 0
    seen_project_files: set[str] = set()
    host_projects_dir = host_gemini / "config" / "projects"
    sandbox_projects_dir = ensure_within_root(sandbox_home, sandbox_gemini / "config" / "projects")
    if host_projects_dir.is_dir():
        for src_proj in sorted(host_projects_dir.glob("*.json")):
            if not src_proj.is_file():
                continue
            parsed_proj = _read_json_safe(src_proj)
            if not isinstance(parsed_proj, dict):
                continue
            seen_project_files.add(src_proj.name)
            if "sidecar" in parsed_proj:
                sc_ref = parsed_proj.get("sidecar")
                ref_id = str(sc_ref.get("sidecarId") or "").strip() if isinstance(sc_ref, dict) else ""
                if mode == "strip" or not ref_id or ref_id not in live_sidecars:
                    parsed_proj.pop("sidecar", None)
                    stripped_sidecars += 1
            rewritten_proj = _rewrite_gemini_paths(
                parsed_proj,
                host_gemini,
                sandbox_gemini,
                extra_src_prefixes=raw_home_prefix,
            )
            if turbo_bypass and isinstance(rewritten_proj, dict):
                rewritten_proj = _apply_turbo_project_settings(rewritten_proj)
            scrubbed_proj, hits = _scrub_structure(rewritten_proj, force_redact=False)
            redacted_total += hits
            dst_proj = ensure_within_root(sandbox_projects_dir, sandbox_projects_dir / src_proj.name)
            atomic_write_json(dst_proj, scrubbed_proj, mode=0o600)
            projects_synced += 1
        if projects_synced > 0:
            copied.append("config/projects")
    pruned_entries += _prune_stale_children(sandbox_projects_dir, seen_project_files, sandbox_home)

    tree_files = 0
    for tree_rel in ("config/agents", "config/skills", "config/plugins", "antigravity/skills"):
        tree_res = _sync_safe_tree(
            host_gemini / tree_rel,
            sandbox_gemini / tree_rel,
            sandbox_home,
            host_home,
            prune=True,
        )
        redacted_total += tree_res["redacted_secrets"]
        pruned_entries += tree_res["pruned_entries"]
        if tree_res["files_copied"] > 0:
            tree_files += tree_res["files_copied"]
            copied.append(tree_rel)

    # Merge safe non-auth UI layout keys from Host app_storage.json (Persona, sidebar order, pins, zoom)
    # without touching login usernames, OAuth state, or profile accent color.
    host_app_storage = host_home / "Library" / "Application Support" / "Antigravity" / "app_storage.json"
    if host_app_storage.is_file() and not host_app_storage.is_symlink():
        parsed_host_st = _read_json_safe(host_app_storage)
        if isinstance(parsed_host_st, dict):
            safe_ui_keys = (
                "onboardingPersonaId",
                "projectsOrder",
                "pinned_conversations_order",
                "sidebar_section_display",
                "sidebar_collapsed_sections",
                "sidebar_collapsed_section_headers",
                "theme-preset-dark",
                "jetski.contrast",
                "zoomLevel",
                "defaultLinkOpenTarget",
                "keepComputerAwake",
                "browserSubagentWebviewUx",
            )
            dst_app_storage = ensure_within_root(profile_dir, profile_dir / "data" / "app_storage.json")
            existing_st = _read_json_safe(dst_app_storage) if dst_app_storage.is_file() else {}
            if not isinstance(existing_st, dict):
                existing_st = {}
            changed_ui = False
            for ui_k in safe_ui_keys:
                if ui_k in parsed_host_st and existing_st.get(ui_k) != parsed_host_st[ui_k]:
                    existing_st[ui_k] = parsed_host_st[ui_k]
                    changed_ui = True
            if "onboardingPersonaId" not in existing_st:
                existing_st["onboardingPersonaId"] = "engineering"
                changed_ui = True
            if changed_ui:
                _mkdir_0700(ensure_within_root(profile_dir, profile_dir / "data"))
                atomic_write_json(dst_app_storage, existing_st, mode=0o600)
                copied.append("data/app_storage.json")

    # Sync sanitized Antigravity IDE editor settings and keybindings into ide-data/User when present.
    host_ide_user = host_home / "Library" / "Application Support" / "Antigravity IDE" / "User"
    if host_ide_user.is_dir() and not host_ide_user.is_symlink():
        dst_ide_user = ensure_within_root(profile_dir, profile_dir / "ide-data" / "User")
        _mkdir_0700(dst_ide_user)
        for ide_fname in ("settings.json", "keybindings.json"):
            src_ide_f = host_ide_user / ide_fname
            if not src_ide_f.is_file() or src_ide_f.is_symlink():
                continue
            parsed_ide_f = _read_json_safe(src_ide_f)
            if isinstance(parsed_ide_f, (dict, list)):
                scrubbed_ide_f, ide_hits = _scrub_structure(parsed_ide_f, force_redact=False)
                redacted_total += ide_hits
                atomic_write_json(
                    ensure_within_root(dst_ide_user, dst_ide_user / ide_fname),
                    scrubbed_ide_f,
                    mode=0o600,
                )
                copied.append("ide-data/User/{}".format(ide_fname))

    sessions_src_gemini = handoff_source_gemini if handoff_source_gemini is not None else host_gemini
    sessions_result: Dict[str, Any] = {
        "synced_sessions": 0,
        "skipped_up_to_date": 0,
        "total_dst_sessions": 0,
        "worktrees_linked": 0,
        "proto_rebuilt": False,
    }
    if include_sessions:
        sessions_result = sync_conversation_sessions(
            src_gemini=sessions_src_gemini,
            dst_gemini=sandbox_gemini,
            dst_root_bound=sandbox_home,
            host_home=host_home,
            limit=session_limit,
            skip_locked_on_dst=True,
            rebuild_proto=True,
        )
        if sessions_result["synced_sessions"] > 0:
            copied.append("antigravity/conversations")

    sync_state = inspect_profile_sync_state(profile_dir)
    sessions_result["total_dst_sessions"] = sync_state["sessions_count"]
    return {
        "copied": copied,
        "redacted_secrets": redacted_total,
        "stripped_sidecars": stripped_sidecars,
        "pruned_entries": pruned_entries,
        "automations_mode": mode,
        "automations_synced": sync_state["automations_count"],
        "automations_enabled": sync_state["automations_enabled"],
        "projects_synced": projects_synced,
        "sessions_synced": sessions_result["synced_sessions"],
        "sessions": sessions_result,
        "agents_synced": sync_state["agents_count"],
        "plugins_synced": sync_state["plugins_count"],
        "skills_synced": sync_state["skills_count"],
        "tree_files_copied": tree_files,
        "handoff": handoff_result,
        "sync_state": sync_state,
        "synced_at": utc_now_iso(),
    }


def inherit_host_customizations(
    profile_dir: Path,
    real_home: Optional[Path] = None,
) -> Dict[str, Any]:
    """Inherit non-secret GEMINI.md, sanitized setup trees/JSON, paused automations, and handoff from host."""
    return sync_host_customizations(
        profile_dir,
        real_home=real_home,
        automations_mode="paused",
        include_handoff=True,
    )


def audit_profile_isolation(profile_dir: Path, manifest: ProfileManifest) -> Dict[str, Any]:
    """Inspect sandbox permissions, symlinks, .zshenv HOME isolation, and synced setup state."""
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    data_dir = ensure_within_root(profile_dir, profile_dir / "data")

    def _mode_str(p: Path) -> Optional[str]:
        if not p.exists() or p.is_symlink():
            return None
        return oct(p.stat().st_mode & 0o777)

    forbidden_links_present: List[str] = []
    for rel in FORBIDDEN_HOME_RELPATHS:
        slot = sandbox_home / rel
        if slot.is_symlink():
            forbidden_links_present.append(rel)

    active_links: List[Dict[str, str]] = []
    for rel in ALL_MANAGED_LINKS:
        slot = sandbox_home / rel
        if slot.is_symlink():
            active_links.append({"relpath": rel, "target": os.readlink(str(slot))})

    zshenv_path = sandbox_home / ".zshenv"
    zshenv_locked = False
    if zshenv_path.is_file() and not zshenv_path.is_symlink():
        text = zshenv_path.read_text(encoding="utf-8", errors="replace")
        zshenv_locked = "export HOME=" in text

    token_file = sandbox_home / ".gemini" / "jetski-standalone-oauth-token"
    mcp_file = _resolve_profile_mcp_file(sandbox_home)
    handoff_file = sandbox_home / ".gemini" / "HANDOFF_CONTEXT.md"

    return {
        "permissions": {
            "profile_dir": _mode_str(profile_dir),
            "data_dir": _mode_str(data_dir),
            "sandbox_home": _mode_str(sandbox_home),
            "oauth_token_file": _mode_str(token_file),
            "mcp_config_file": _mode_str(mcp_file),
            "handoff_file": _mode_str(handoff_file),
            "zshenv_file": _mode_str(zshenv_path),
        },
        "auth_mode": manifest.auth_mode,
        "link_policy": manifest.link_policy,
        "zshenv_home_locked": zshenv_locked,
        "oauth_token_present": token_file.is_file(),
        "forbidden_symlinks_present": forbidden_links_present,
        "active_symlinks": active_links,
        "sync_state": inspect_profile_sync_state(profile_dir),
    }
