"""Sandbox directory provisioning, symlink blocklist, cache hygiene, and MCP scrubbing."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agy_profiles.config import (
    CACHE_DIR_NAMES,
    ProfileManifest,
    TargetInfo,
    atomic_write_json,
    atomic_write_text,
    ensure_symlink_slot_within_root,
    ensure_within_root,
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
    r"(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{10,}|gho_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|xoxb-[A-Za-z0-9-]{10,}|xoxp-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{10,})"
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
                        os.symlink(str(src), str(slot))
                elif not slot.exists():
                    os.symlink(str(src), str(slot))
                linked.append(clean_rel)
            else:
                skipped_missing.append(clean_rel)
        else:
            if slot.is_symlink():
                slot.unlink()
                removed.append(clean_rel)
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
    _write_sandbox_zshenv(sandbox_home, host_home)
    link_result = _reconcile_policy_symlinks(sandbox_home, host_home, manifest.link_policy)

    # Suppress Hub auto-updater and enforce requested background tray behavior.
    app_storage_path = ensure_within_root(profile_dir, profile_dir / "data" / "app_storage.json")
    app_storage = _read_existing_json_dict(app_storage_path)
    app_storage["autoCheckForUpdates"] = "false"
    app_storage["runInBackground"] = "true" if manifest.keep_background_alive else "false"
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
_SKIP_TREE_NAMES = {".DS_Store", ".git", "__pycache__", "node_modules"}
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


def inspect_profile_sync_state(profile_dir: Path) -> Dict[str, Any]:
    """Summarize synced customizations inside a profile sandbox without inspecting secrets."""
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    projects_dir = sandbox_home / ".gemini" / "config" / "projects"
    handoff_file = sandbox_home / ".gemini" / "HANDOFF_CONTEXT.md"
    mcp_file = _resolve_profile_mcp_file(sandbox_home)
    return {
        "projects_count": (
            sum(1 for p in projects_dir.glob("*.json") if p.is_file())
            if projects_dir.is_dir()
            else 0
        ),
        "agents_count": _count_visible_entries(sandbox_home / ".gemini" / "config" / "agents"),
        "plugins_count": _count_visible_entries(sandbox_home / ".gemini" / "config" / "plugins"),
        "skills_count": _count_visible_entries(sandbox_home / ".gemini" / "config" / "skills")
        + _count_visible_entries(sandbox_home / ".gemini" / "antigravity" / "skills"),
        "mcp_present": mcp_file.is_file(),
        "gemini_md_present": (sandbox_home / ".gemini" / "GEMINI.md").is_file(),
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
    return {
        "email": email,
        "source": source,
        "auth_method": oauth_info["auth_method"],
        "oauth_present": oauth_info["oauth_present"],
        "app_storage_email": host_storage,
        "google_accounts_active": google_active,
        "projects_count": projects_count,
        "plugins_count": _count_visible_entries(host_gemini / "config" / "plugins"),
        "agents_count": _count_visible_entries(host_gemini / "config" / "agents"),
        "skills_count": _count_visible_entries(host_gemini / "config" / "skills")
        + _count_visible_entries(host_gemini / "antigravity" / "skills"),
        "mcp_present": mcp_present,
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


def collect_host_handoff(
    real_home: Optional[Path] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Read Host Antigravity conversation summaries and transcript tails strictly read-only."""
    capped_limit = max(1, min(30, int(limit)))
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    host_gemini = host_home / ".gemini"
    db_path = host_gemini / "antigravity" / "conversation_summaries.db"
    host_acct = detect_host_account(real_home=host_home)

    if not db_path.is_file():
        return {
            "available": False,
            "db_path": str(db_path),
            "generated_at": utc_now_iso(),
            "host_account": host_acct.get("email"),
            "count": 0,
            "conversations": [],
            "resume_prompt": "",
            "reason": "Host conversation_summaries.db was not found.",
        }

    pid_map = _load_host_project_map(host_gemini)
    conversations: List[Dict[str, Any]] = []
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = _open_sqlite_readonly(db_path)
        table_rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        tables = {str(r[0]) for r in table_rows}
        if "conversation_summaries" not in tables:
            return {
                "available": False,
                "db_path": str(db_path),
                "generated_at": utc_now_iso(),
                "host_account": host_acct.get("email"),
                "count": 0,
                "conversations": [],
                "resume_prompt": "",
                "reason": "Host database has no conversation_summaries table.",
            }

        col_rows = conn.execute("PRAGMA table_info(conversation_summaries)").fetchall()
        col_set = {str(r[1]) for r in col_rows}
        id_col = "conversation_id" if "conversation_id" in col_set else ("id" if "id" in col_set else None)
        if not id_col:
            return {
                "available": False,
                "db_path": str(db_path),
                "generated_at": utc_now_iso(),
                "host_account": host_acct.get("email"),
                "count": 0,
                "conversations": [],
                "resume_prompt": "",
                "reason": "Host conversation_summaries table is missing an identifier column.",
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
                or _read_pbtxt_title(host_gemini, conv_id)
                or "Untitled conversation"
            )
            title = _clean_prose_text(raw_title, max_len=120)
            primary_ws = _parse_primary_workspace(rec.get("workspace_uris"))
            proj_id = str(rec.get("project_id") or "").strip()
            proj_name = pid_map.get(proj_id) or (Path(primary_ws).name if primary_ws else "") or "General"
            proj_clean = _clean_prose_text(proj_name, max_len=64)
            tail = _read_transcript_tail(host_gemini, conv_id)
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
            "db_path": str(db_path),
            "generated_at": utc_now_iso(),
            "host_account": host_acct.get("email"),
            "count": 0,
            "conversations": [],
            "resume_prompt": "",
            "reason": "Unable to read Host conversation database cleanly: {}.".format(exc),
        }
    finally:
        if conn is not None:
            conn.close()

    prompt_lines = [
        "Read ~/.gemini/HANDOFF_CONTEXT.md first to recover active Host workspace context.",
        "Recent Host threads:",
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
        prompt_lines.append("1. No active Host threads were recorded yet.")

    return {
        "available": True,
        "db_path": str(db_path),
        "generated_at": utc_now_iso(),
        "host_account": host_acct.get("email"),
        "count": len(conversations),
        "conversations": conversations,
        "resume_prompt": "\n".join(prompt_lines),
    }


def write_handoff_context(
    profile_dir: Path,
    real_home: Optional[Path] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Generate a sanitized, Zero-Dashes HANDOFF_CONTEXT.md inside the sandbox .gemini dir."""
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    digest = collect_host_handoff(real_home=real_home, limit=limit)
    if not digest.get("available") and not digest.get("conversations"):
        return {
            "written": False,
            "path": None,
            "count": 0,
            "reason": digest.get("reason") or "Host handoff unavailable.",
        }

    dst_path = ensure_within_root(sandbox_home, sandbox_home / ".gemini" / "HANDOFF_CONTEXT.md")
    lines: List[str] = [
        "# Host Antigravity Handoff Context",
        "",
        "Generated at: {}".format(digest["generated_at"]),
        "Host account: {}".format(digest.get("host_account") or "unknown"),
        "Conversations indexed: {}".format(len(digest["conversations"])),
        "",
        "## Recent Host Threads",
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
        lines.append("No active conversations found in Host database.")
        lines.append("")

    lines.extend(["## Suggested Resume Prompt", "", "```text", digest["resume_prompt"], "```", ""])
    atomic_write_text(dst_path, "\n".join(lines), mode=0o600)
    return {
        "written": True,
        "path": str(dst_path),
        "count": len(digest["conversations"]),
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


def _sync_safe_tree(
    src_root: Path,
    dst_root: Path,
    sandbox_home: Path,
    host_home: Path,
) -> Dict[str, int]:
    verified_dst = ensure_within_root(sandbox_home, dst_root)
    if not src_root.exists() or not src_root.is_dir():
        return {"files_copied": 0, "redacted_secrets": 0}

    _mkdir_0700(verified_dst)
    files_copied = 0
    redacted_secrets = 0
    seen_dirs: set[Tuple[int, int]] = set()

    def _walk(curr_src: Path, curr_dst: Path, depth: int) -> None:
        nonlocal files_copied, redacted_secrets
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
                        continue
                raw_bytes = target_node.read_bytes()
            except (OSError, ValueError):
                continue
            _atomic_write_bytes(child_dst, raw_bytes, mode=dst_mode)
            files_copied += 1

    _walk(src_root, verified_dst, 0)
    return {"files_copied": files_copied, "redacted_secrets": redacted_secrets}


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


def sync_host_customizations(
    profile_dir: Path,
    real_home: Optional[Path] = None,
    include_sidecars: bool = False,
    include_handoff: bool = True,
    handoff_limit: int = 10,
) -> Dict[str, Any]:
    """Sync sanitized Host projects, plugins, agents, skills, rules, MCP JSON, and optional handoff."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
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
        write_handoff_context(profile_dir, real_home=host_home, limit=handoff_limit)
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

    host_cfg_json = host_gemini / "config" / "config.json"
    if host_cfg_json.is_file():
        parsed_cfg = _read_json_safe(host_cfg_json)
        if isinstance(parsed_cfg, dict):
            if not include_sidecars and "sidecars" in parsed_cfg:
                raw_sidecars = parsed_cfg.get("sidecars")
                if isinstance(raw_sidecars, dict):
                    stripped_sidecars += len(raw_sidecars)
                elif raw_sidecars:
                    stripped_sidecars += 1
                parsed_cfg["sidecars"] = {}
            scrubbed_cfg, hits = _scrub_structure(parsed_cfg, force_redact=False)
            redacted_total += hits
            dst_cfg = ensure_within_root(sandbox_home, sandbox_gemini / "config" / "config.json")
            atomic_write_json(dst_cfg, scrubbed_cfg, mode=0o600)
            copied.append("config/config.json")

    for rel_json in ("config/plugins.json", "config/skills.json"):
        src_rel = host_gemini / rel_json
        if not src_rel.is_file():
            continue
        parsed_rel = _read_json_safe(src_rel)
        if isinstance(parsed_rel, (dict, list)):
            scrubbed_rel, hits = _scrub_structure(parsed_rel, force_redact=False)
            redacted_total += hits
            dst_rel = ensure_within_root(sandbox_home, sandbox_gemini / rel_json)
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
    host_projects_dir = host_gemini / "config" / "projects"
    sandbox_projects_dir = ensure_within_root(sandbox_home, sandbox_gemini / "config" / "projects")
    if host_projects_dir.is_dir():
        for src_proj in sorted(host_projects_dir.glob("*.json")):
            if not src_proj.is_file():
                continue
            parsed_proj = _read_json_safe(src_proj)
            if not isinstance(parsed_proj, dict):
                continue
            if not include_sidecars and "sidecar" in parsed_proj:
                parsed_proj.pop("sidecar", None)
                stripped_sidecars += 1
            scrubbed_proj, hits = _scrub_structure(parsed_proj, force_redact=False)
            redacted_total += hits
            dst_proj = ensure_within_root(sandbox_projects_dir, sandbox_projects_dir / src_proj.name)
            atomic_write_json(dst_proj, scrubbed_proj, mode=0o600)
            projects_synced += 1
        if projects_synced > 0:
            copied.append("config/projects")

    tree_files = 0
    for tree_rel in ("config/agents", "config/skills", "config/plugins", "antigravity/skills"):
        tree_res = _sync_safe_tree(
            host_gemini / tree_rel,
            sandbox_gemini / tree_rel,
            sandbox_home,
            host_home,
        )
        redacted_total += tree_res["redacted_secrets"]
        if tree_res["files_copied"] > 0:
            tree_files += tree_res["files_copied"]
            copied.append(tree_rel)

    sync_state = inspect_profile_sync_state(profile_dir)
    return {
        "copied": copied,
        "redacted_secrets": redacted_total,
        "stripped_sidecars": stripped_sidecars,
        "projects_synced": projects_synced,
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
    """Inherit non-secret GEMINI.md, sanitized setup trees/JSON, and optional handoff from host."""
    return sync_host_customizations(
        profile_dir,
        real_home=real_home,
        include_sidecars=False,
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
