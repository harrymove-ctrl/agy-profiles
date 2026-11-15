"""Sandbox directory provisioning, symlink blocklist, cache hygiene, and MCP scrubbing."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
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
        sandbox_home / ".gemini" / "mcp_config.json",
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


def inherit_host_customizations(
    profile_dir: Path,
    real_home: Optional[Path] = None,
) -> Dict[str, Any]:
    """Inherit non-secret GEMINI.md and sanitized settings/MCP JSON from host .gemini."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
    host_gemini = host_home / ".gemini"
    copied: List[str] = []
    redacted_total = 0

    host_gemini_md = host_gemini / "GEMINI.md"
    if host_gemini_md.is_file():
        dst_md = ensure_within_root(sandbox_home, sandbox_home / ".gemini" / "GEMINI.md")
        atomic_write_text(dst_md, host_gemini_md.read_text(encoding="utf-8", errors="replace"), mode=0o600)
        copied.append("GEMINI.md")

    host_settings = host_gemini / "settings.json"
    if host_settings.is_file():
        scrubbed_settings, hits = sanitize_mcp_json_text(
            host_settings.read_text(encoding="utf-8"),
            source_path=str(host_settings),
        )
        dst_settings = ensure_within_root(sandbox_home, sandbox_home / ".gemini" / "settings.json")
        atomic_write_json(dst_settings, scrubbed_settings, mode=0o600)
        copied.append("settings.json")
        redacted_total += hits

    mcp_pairs = (
        (host_gemini / "antigravity" / "mcp_config.json", sandbox_home / ".gemini" / "antigravity" / "mcp_config.json", "antigravity/mcp_config.json"),
        (host_gemini / "mcp_config.json", sandbox_home / ".gemini" / "mcp_config.json", "mcp_config.json"),
    )
    for src_mcp, dst_mcp_raw, label in mcp_pairs:
        if not src_mcp.is_file():
            continue
        scrubbed_mcp, hits = sanitize_mcp_json_text(
            src_mcp.read_text(encoding="utf-8"),
            source_path=str(src_mcp),
        )
        dst_mcp = ensure_within_root(sandbox_home, dst_mcp_raw)
        atomic_write_json(dst_mcp, scrubbed_mcp, mode=0o600)
        copied.append(label)
        redacted_total += hits

    return {"copied": copied, "redacted_secrets": redacted_total}


def audit_profile_isolation(profile_dir: Path, manifest: ProfileManifest) -> Dict[str, Any]:
    """Inspect sandbox permissions, symlinks, and .zshenv HOME isolation on disk."""
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
    mcp_file = sandbox_home / ".gemini" / "antigravity" / "mcp_config.json"

    return {
        "permissions": {
            "profile_dir": _mode_str(profile_dir),
            "data_dir": _mode_str(data_dir),
            "sandbox_home": _mode_str(sandbox_home),
            "oauth_token_file": _mode_str(token_file),
            "mcp_config_file": _mode_str(mcp_file),
            "zshenv_file": _mode_str(zshenv_path),
        },
        "auth_mode": manifest.auth_mode,
        "link_policy": manifest.link_policy,
        "zshenv_home_locked": zshenv_locked,
        "oauth_token_present": token_file.is_file(),
        "forbidden_symlinks_present": forbidden_links_present,
        "active_symlinks": active_links,
    }
