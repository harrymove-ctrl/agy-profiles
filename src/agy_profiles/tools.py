"""Unified ToolSpec registry powering CLI, MCP server, and local web console."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from agy_profiles import __version__
from agy_profiles.config import (
    DEFAULT_ACCENTS,
    ProfileManifest,
    TargetInfo,
    atomic_write_json,
    detect_targets,
    ensure_symlink_slot_within_root,
    ensure_within_root,
    get_profile_dir,
    load_manifest,
    resolve_profiles_root,
    save_manifest,
    validate_accent,
    validate_auth_mode,
    validate_automations_mode,
    validate_link_policy,
    validate_profile_name,
    validate_target,
)
from agy_profiles.errors import ToolError
from agy_profiles.evidence import (
    EvidenceRecord,
    ObligationItem,
    ObligationReport,
    compute_sha256,
    utc_now_iso,
)
from agy_profiles.isolation import (
    ALL_MANAGED_LINKS,
    audit_profile_isolation,
    collect_handoff_from_gemini,
    collect_host_handoff,
    detect_host_account,
    detect_profile_account,
    inherit_host_customizations,
    inspect_profile_sync_state,
    pause_host_automations,
    provision_profile_dirs,
    restore_host_automations,
    sanitize_mcp_json_text,
    sync_conversation_sessions,
    sync_host_customizations,
    validate_link_relpath,
    write_host_handoff_context,
)
from agy_profiles.macos_launcher import (
    build_launcher,
    remove_launcher,
    resolve_launcher_bundle_path,
    verify_launcher_signature,
)
from agy_profiles.process_guard import (
    DATA_SUBDIR_BY_TARGET,
    LOCK_FILENAMES,
    command_matches_user_data_dir,
    inspect_host_hub_tls_health,
    inspect_host_runtime,
    inspect_locks,
    launch_profile,
    list_all_processes,
    repair_host_hub,
    repair_locks,
    stop_profile,
)
from agy_profiles.quota_guard import recover_desktop_sessions_once


@dataclass
class RuntimeContext:
    """Explicit runtime configuration passed into all tool handlers."""

    root: Path
    real_home: Optional[Path] = None
    cli_bin_path: Optional[str] = None


@dataclass
class ToolSpec:
    """Registered tool contract shared across CLI, MCP, and Web surfaces."""

    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[[RuntimeContext, Dict[str, Any]], Dict[str, Any]]
    mutates: bool = False


DISK_CACHE_TTL_SEC = 30.0
_DISK_SIZE_CACHE: Dict[str, Tuple[float, int]] = {}


def invalidate_disk_size_cache() -> None:
    """Clear cached sandbox disk-usage entries after mutating operations."""
    _DISK_SIZE_CACHE.clear()


def _dir_size_bytes_no_follow(path: Path) -> int:
    """Compute disk usage inside a directory without following symlinks (30s TTL cache)."""
    if not path.is_dir():
        return 0
    cache_key = str(path.resolve())
    now = time.monotonic()
    cached = _DISK_SIZE_CACHE.get(cache_key)
    if cached is not None and (now - cached[0]) <= DISK_CACHE_TTL_SEC:
        return cached[1]

    total = 0
    for dirpath, dirnames, filenames in os.walk(str(path), followlinks=False):
        # Prune symlinked directories so linked host directories are never traversed.
        kept_dirs: List[str] = []
        for d in dirnames:
            full_d = os.path.join(dirpath, d)
            if not os.path.islink(full_d):
                kept_dirs.append(d)
        dirnames[:] = kept_dirs
        for fname in filenames:
            full_f = os.path.join(dirpath, fname)
            if os.path.islink(full_f):
                continue
            try:
                total += os.path.getsize(full_f)
            except OSError:
                pass
    _DISK_SIZE_CACHE[cache_key] = (now, total)
    return total


def _default_launcher_dest(ctx: RuntimeContext) -> Optional[Path]:
    """Return hermetic Applications directory when ctx overrides real_home."""
    if ctx.real_home is not None:
        return ctx.real_home.expanduser() / "Applications"
    return None


def _build_profile_summary(
    root: Path,
    profile_dir: Path,
    manifest: ProfileManifest,
    ps_rows: List[Dict[str, Any]],
    launcher_dest: Optional[Path] = None,
) -> Dict[str, Any]:
    hub_rt = inspect_locks(profile_dir, "hub", ps_rows=ps_rows)
    ide_rt = inspect_locks(profile_dir, "ide", ps_rows=ps_rows)
    launchers = {
        "hub": resolve_launcher_bundle_path(manifest.name, manifest.label, "hub", dest_dir=launcher_dest).exists(),
        "ide": resolve_launcher_bundle_path(manifest.name, manifest.label, "ide", dest_dir=launcher_dest).exists(),
    }
    return {
        "manifest": manifest.to_dict(),
        "paths": {
            "profile_dir": str(profile_dir),
            "data_dir": str(profile_dir / "data"),
            "ide_data_dir": str(profile_dir / "ide-data"),
            "sandbox_home": str(profile_dir / "home"),
        },
        "runtime": {"hub": hub_rt, "ide": ide_rt},
        "launchers": launchers,
        "account": detect_profile_account(profile_dir),
        "sync_state": inspect_profile_sync_state(profile_dir),
        "disk_bytes": _dir_size_bytes_no_follow(profile_dir),
    }


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_cli_bin(ctx: RuntimeContext) -> str:
    if ctx.cli_bin_path:
        return ctx.cli_bin_path
    repo_bin = Path(__file__).resolve().parents[2] / "bin" / "agy-profiles"
    if repo_bin.is_file():
        return str(repo_bin)
    found = shutil.which("agy-profiles") or shutil.which("agyp")
    if found:
        return found
    return sys.executable


def _compute_quota_flow(
    host_account: Dict[str, Any],
    host_runtime: Dict[str, Dict[str, Any]],
    profiles: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Summarize active quota ownership and automation cron state across Host and backup profiles."""
    hub_rt = host_runtime.get("hub") or {}
    ide_rt = host_runtime.get("ide") or {}
    host_running = hub_rt.get("state") == "running" or ide_rt.get("state") == "running"
    host_schedule_count = int(hub_rt.get("schedule_count") or 0) + int(
        ide_rt.get("schedule_count") or 0
    )
    host_auto_enabled = int(host_account.get("automations_enabled") or 0)

    active_profiles: List[str] = []
    standby_profiles: List[str] = []
    for entry in profiles:
        pname = str((entry.get("manifest") or {}).get("name") or "")
        if not pname:
            continue
        sync_st = entry.get("sync_state") or {}
        rt = entry.get("runtime") or {}
        prof_enabled = int(sync_st.get("automations_enabled") or 0)
        prof_crons = int((rt.get("hub") or {}).get("schedule_count") or 0) + int(
            (rt.get("ide") or {}).get("schedule_count") or 0
        )
        if prof_enabled > 0 or prof_crons > 0:
            active_profiles.append(pname)
        else:
            standby_profiles.append(pname)

    if not profiles:
        mode = "no_profiles"
        active_owner = "host"
        dual_warn = False
        summary = "Main Antigravity is active without any backup profiles provisioned yet."
    elif active_profiles and (host_schedule_count > 0 or (host_running and host_auto_enabled > 0)):
        mode = "dual_active"
        active_owner = active_profiles[0]
        dual_warn = True
        summary = (
            "Both Main Antigravity and {} have active automations; "
            "return to Host to pause backup crons or quit Main Antigravity."
        ).format(", ".join(active_profiles))
    elif active_profiles:
        mode = "backup_active"
        active_owner = active_profiles[0]
        dual_warn = False
        summary = "Backup profile {} currently owns active quota and scheduled automations.".format(
            active_profiles[0]
        )
    else:
        mode = "host_primary"
        active_owner = "host"
        dual_warn = False
        summary = (
            "Main Antigravity owns active quota and automations while {} {} ready in paused standby."
        ).format(
            len(standby_profiles),
            "profile is" if len(standby_profiles) == 1 else "profiles are",
        )

    return {
        "mode": mode,
        "active_owner": active_owner,
        "active_profiles": active_profiles,
        "standby_profiles": standby_profiles,
        "host_running": host_running,
        "host_schedule_count": host_schedule_count,
        "dual_automations_warning": dual_warn,
        "summary": summary,
    }


def _handle_profile_list(ctx: RuntimeContext, _params: Dict[str, Any]) -> Dict[str, Any]:
    root = ctx.root
    targets = detect_targets()
    ps_rows = list_all_processes()
    profiles: List[Dict[str, Any]] = []
    if root.is_dir():
        for entry in sorted(root.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_dir() or entry.is_symlink():
                continue
            manifest_file = entry / "profile.json"
            if not manifest_file.is_file():
                continue
            try:
                _, manifest = load_manifest(root, entry.name)
            except ToolError:
                continue
            profiles.append(
                _build_profile_summary(
                    root,
                    entry,
                    manifest,
                    ps_rows,
                    launcher_dest=_default_launcher_dest(ctx),
                )
            )
    host_account = detect_host_account(real_home=ctx.real_home)
    host_runtime = inspect_host_runtime(
        real_home=ctx.real_home,
        targets=targets,
        ps_rows=ps_rows,
    )
    flow = _compute_quota_flow(host_account, host_runtime, profiles)
    return {
        "root": str(root),
        "default_root": str(resolve_profiles_root()),
        "host_account": host_account,
        "host_runtime": host_runtime,
        "flow": flow,
        "targets": {k: v.to_dict() for k, v in targets.items()},
        "profiles": profiles,
    }


def _parse_handoff_limit(params: Dict[str, Any]) -> int:
    raw = params.get("limit", 10)
    if isinstance(raw, bool):
        raise ToolError(
            "invalid_argument",
            "Handoff limit must be an integer between 1 and 30.",
            "Pass an integer limit between 1 and 30.",
        )
    try:
        val = int(raw)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            "invalid_argument",
            "Handoff limit must be an integer between 1 and 30.",
            "Pass an integer limit between 1 and 30.",
        ) from exc
    if val < 1 or val > 30:
        raise ToolError(
            "invalid_argument",
            "Handoff limit {} is out of range (1 to 30).".format(val),
            "Pass an integer limit between 1 and 30.",
        )
    return val


def _resolve_handoff_source(
    ctx: RuntimeContext,
    raw_source: Optional[str],
) -> Tuple[str, Optional[Path], Optional[str]]:
    clean = str(raw_source or "host").strip() or "host"
    if clean.lower() == "host":
        return "host", None, None
    src_name = validate_profile_name(clean)
    src_dir, src_manifest = load_manifest(ctx.root, src_name)
    src_gemini = ensure_within_root(src_dir, src_dir / "home" / ".gemini")
    acct = detect_profile_account(src_dir).get("email") or src_manifest.label
    return src_manifest.name, src_gemini, acct


def _parse_session_limit(params: Dict[str, Any]) -> int:
    raw = params.get("session_limit", 25)
    if isinstance(raw, bool):
        raise ToolError(
            "invalid_argument",
            "Session limit must be an integer between 1 and 100.",
            "Pass an integer session_limit between 1 and 100.",
        )
    try:
        val = int(raw)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            "invalid_argument",
            "Session limit must be an integer between 1 and 100.",
            "Pass an integer session_limit between 1 and 100.",
        ) from exc
    if val < 1 or val > 100:
        raise ToolError(
            "invalid_argument",
            "Session limit {} is out of range (1 to 100).".format(val),
            "Pass an integer session_limit between 1 and 100.",
        )
    return val


def _handle_profile_sync(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    include_sidecars = bool(params.get("include_sidecars", False))
    raw_mode = params.get("automations_mode")
    automations_mode = validate_automations_mode(str(raw_mode)) if raw_mode is not None else None
    include_handoff = bool(params.get("include_handoff", True))
    include_sessions = bool(params.get("include_sessions", True))
    turbo_bypass = bool(params.get("turbo_bypass", True))
    session_limit = _parse_session_limit(params)
    restart = bool(params.get("restart", False))
    limit = _parse_handoff_limit(params)
    source_name, source_gemini, source_account = _resolve_handoff_source(ctx, params.get("from_source"))

    profile_dir, manifest = load_manifest(ctx.root, name)
    stop_res: Optional[Dict[str, Any]] = None
    launch_res: Optional[Dict[str, Any]] = None
    if restart:
        stop_res = stop_profile(ctx.root, profile_dir, target="all")

    provision_profile_dirs(ctx.root, manifest, real_home=ctx.real_home)
    sync_res = sync_host_customizations(
        profile_dir,
        real_home=ctx.real_home,
        include_sidecars=include_sidecars,
        automations_mode=automations_mode,
        include_handoff=include_handoff,
        handoff_limit=limit,
        handoff_source_gemini=source_gemini,
        handoff_source_account=source_account,
        handoff_source_name=source_name,
        include_sessions=include_sessions,
        session_limit=session_limit,
        turbo_bypass=turbo_bypass,
    )

    if restart:
        launch_res = launch_profile(
            ctx.root,
            profile_dir,
            manifest,
            target=manifest.default_target,
            real_home=ctx.real_home,
        )

    ps_rows = list_all_processes()
    summary = _build_profile_summary(
        ctx.root,
        profile_dir,
        manifest,
        ps_rows,
        launcher_dest=_default_launcher_dest(ctx),
    )
    ev = EvidenceRecord(
        operation="profile_sync",
        authority="filesystem",
        confidence="observed",
        summary=(
            "Synced {} projects, {} automations ({} active, mode={}), {} plugins, {} agents into '{}' "
            "(redacted {}, pruned {}, stripped {} sidecars)."
        ).format(
            sync_res["projects_synced"],
            sync_res["automations_synced"],
            sync_res["automations_enabled"],
            sync_res["automations_mode"],
            sync_res["plugins_synced"],
            sync_res["agents_synced"],
            manifest.name,
            sync_res["redacted_secrets"],
            sync_res["pruned_entries"],
            sync_res["stripped_sidecars"],
        ),
        facts={
            "profile": manifest.name,
            "restarted": restart,
            "automations_mode": sync_res["automations_mode"],
            "automations_synced": sync_res["automations_synced"],
            "automations_enabled": sync_res["automations_enabled"],
            "projects_synced": sync_res["projects_synced"],
            "pruned_entries": sync_res["pruned_entries"],
            "plugins_synced": sync_res["plugins_synced"],
            "agents_synced": sync_res["agents_synced"],
            "skills_synced": sync_res["skills_synced"],
            "redacted_secrets": sync_res["redacted_secrets"],
            "stripped_sidecars": sync_res["stripped_sidecars"],
            "handoff_source": source_name,
            "handoff_written": bool(sync_res["handoff"].get("written")),
        },
        limitations=[],
    )
    summary["sync"] = sync_res
    summary["restarted"] = restart
    summary["stop"] = stop_res
    summary["launch"] = launch_res
    summary["evidence"] = ev.to_dict()
    return summary


def _handle_host_handoff(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    limit = _parse_handoff_limit(params)
    source_name, source_gemini, source_account = _resolve_handoff_source(ctx, params.get("source"))
    host_account = detect_host_account(real_home=ctx.real_home)
    if source_gemini is not None:
        digest = collect_handoff_from_gemini(
            source_gemini,
            source_account,
            source_name=source_name,
            limit=limit,
        )
    else:
        digest = collect_host_handoff(real_home=ctx.real_home, limit=limit)
    ev = EvidenceRecord(
        operation="host_handoff",
        authority="filesystem",
        confidence="observed" if digest.get("available") else "inferred",
        summary="Read {} {} conversations read-only for cross-account handoff.".format(
            digest["count"],
            "Host" if source_name == "host" else source_name,
        ),
        facts={
            "available": digest["available"],
            "source": source_name,
            "count": digest["count"],
            "host_account": host_account.get("email"),
            "source_account": digest.get("source_account"),
        },
        limitations=([] if digest.get("available") else [str(digest.get("reason") or "Conversation database unavailable.")]),
    )
    digest["host_account_details"] = host_account
    digest["evidence"] = ev.to_dict()
    return digest


def _handle_profile_inspect(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = str(params.get("name") or "")
    profile_dir, manifest = load_manifest(ctx.root, name)
    ps_rows = list_all_processes()
    summary = _build_profile_summary(
        ctx.root,
        profile_dir,
        manifest,
        ps_rows,
        launcher_dest=_default_launcher_dest(ctx),
    )
    iso = audit_profile_isolation(profile_dir, manifest)
    ev = EvidenceRecord(
        operation="profile_inspect",
        authority="filesystem",
        confidence="observed",
        summary="Inspected sandbox profile {!r} permissions, symlinks, and runtime locks.".format(manifest.name),
        facts={
            "profile": manifest.name,
            "account_email": summary["account"]["email"],
            "permissions": iso["permissions"],
            "zshenv_home_locked": iso["zshenv_home_locked"],
            "forbidden_symlinks_present": iso["forbidden_symlinks_present"],
            "sync_state": iso["sync_state"],
            "runtime_hub_state": summary["runtime"]["hub"]["state"],
            "runtime_ide_state": summary["runtime"]["ide"]["state"],
        },
        limitations=[
            "Filesystem audit reflects local disk and /bin/ps snapshot at inspection time.",
            "System Keychain entries are opaque when auth_mode is set to system-keychain.",
        ],
    )
    summary["isolation"] = iso
    summary["evidence"] = ev.to_dict()
    return summary


def _handle_profile_create(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    profile_dir = get_profile_dir(ctx.root, name)
    if (profile_dir / "profile.json").exists():
        raise ToolError(
            "profile_exists",
            "Profile {!r} already exists in {!r}.".format(name, str(ctx.root)),
            "Choose a new name or run 'agy-profiles inspect {}'.",
            {"name": name},
            http_status=409,
        )

    label = str(params.get("label") or name).strip() or name
    raw_accent = params.get("accent")
    if not raw_accent:
        idx = sum(ord(c) for c in name) % len(DEFAULT_ACCENTS)
        accent = DEFAULT_ACCENTS[idx]
    else:
        accent = validate_accent(str(raw_accent))

    default_target = validate_target(str(params.get("default_target") or "hub"))
    link_policy = validate_link_policy(str(params.get("link_policy") or "minimal"))
    auth_mode = validate_auth_mode(str(params.get("auth_mode") or "isolated-file"))
    keep_bg = bool(params.get("keep_background_alive", True))
    inherit_cfg = bool(params.get("inherit_config", False))

    targets = detect_targets()
    versions = {k: t.version for k, t in targets.items() if t.installed and t.version}

    manifest = ProfileManifest(
        schema_version=1,
        name=name,
        label=label,
        accent=accent,
        default_target=default_target,
        link_policy=link_policy,
        auth_mode=auth_mode,
        keep_background_alive=keep_bg,
        last_host_versions=versions,
    )
    provision_info = provision_profile_dirs(ctx.root, manifest, real_home=ctx.real_home)
    inherit_info: Dict[str, Any] = {"copied": [], "redacted_secrets": 0}
    try:
        if inherit_cfg:
            inherit_info = inherit_host_customizations(profile_dir, real_home=ctx.real_home)
        save_manifest(ctx.root, profile_dir, manifest)
    except BaseException:
        # Roll back partial creation if fail-closed host config inheritance rejects malformed JSON.
        _safe_unlink_and_rmtree(ctx.root, profile_dir)
        raise

    inspected = _handle_profile_inspect(ctx, {"name": name})
    inspected["provisioned"] = provision_info
    inspected["inherited"] = inherit_info
    return inspected


def _handle_profile_update(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    profile_dir, manifest = load_manifest(ctx.root, name)
    old_label = manifest.label

    if "label" in params and params["label"] is not None:
        cleaned_label = str(params["label"]).strip()
        if not cleaned_label:
            raise ToolError(
                "invalid_argument",
                "Profile label cannot be empty.",
                "Provide a non-empty display label.",
            )
        manifest.label = cleaned_label
    if "accent" in params and params["accent"] is not None:
        manifest.accent = validate_accent(str(params["accent"]))
    if "default_target" in params and params["default_target"] is not None:
        manifest.default_target = validate_target(str(params["default_target"]))
    if "link_policy" in params and params["link_policy"] is not None:
        manifest.link_policy = validate_link_policy(str(params["link_policy"]))
    if "auth_mode" in params and params["auth_mode"] is not None:
        manifest.auth_mode = validate_auth_mode(str(params["auth_mode"]))
    if "keep_background_alive" in params and params["keep_background_alive"] is not None:
        manifest.keep_background_alive = bool(params["keep_background_alive"])

    provision_profile_dirs(ctx.root, manifest, real_home=ctx.real_home)
    save_manifest(ctx.root, profile_dir, manifest)

    if manifest.label != old_label:
        launcher_dest = _default_launcher_dest(ctx)
        existing_targets = [
            tgt
            for tgt in ("hub", "ide")
            if resolve_launcher_bundle_path(name, old_label, tgt, dest_dir=launcher_dest).exists()
        ]
        cli_bin = _resolve_cli_bin(ctx)
        for tgt in existing_targets:
            remove_launcher(name, old_label, tgt, dest_dir=launcher_dest)
            build_launcher(
                profile_name=name,
                label=manifest.label,
                target=tgt,
                cli_bin_path=cli_bin,
                dest_dir=launcher_dest,
                root=ctx.root,
            )

    return _handle_profile_inspect(ctx, {"name": name})


def _handle_profile_launch(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    profile_dir, manifest = load_manifest(ctx.root, name)
    target = params.get("target")
    workspace = params.get("workspace")
    return launch_profile(
        ctx.root,
        profile_dir,
        manifest,
        target=str(target) if target is not None else None,
        workspace=str(workspace) if workspace is not None else None,
        real_home=ctx.real_home,
    )


def _handle_profile_stop(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    profile_dir, _ = load_manifest(ctx.root, name)
    target = str(params.get("target") or "all")
    if target not in ("hub", "ide", "all"):
        raise ToolError(
            "invalid_argument",
            "Invalid stop target {!r}.".format(target),
            "Use 'hub', 'ide', or 'all'.",
        )
    timeout_sec = float(params.get("timeout_sec") or 5.0)
    res = stop_profile(ctx.root, profile_dir, target=target, timeout_sec=timeout_sec)
    res["profile"] = name
    return res


def _handle_profile_repair(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    raw_name = str(params.get("name") or "").strip()
    if raw_name.lower() == "host":
        do_launch = bool(params.get("launch", True))
        return repair_host_hub(real_home=ctx.real_home, launch=do_launch)
    name = validate_profile_name(raw_name)
    profile_dir, manifest = load_manifest(ctx.root, name)
    target = params.get("target")
    locks = repair_locks(
        ctx.root,
        profile_dir,
        target=str(target) if target is not None else None,
    )
    provision = provision_profile_dirs(ctx.root, manifest, real_home=ctx.real_home)
    return {
        "profile": name,
        "locks_removed": locks["removed"],
        "provisioned": provision,
    }


def _copy_tree_excluding_transient(src_root: Path, dst_root: Path) -> None:
    """Copy a profile data directory cleanly while skipping symlinks and transient locks."""
    if not src_root.is_dir():
        return
    skip_names = set(LOCK_FILENAMES)
    for dirpath, dirnames, filenames in os.walk(str(src_root), followlinks=False):
        rel = os.path.relpath(dirpath, str(src_root))
        dst_dir = dst_root if rel == "." else (dst_root / rel)
        dst_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(dst_dir), 0o700)

        kept_dirs: List[str] = []
        for d in dirnames:
            full_d = os.path.join(dirpath, d)
            if os.path.islink(full_d) or d in skip_names:
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for fname in filenames:
            if fname in skip_names or fname.endswith(".tmp"):
                continue
            full_f = os.path.join(dirpath, fname)
            if os.path.islink(full_f):
                continue
            dst_f = dst_dir / fname
            shutil.copy2(full_f, str(dst_f))
            if fname in ("jetski-standalone-oauth-token", "credential-user-scope") or fname.endswith(".json"):
                os.chmod(str(dst_f), 0o600)


def _handle_profile_clone(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    src_name = validate_profile_name(str(params.get("source") or ""))
    dst_name = validate_profile_name(str(params.get("target") or ""))
    if src_name == dst_name:
        raise ToolError(
            "invalid_argument",
            "Source and destination profile names must differ.",
            "Choose a distinct target profile name.",
        )

    src_dir, src_manifest = load_manifest(ctx.root, src_name)
    ps_rows = list_all_processes()
    for tgt in ("hub", "ide"):
        state = inspect_locks(src_dir, tgt, ps_rows=ps_rows)
        if state["state"] == "running":
            raise ToolError(
                "profile_running",
                "Cannot clone source profile {!r} while {} is running (PIDs: {}).".format(
                    src_name, tgt, state["pids"]
                ),
                "Stop the source profile before cloning to keep state consistent.",
                {"source": src_name, "target": tgt, "pids": state["pids"]},
            )

    dst_dir = get_profile_dir(ctx.root, dst_name)
    if (dst_dir / "profile.json").exists():
        raise ToolError(
            "profile_exists",
            "Target profile {!r} already exists.".format(dst_name),
            "Choose an unused target profile name.",
            {"target": dst_name},
            http_status=409,
        )

    dst_label = str(params.get("label") or "{} Copy".format(src_manifest.label)).strip() or dst_name
    dst_manifest = ProfileManifest(
        schema_version=1,
        name=dst_name,
        label=dst_label,
        accent=src_manifest.accent,
        default_target=src_manifest.default_target,
        link_policy=src_manifest.link_policy,
        auth_mode=src_manifest.auth_mode,
        keep_background_alive=src_manifest.keep_background_alive,
        last_host_versions=dict(src_manifest.last_host_versions),
    )

    fresh_auth = bool(params.get("fresh_auth", False))

    try:
        provision_profile_dirs(ctx.root, dst_manifest, real_home=ctx.real_home)
        for sub in ("data", "ide-data"):
            _copy_tree_excluding_transient(src_dir / sub, dst_dir / sub)
        _copy_tree_excluding_transient(src_dir / "home" / ".gemini", dst_dir / "home" / ".gemini")
        _copy_tree_excluding_transient(
            src_dir / "home" / "Library" / "Application Support" / "antigravity",
            dst_dir / "home" / "Library" / "Application Support" / "antigravity",
        )
        # Strip source installation_id and installation_uuid fingerprints so Antigravity Mobile
        # treats the cloned profile as a distinct machine instance without handshake collisions.
        for id_rel in (
            Path("home") / ".gemini" / "installation_id",
            Path("home") / ".gemini" / "antigravity" / "installation_id",
            Path("home") / ".gemini" / "antigravity-cli" / "installation_id",
        ):
            id_path = ensure_within_root(dst_dir, dst_dir / id_rel)
            if id_path.is_file() or id_path.is_symlink():
                id_path.unlink()
        for pbtxt_rel in (
            Path("home") / ".gemini" / "antigravity" / "antigravity_state.pbtxt",
            Path("home") / ".gemini" / "antigravity-cli" / "jetski_state.pbtxt",
        ):
            pb_path = ensure_within_root(dst_dir, dst_dir / pbtxt_rel)
            if pb_path.is_file() and not pb_path.is_symlink():
                kept_lines = [
                    ln
                    for ln in pb_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if not ln.lstrip().startswith("installation_uuid:")
                ]
                pb_path.write_text("\n".join(kept_lines) + ("\n" if kept_lines else ""), encoding="utf-8")
                os.chmod(str(pb_path), 0o600)
        if fresh_auth:
            for cred_rel in (
                Path("home") / ".gemini" / "jetski-standalone-oauth-token",
                Path("home") / ".gemini" / "google_accounts.json",
                Path("home") / "Library" / "Application Support" / "antigravity" / "credential-user-scope",
            ):
                cred_path = ensure_within_root(dst_dir, dst_dir / cred_rel)
                if cred_path.is_file() or cred_path.is_symlink():
                    cred_path.unlink()
            for app_dir_name in ("data", "ide-data"):
                storage_file = ensure_within_root(dst_dir, dst_dir / app_dir_name / "app_storage.json")
                if storage_file.is_file():
                    try:
                        parsed_st = json.loads(storage_file.read_text(encoding="utf-8", errors="replace"))
                        if isinstance(parsed_st, dict):
                            cleaned_st = {
                                k: v
                                for k, v in parsed_st.items()
                                if k != "agy.onboarding.lastLoginUsername" and not str(k).endswith("lastLoginUsername")
                            }
                            atomic_write_json(storage_file, cleaned_st, mode=0o600)
                    except (OSError, ValueError):
                        pass
                for transient_auth in ("Cookies", "Cookies-journal", "Local Storage", "Session Storage"):
                    tpath = ensure_within_root(dst_dir, dst_dir / app_dir_name / transient_auth)
                    if tpath.is_dir() and not tpath.is_symlink():
                        shutil.rmtree(str(tpath))
                    elif tpath.is_file() or tpath.is_symlink():
                        tpath.unlink()
        # Rewrite sandbox .zshenv and policy symlinks cleanly for the cloned home directory.
        provision_profile_dirs(ctx.root, dst_manifest, real_home=ctx.real_home)
        save_manifest(ctx.root, dst_dir, dst_manifest)
    except BaseException:
        _safe_unlink_and_rmtree(ctx.root, dst_dir)
        raise

    inspected = _handle_profile_inspect(ctx, {"name": dst_name})
    inspected["fresh_auth"] = fresh_auth
    return inspected


def _retarget_internal_symlinks(src_dir: Path, dst_dir: Path) -> int:
    """Rewrite internal absolute symlinks pointing into src_dir to point into dst_dir."""
    dst_resolved = str(dst_dir.resolve())
    src_resolved = str(src_dir.parent.resolve() / src_dir.name)
    pairs = [(src_resolved, dst_resolved)]
    if str(src_dir) != src_resolved:
        pairs.append((str(src_dir), str(dst_dir)))

    count = 0
    for dirpath, dirnames, filenames in os.walk(str(dst_dir), followlinks=False):
        for entry in list(dirnames) + list(filenames):
            full_path = os.path.join(dirpath, entry)
            if not os.path.islink(full_path):
                continue
            raw_target = os.readlink(full_path)
            new_target = raw_target
            for old_prefix, new_prefix in pairs:
                if raw_target == old_prefix:
                    new_target = new_prefix
                    break
                if raw_target.startswith(old_prefix + os.sep):
                    new_target = new_prefix + raw_target[len(old_prefix):]
                    break
            if new_target != raw_target:
                os.unlink(full_path)
                os.symlink(new_target, full_path)
                count += 1
    return count


def _handle_profile_rename(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    src_name = validate_profile_name(str(params.get("source") or ""))
    dst_name = validate_profile_name(str(params.get("target") or ""))
    if src_name == dst_name:
        raise ToolError(
            "invalid_argument",
            "Source and target profile names must differ.",
            "Choose a distinct target profile name.",
        )

    src_dir, src_manifest = load_manifest(ctx.root, src_name)
    dst_dir = get_profile_dir(ctx.root, dst_name)
    if dst_dir.exists() or dst_dir.is_symlink():
        raise ToolError(
            "profile_exists",
            "Target profile {!r} already exists.".format(dst_name),
            "Choose an unused target profile name.",
            {"target": dst_name},
            http_status=409,
        )

    restart = bool(params.get("restart", False))
    ps_rows = list_all_processes()
    running_targets: List[str] = []
    for tgt in ("hub", "ide"):
        state = inspect_locks(src_dir, tgt, ps_rows=ps_rows)
        if state["state"] == "running":
            running_targets.append(tgt)

    if running_targets and not restart:
        raise ToolError(
            "profile_running",
            "Cannot rename profile {!r} while {} is running.".format(
                src_name, ", ".join(running_targets)
            ),
            "Stop the profile first or pass restart=true (--restart).",
            {"source": src_name, "running_targets": running_targets},
        )
    if running_targets and restart:
        stop_profile(ctx.root, src_dir, target="all")

    launcher_dest = _default_launcher_dest(ctx)
    had_launchers = [
        tgt
        for tgt in ("hub", "ide")
        if resolve_launcher_bundle_path(src_name, src_manifest.label, tgt, dest_dir=launcher_dest).exists()
    ]
    for tgt in ("hub", "ide"):
        remove_launcher(src_name, src_manifest.label, tgt, dest_dir=launcher_dest)

    os.replace(str(src_dir), str(dst_dir))
    _retarget_internal_symlinks(src_dir, dst_dir)

    for run_file in (dst_dir / "run.hub.json", dst_dir / "run.ide.json"):
        if run_file.exists():
            run_file.unlink()
    for tgt in ("hub", "ide"):
        repair_locks(ctx.root, dst_dir, target=tgt, allow_live_noop=True)

    raw_label = params.get("label")
    if raw_label is not None and str(raw_label).strip():
        new_label = str(raw_label).strip()
    else:
        acct_email = detect_profile_account(dst_dir).get("email")
        if acct_email and src_manifest.label.strip().lower() in (
            src_name.lower(),
            src_name.replace("-", " ").lower(),
        ):
            new_label = str(acct_email)
        else:
            new_label = src_manifest.label

    src_manifest.name = dst_name
    src_manifest.label = new_label
    provision_profile_dirs(ctx.root, src_manifest, real_home=ctx.real_home)
    save_manifest(ctx.root, dst_dir, src_manifest)

    cli_bin = _resolve_cli_bin(ctx)
    for tgt in had_launchers:
        build_launcher(
            profile_name=dst_name,
            label=new_label,
            target=tgt,
            cli_bin_path=cli_bin,
            dest_dir=launcher_dest,
            root=ctx.root,
        )

    if restart:
        for tgt in (running_targets or [src_manifest.default_target]):
            launch_profile(
                ctx.root,
                dst_dir,
                src_manifest,
                target=tgt,
                real_home=ctx.real_home,
            )

    inspected = _handle_profile_inspect(ctx, {"name": dst_name})
    inspected["renamed_from"] = src_name
    inspected["restarted"] = restart
    return inspected


def _safe_unlink_and_rmtree(root: Path, profile_dir: Path) -> None:
    verified = ensure_within_root(root, profile_dir)
    if not verified.exists():
        return
    sandbox_home = verified / "home"
    if sandbox_home.is_dir():
        for rel in ALL_MANAGED_LINKS:
            slot = ensure_symlink_slot_within_root(sandbox_home, sandbox_home / rel)
            if slot.is_symlink():
                slot.unlink()
    shutil.rmtree(str(verified))


def _handle_profile_delete(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    if not bool(params.get("confirm", False)):
        raise ToolError(
            "invalid_argument",
            "Profile deletion requires explicit confirmation.",
            "Pass confirm=true (or --yes on the CLI).",
        )
    profile_dir, manifest = load_manifest(ctx.root, name)
    force_stop = bool(params.get("force_stop", False))
    ps_rows = list_all_processes()
    running_targets: List[str] = []
    for tgt in ("hub", "ide"):
        if inspect_locks(profile_dir, tgt, ps_rows=ps_rows)["state"] == "running":
            running_targets.append(tgt)

    if running_targets:
        if not force_stop:
            raise ToolError(
                "profile_running",
                "Cannot delete profile {!r} while {} is running.".format(name, ", ".join(running_targets)),
                "Stop the profile first or pass force_stop=true.",
                {"name": name, "running_targets": running_targets},
            )
        stop_profile(ctx.root, profile_dir, target="all")

    launcher_dest = _default_launcher_dest(ctx)
    removed_launchers: List[str] = []
    for tgt in ("hub", "ide"):
        res = remove_launcher(name, manifest.label, tgt, dest_dir=launcher_dest)
        if res["removed"]:
            removed_launchers.append(res["bundle_path"])

    _safe_unlink_and_rmtree(ctx.root, profile_dir)
    return {
        "deleted": True,
        "profile": name,
        "removed_launchers": removed_launchers,
    }


def _handle_launcher_build(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    _, manifest = load_manifest(ctx.root, name)
    target = validate_target(str(params.get("target") or manifest.default_target))
    dest = params.get("dest")
    dest_path = Path(str(dest)).expanduser() if dest else _default_launcher_dest(ctx)
    cli_bin = _resolve_cli_bin(ctx)
    return build_launcher(
        profile_name=name,
        label=manifest.label,
        target=target,
        cli_bin_path=cli_bin,
        dest_dir=dest_path,
        root=ctx.root,
    )


def _handle_launcher_remove(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = validate_profile_name(str(params.get("name") or ""))
    _, manifest = load_manifest(ctx.root, name)
    target = validate_target(str(params.get("target") or manifest.default_target))
    dest = params.get("dest")
    dest_path = Path(str(dest)).expanduser() if dest else _default_launcher_dest(ctx)
    return remove_launcher(name, manifest.label, target, dest_dir=dest_path)


def _inspect_git_dirty(workspace: Optional[str]) -> Dict[str, Any]:
    """Check git working tree cleanliness read-only without blocking or failing."""
    if not workspace:
        return {"workspace": None, "is_git": False, "dirty": False, "modified_count": 0}
    ws_path = Path(workspace).expanduser()
    if not ws_path.is_dir() or not shutil.which("git"):
        return {"workspace": str(ws_path), "is_git": False, "dirty": False, "modified_count": 0}
    try:
        proc = subprocess.run(
            ["git", "-C", str(ws_path), "status", "--porcelain", "--untracked-files=normal"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"workspace": str(ws_path), "is_git": False, "dirty": False, "modified_count": 0}
    if proc.returncode != 0:
        return {"workspace": str(ws_path), "is_git": False, "dirty": False, "modified_count": 0}
    changed = [line for line in proc.stdout.splitlines() if line.strip()]
    return {
        "workspace": str(ws_path),
        "is_git": True,
        "dirty": len(changed) > 0,
        "modified_count": len(changed),
    }


def _copy_prompt_to_clipboard(prompt_text: str, copy_prompt: bool) -> bool:
    if not (copy_prompt and prompt_text and sys.platform == "darwin" and Path("/usr/bin/pbcopy").exists()):
        return False
    try:
        cp_proc = subprocess.run(
            ["/usr/bin/pbcopy"],
            input=prompt_text,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
        return cp_proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _handle_switch_to_host(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    raw_from = str(params.get("from_source") or "").strip()
    if not raw_from or raw_from.lower() == "host":
        raise ToolError(
            "invalid_argument",
            "Returning quota to Host requires a backup profile in from_source.",
            "Pass --from <profile> when switching back to host.",
        )
    src_name = validate_profile_name(raw_from)
    src_dir, src_manifest = load_manifest(ctx.root, src_name)
    copy_prompt = bool(params.get("copy_prompt", False))
    launch = bool(params.get("launch", True))
    include_sessions = bool(params.get("include_sessions", True))
    session_limit = _parse_session_limit(params)
    limit = _parse_handoff_limit(params)
    explicit_ws = str(params.get("workspace") or "").strip() or None

    handoff_digest = _handle_host_handoff(ctx, {"limit": limit, "source": src_manifest.name})
    check_ws = explicit_ws
    if not check_ws:
        for item in handoff_digest.get("conversations") or []:
            cand_ws = str(item.get("workspace") or "").strip()
            if cand_ws and Path(cand_ws).is_dir():
                check_ws = cand_ws
                break
    git_status = _inspect_git_dirty(check_ws)

    ps_before = list_all_processes()
    running_targets = [
        tgt
        for tgt in ("hub", "ide")
        if inspect_locks(src_dir, tgt, ps_rows=ps_before)["state"] == "running"
    ]
    stop_res: Optional[Dict[str, Any]] = None
    relaunch_results: List[Dict[str, Any]] = []
    if launch and running_targets:
        stop_res = stop_profile(ctx.root, src_dir, target="all")

    src_gemini_dir = ensure_within_root(src_dir, src_dir / "home" / ".gemini")
    src_acct = detect_profile_account(src_dir).get("email") or src_manifest.label
    handoff_written = write_host_handoff_context(
        src_gemini_dir,
        src_acct,
        src_manifest.name,
        real_home=ctx.real_home,
        limit=limit,
    )

    host_home = (ctx.real_home if ctx.real_home is not None else Path.home()).resolve()
    host_rt_now = inspect_host_runtime(real_home=ctx.real_home, ps_rows=ps_before)
    host_now_running = (
        host_rt_now["hub"]["state"] == "running" or host_rt_now["ide"]["state"] == "running"
    )
    sessions_returned: Dict[str, Any] = {
        "synced_sessions": 0,
        "skipped_up_to_date": 0,
        "total_dst_sessions": 0,
        "worktrees_linked": 0,
        "proto_rebuilt": False,
    }
    if include_sessions:
        sessions_returned = sync_conversation_sessions(
            src_gemini=src_gemini_dir,
            dst_gemini=ensure_within_root(host_home, host_home / ".gemini"),
            dst_root_bound=host_home,
            host_home=host_home,
            limit=session_limit,
            skip_locked_on_dst=True,
            rebuild_proto=(not host_now_running),
        )

    provision_profile_dirs(ctx.root, src_manifest, real_home=ctx.real_home)
    sync_res = sync_host_customizations(
        src_dir,
        real_home=ctx.real_home,
        automations_mode="paused",
        include_handoff=False,
        include_sessions=False,
    )
    host_restored = restore_host_automations(real_home=ctx.real_home)

    host_repair_res: Optional[Dict[str, Any]] = None
    host_hub_rt = inspect_host_runtime(real_home=ctx.real_home).get("hub", {})
    host_tls = inspect_host_hub_tls_health(real_home=ctx.real_home, host_hub_runtime=host_hub_rt)
    if launch and (host_hub_rt.get("state") != "running" or host_tls.get("tls_broken")):
        host_repair_res = repair_host_hub(real_home=ctx.real_home, launch=True)

    if launch and running_targets:
        for tgt in running_targets:
            relaunch_results.append(
                launch_profile(
                    ctx.root,
                    src_dir,
                    src_manifest,
                    target=tgt,
                    real_home=ctx.real_home,
                )
            )

    prompt_text = str(handoff_digest.get("resume_prompt") or "")
    prompt_copied = _copy_prompt_to_clipboard(prompt_text, copy_prompt)

    overview = _handle_profile_list(ctx, {})
    backup_summary = next(
        (p for p in overview["profiles"] if p["manifest"]["name"] == src_manifest.name),
        None,
    )
    ev = EvidenceRecord(
        operation="profile_switch_host",
        authority="filesystem",
        confidence="observed",
        summary=(
            "Returned quota from '{}' to Host ({} conversations indexed, backup automations paused)."
        ).format(src_manifest.name, handoff_written.get("count", 0)),
        facts={
            "target_profile": "host",
            "from_source": src_manifest.name,
            "handoff_written": bool(handoff_written.get("written")),
            "handoff_count": int(handoff_written.get("count") or 0),
            "backup_automations_enabled": int(sync_res.get("automations_enabled") or 0),
            "git_dirty": git_status["dirty"],
            "git_modified_count": git_status["modified_count"],
            "prompt_copied": prompt_copied,
        },
        limitations=[],
    )
    return {
        "target_profile": "host",
        "from_source": src_manifest.name,
        "handoff": handoff_written,
        "sessions": sessions_returned,
        "sync": sync_res,
        "stop": stop_res,
        "backup_profile": backup_summary,
        "host_account": overview["host_account"],
        "host_runtime": overview["host_runtime"],
        "flow": overview["flow"],
        "switch": {
            "target": "hub",
            "automations_mode": "paused",
            "from_source": src_manifest.name,
            "git_status": git_status,
            "prompt_copied": prompt_copied,
            "resume_prompt": prompt_text,
            "relaunched_backup": relaunch_results,
            "host_repaired": host_repair_res,
            "host_automations_restored": host_restored,
        },
        "evidence": ev.to_dict(),
    }


def _handle_profile_switch(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    raw_name = str(params.get("name") or "").strip()
    if raw_name.lower() == "host":
        return _handle_switch_to_host(ctx, params)
    name = validate_profile_name(raw_name)
    profile_dir, manifest = load_manifest(ctx.root, name)
    mode = validate_automations_mode(str(params.get("automations_mode") or "active"))
    chosen_target = validate_target(str(params.get("target") or manifest.default_target))
    raw_from = str(params.get("from_source") or "host").strip() or "host"
    from_source = "host" if raw_from == name else raw_from
    copy_prompt = bool(params.get("copy_prompt", False))
    launch = bool(params.get("launch", True))
    include_sessions = bool(params.get("include_sessions", True))
    session_limit = _parse_session_limit(params)
    limit = _parse_handoff_limit(params)
    explicit_ws = str(params.get("workspace") or "").strip() or None

    handoff_digest = _handle_host_handoff(ctx, {"limit": limit, "source": from_source})
    check_ws = explicit_ws
    if not check_ws:
        for item in handoff_digest.get("conversations") or []:
            cand_ws = str(item.get("workspace") or "").strip()
            if cand_ws and Path(cand_ws).is_dir():
                check_ws = cand_ws
                break
    git_status = _inspect_git_dirty(check_ws)

    source_name, source_gemini, source_account = _resolve_handoff_source(ctx, from_source)
    stop_res: Optional[Dict[str, Any]] = None
    launch_res: Optional[Dict[str, Any]] = None
    if launch:
        stop_res = stop_profile(ctx.root, profile_dir, target="all")

    host_paused: Dict[str, Any] = {"paused_count": 0, "paused_ids": []}
    if mode == "active":
        host_paused = pause_host_automations(real_home=ctx.real_home)

    provision_profile_dirs(ctx.root, manifest, real_home=ctx.real_home)
    sync_res = sync_host_customizations(
        profile_dir,
        real_home=ctx.real_home,
        automations_mode=mode,
        include_handoff=True,
        handoff_limit=limit,
        handoff_source_gemini=source_gemini,
        handoff_source_account=source_account,
        handoff_source_name=source_name,
        include_sessions=include_sessions,
        session_limit=session_limit,
        turbo_bypass=True,
    )

    if launch:
        launch_ws = explicit_ws or (check_ws if chosen_target == "ide" and check_ws else None)
        launch_res = launch_profile(
            ctx.root,
            profile_dir,
            manifest,
            target=chosen_target,
            workspace=launch_ws,
            real_home=ctx.real_home,
        )

    prompt_text = str(handoff_digest.get("resume_prompt") or "")
    prompt_copied = _copy_prompt_to_clipboard(prompt_text, copy_prompt)

    ps_rows = list_all_processes()
    summary = _build_profile_summary(
        ctx.root,
        profile_dir,
        manifest,
        ps_rows,
        launcher_dest=_default_launcher_dest(ctx),
    )
    ev = EvidenceRecord(
        operation="profile_switch",
        authority="filesystem",
        confidence="observed",
        summary="Switched to '{}' (automations={}, synced {} projects, {} automations active, launch={}).".format(
            manifest.name,
            mode,
            sync_res["projects_synced"],
            sync_res["automations_enabled"],
            launch,
        ),
        facts={
            "profile": manifest.name,
            "target": chosen_target,
            "automations_mode": mode,
            "automations_synced": sync_res["automations_synced"],
            "automations_enabled": sync_res["automations_enabled"],
            "from_source": source_name,
            "git_dirty": git_status["dirty"],
            "git_modified_count": git_status["modified_count"],
            "prompt_copied": prompt_copied,
            "launched": launch,
        },
        limitations=[],
    )
    summary["sync"] = sync_res
    summary["stop"] = stop_res
    summary["switch"] = {
        "target": chosen_target,
        "automations_mode": mode,
        "from_source": source_name,
        "git_status": git_status,
        "prompt_copied": prompt_copied,
        "resume_prompt": prompt_text,
        "launched": launch_res,
        "host_automations_paused": host_paused,
    }
    summary["evidence"] = ev.to_dict()
    return summary


def _handle_system_doctor(ctx: RuntimeContext, _params: Dict[str, Any]) -> Dict[str, Any]:
    targets = detect_targets()
    root_exists = ctx.root.is_dir()
    root_mode = oct(ctx.root.stat().st_mode & 0o777) if root_exists else None
    osacompile_path = shutil.which("osacompile")

    ps_rows = list_all_processes()
    stale_profiles: List[str] = []
    insecure_profiles: List[str] = []
    unsigned_launchers: List[str] = []
    launcher_dest = _default_launcher_dest(ctx)
    profile_count = 0
    if root_exists:
        for entry in sorted(ctx.root.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_dir() or not (entry / "profile.json").is_file():
                continue
            profile_count += 1
            _, manifest = load_manifest(ctx.root, entry.name)
            for tgt in ("hub", "ide"):
                if inspect_locks(entry, tgt, ps_rows=ps_rows)["state"] == "stale-lock":
                    stale_profiles.append("{}:{}".format(entry.name, tgt))
                bundle = resolve_launcher_bundle_path(
                    manifest.name,
                    manifest.label,
                    tgt,
                    dest_dir=launcher_dest,
                )
                if bundle.exists() and not verify_launcher_signature(bundle):
                    unsigned_launchers.append("{}:{}".format(entry.name, tgt))
            iso = audit_profile_isolation(entry, manifest)
            if iso["forbidden_symlinks_present"] or not iso["zshenv_home_locked"]:
                insecure_profiles.append(entry.name)

    checks = [
        {
            "id": "python_runtime",
            "status": "pass" if sys.version_info >= (3, 9) else "fail",
            "detail": "Python {}.{}.{}".format(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
        },
        {
            "id": "antigravity_hub",
            "status": "pass" if targets["hub"].installed else "warn",
            "detail": targets["hub"].version if targets["hub"].installed else "Antigravity.app not detected",
        },
        {
            "id": "antigravity_ide",
            "status": "pass" if targets["ide"].installed else "info",
            "detail": targets["ide"].version if targets["ide"].installed else "Antigravity IDE.app not installed",
        },
        {
            "id": "storage_root",
            "status": "pass" if (not root_exists or root_mode == "0o700") else "warn",
            "detail": "{} (exists={}, mode={})".format(ctx.root, root_exists, root_mode),
        },
        {
            "id": "osacompile",
            "status": "pass" if osacompile_path else "warn",
            "detail": osacompile_path or "Unavailable on non-macOS host",
        },
        {
            "id": "launcher_signatures",
            "status": "warn" if unsigned_launchers else "pass",
            "detail": ", ".join(unsigned_launchers) if unsigned_launchers else "Compiled .app launchers carry valid signatures",
        },
        {
            "id": "stale_locks",
            "status": "warn" if stale_profiles else "pass",
            "detail": ", ".join(stale_profiles) if stale_profiles else "No stale lock files detected",
        },
        {
            "id": "isolation_audit",
            "status": "fail" if insecure_profiles else "pass",
            "detail": ", ".join(insecure_profiles) if insecure_profiles else "All provisioned profiles pass isolation checks",
        },
        {
            "id": "host_hub_tls",
            "status": "warn" if inspect_host_hub_tls_health(real_home=ctx.real_home).get("tls_broken") else "pass",
            "detail": str(inspect_host_hub_tls_health(real_home=ctx.real_home).get("detail") or "Host Hub localhost TLS pipe healthy"),
        },
    ]
    ev = EvidenceRecord(
        operation="system_doctor",
        authority="host-inspection",
        confidence="observed",
        summary="Checked host Antigravity installations, sandbox root, and {} profile(s).".format(profile_count),
        facts={
            "version": __version__,
            "root": str(ctx.root),
            "profile_count": profile_count,
            "targets": {k: v.to_dict() for k, v in targets.items()},
            "checks": checks,
        },
        limitations=[
            "Doctor checks inspect existing on-disk manifests and host Info.plist metadata without spawning GUI apps."
        ],
    )
    return {"checks": checks, "targets": {k: v.to_dict() for k, v in targets.items()}, "evidence": ev.to_dict()}


def _handle_obligations_verify(_ctx: RuntimeContext, _params: Dict[str, Any]) -> Dict[str, Any]:
    """Run non-destructive in-memory/tempdir self-checks proving core security invariants."""
    pkg_dir = Path(__file__).resolve().parent
    config_sha = _file_sha256(pkg_dir / "config.py")
    iso_sha = _file_sha256(pkg_dir / "isolation.py")
    proc_sha = _file_sha256(pkg_dir / "process_guard.py")
    web_sha = _file_sha256(pkg_dir / "web_server.py")

    items: List[ObligationItem] = []
    evidence_list: List[EvidenceRecord] = []

    with tempfile.TemporaryDirectory(prefix="agy-obligations-") as tmp:
        tmp_path = Path(tmp)

        # 1. Profile name validation
        pos_ok = validate_profile_name("research-alpha_1.0") == "research-alpha_1.0"
        neg_rejected = False
        mal_rejected = False
        for bad in ("../escape", "default"):
            try:
                validate_profile_name(bad)
            except ToolError:
                if bad == "default":
                    neg_rejected = True
                else:
                    mal_rejected = True
        passed = pos_ok and neg_rejected and mal_rejected
        ev1 = EvidenceRecord(
            operation="verify_name_validation",
            authority="self-check",
            confidence="observed",
            summary="Verified valid profile name acceptance and reserved/traversal rejection.",
            facts={"positive": pos_ok, "reserved_rejected": neg_rejected, "traversal_rejected": mal_rejected},
            limitations=["Checks tested representative valid, reserved, and traversal strings."],
        )
        evidence_list.append(ev1)
        items.append(
            ObligationItem(
                obligation_id="isolation.name_validation",
                title="Reject reserved or traversal profile slugs",
                status="closed" if passed else "failed",
                owner_module="config.py",
                module_sha256=config_sha,
                cases_checked=["positive", "negative", "malformed"],
                detail="Accepted valid slug and rejected 'default' and '../escape'.",
                evidence_id=ev1.evidence_id,
            )
        )

        # 2. Path containment
        safe_root = tmp_path / "root"
        safe_root.mkdir(parents=True)
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret", encoding="utf-8")
        escape_link = safe_root / "escape"
        os.symlink(str(outside_file), str(escape_link))
        contained_ok = False
        escape_blocked = False
        try:
            ensure_within_root(safe_root, safe_root / "valid-child")
            contained_ok = True
        except ToolError:
            contained_ok = False
        try:
            ensure_within_root(safe_root, escape_link)
        except ToolError as exc:
            escape_blocked = exc.code == "path_boundary_violation"
        passed2 = contained_ok and escape_blocked
        ev2 = EvidenceRecord(
            operation="verify_path_containment",
            authority="self-check",
            confidence="observed",
            summary="Verified ensure_within_root blocks symlink escapes outside profiles root.",
            facts={"contained_ok": contained_ok, "symlink_escape_blocked": escape_blocked},
            limitations=["Tested within temporary directory on local filesystem."],
        )
        evidence_list.append(ev2)
        items.append(
            ObligationItem(
                obligation_id="isolation.path_containment",
                title="Enforce strict sandbox root path containment",
                status="closed" if passed2 else "failed",
                owner_module="config.py",
                module_sha256=config_sha,
                cases_checked=["positive", "symlink_escape"],
                detail="Permitted valid child and blocked external symlink traversal.",
                evidence_id=ev2.evidence_id,
            )
        )

        # 3. Forbidden symlinks
        allowed_ok = validate_link_relpath("Library/Fonts") == "Library/Fonts"
        ssh_blocked = False
        keychain_blocked = False
        try:
            validate_link_relpath(".ssh/id_ed25519")
        except ToolError as exc:
            ssh_blocked = exc.code == "forbidden_symlink"
        try:
            validate_link_relpath("Library/Keychains")
        except ToolError as exc:
            keychain_blocked = exc.code == "forbidden_symlink"
        passed3 = allowed_ok and ssh_blocked and keychain_blocked
        ev3 = EvidenceRecord(
            operation="verify_forbidden_symlinks",
            authority="self-check",
            confidence="observed",
            summary="Verified forbidden credential paths cannot be symlinked into sandbox homes.",
            facts={"allowed_ok": allowed_ok, "ssh_blocked": ssh_blocked, "keychain_blocked": keychain_blocked},
            limitations=["Checks policy gate against FORBIDDEN_HOME_RELPATHS list."],
        )
        evidence_list.append(ev3)
        items.append(
            ObligationItem(
                obligation_id="isolation.forbidden_symlinks",
                title="Block symlinks to SSH, Keychain, and host .gemini paths",
                status="closed" if passed3 else "failed",
                owner_module="isolation.py",
                module_sha256=iso_sha,
                cases_checked=["positive", "ssh_block", "keychain_block"],
                detail="Permitted Library/Fonts and rejected .ssh/id_ed25519 and Library/Keychains.",
                evidence_id=ev3.evidence_id,
            )
        )

        # 4. Fail-closed MCP scrubbing
        sample_mcp = '{"mcpServers":{"srv":{"env":{"API_TOKEN":"tok_secret"},"args":["--token=abc","--api-key","xyz","https://user:pw@example.com/api?key=123"]}}}'
        cleaned, hits = sanitize_mcp_json_text(sample_mcp)
        srv = cleaned["mcpServers"]["srv"]
        scrub_ok = (
            hits >= 5
            and "tok_secret" not in str(cleaned)
            and "abc" not in str(srv["args"])
            and "xyz" not in str(srv["args"])
            and "pw" not in str(srv["args"])
            and "123" not in str(srv["args"])
        )
        malformed_blocked = False
        try:
            sanitize_mcp_json_text("{bad-json")
        except ToolError as exc:
            malformed_blocked = exc.code == "mcp_config_malformed"
        passed4 = scrub_ok and malformed_blocked
        ev4 = EvidenceRecord(
            operation="verify_mcp_scrub",
            authority="self-check",
            confidence="observed",
            summary="Verified MCP secret scrubbing across env and args plus fail-closed JSON rejection.",
            facts={"scrub_ok": scrub_ok, "redactions": hits, "malformed_blocked": malformed_blocked},
            limitations=["Evaluated against synthetic MCP configuration payload."],
        )
        evidence_list.append(ev4)
        items.append(
            ObligationItem(
                obligation_id="mcp.fail_closed_scrub",
                title="Scrub MCP secrets in env/headers/args and fail closed on invalid JSON",
                status="closed" if passed4 else "failed",
                owner_module="isolation.py",
                module_sha256=iso_sha,
                cases_checked=["env_secret", "args_secret", "url_secret", "malformed_json"],
                detail="Redacted nested secrets and raised mcp_config_malformed on invalid JSON.",
                evidence_id=ev4.evidence_id,
            )
        )

        # 5. Exact user-data-dir process matching
        d1 = "/tmp/p1/data"
        d10 = "/tmp/p10/data"
        match_exact = command_matches_user_data_dir("/Applications/Antigravity.app --user-data-dir=/tmp/p1/data --enable-features=X", d1)
        no_prefix_collision = not command_matches_user_data_dir("/Applications/Antigravity.app --user-data-dir=/tmp/p10/data", d1)
        no_bare_app = not command_matches_user_data_dir("/Applications/Antigravity.app", d1)
        passed5 = match_exact and no_prefix_collision and no_bare_app
        ev5 = EvidenceRecord(
            operation="verify_process_matching",
            authority="self-check",
            confidence="observed",
            summary="Verified strict --user-data-dir token matching prevents PID collision.",
            facts={
                "match_exact": match_exact,
                "no_prefix_collision": no_prefix_collision,
                "no_bare_app_match": no_bare_app,
            },
            limitations=["Evaluated against representative command-line strings."],
        )
        evidence_list.append(ev5)
        items.append(
            ObligationItem(
                obligation_id="process.exact_userdata_match",
                title="Match processes strictly by exact --user-data-dir path",
                status="closed" if passed5 else "failed",
                owner_module="process_guard.py",
                module_sha256=proc_sha,
                cases_checked=["exact", "prefix_collision", "unrelated_instance"],
                detail="Matched /tmp/p1/data only and ignored /tmp/p10/data and default app.",
                evidence_id=ev5.evidence_id,
            )
        )

        # 6. Web CSRF, Origin, Host, and bind validation
        from agy_profiles import web_server

        bind_ok = web_server.validate_bind_host("127.0.0.1") == "127.0.0.1"
        bind_wild_blocked = False
        try:
            web_server.validate_bind_host("0.0.0.0")
        except ToolError as exc:
            bind_wild_blocked = exc.code == "invalid_host_bind"

        expected_host = "127.0.0.1:47920"
        expected_origin = "http://127.0.0.1:47920"
        host_ok = web_server.validate_host_header(expected_host, expected_host)
        host_evil_blocked = not web_server.validate_host_header("evil.com:47920", expected_host)
        orig_ok = web_server.validate_mutation_origin(expected_origin, expected_origin)
        orig_null_blocked = not web_server.validate_mutation_origin("null", expected_origin)
        orig_missing_blocked = not web_server.validate_mutation_origin(None, expected_origin)
        passed6 = (
            bind_ok
            and bind_wild_blocked
            and host_ok
            and host_evil_blocked
            and orig_ok
            and orig_null_blocked
            and orig_missing_blocked
        )
        ev6 = EvidenceRecord(
            operation="verify_web_guards",
            authority="self-check",
            confidence="observed",
            summary="Verified loopback-only bind, Host check, and strict Origin validation.",
            facts={
                "bind_ok": bind_ok,
                "wildcard_bind_blocked": bind_wild_blocked,
                "host_rebind_blocked": host_evil_blocked,
                "null_origin_blocked": orig_null_blocked,
                "missing_origin_blocked": orig_missing_blocked,
            },
            limitations=["Helper self-check complemented by live HTTP integration tests in tests/test_web_security.py."],
        )
        evidence_list.append(ev6)
        items.append(
            ObligationItem(
                obligation_id="web.csrf_and_origin_guard",
                title="Enforce loopback bind, Host allowlist, Origin: null block, and CSRF checks",
                status="closed" if passed6 else "failed",
                owner_module="web_server.py",
                module_sha256=web_sha,
                cases_checked=["loopback_bind", "host_rebind", "origin_null", "origin_missing"],
                detail="Rejected 0.0.0.0 bind, foreign Host, null Origin, and missing Origin.",
                evidence_id=ev6.evidence_id,
            )
        )

    closed_count = sum(1 for item in items if item.status == "closed")
    failed_count = sum(1 for item in items if item.status == "failed")
    ledger_seed = [item.to_dict() for item in items]
    ledger_id = "ldg_" + compute_sha256(ledger_seed)[:16]
    report = ObligationReport(
        ledger_id=ledger_id,
        verified_at=utc_now_iso(),
        summary={"total": len(items), "closed": closed_count, "failed": failed_count},
        items=items,
        evidence=evidence_list,
    )
    return report.to_dict()


def _handle_session_recover(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect Desktop Hub sessions and resume trajectories terminated by auth, model, stream, or quota errors."""
    raw_scope = str(params.get("scope") or "all").strip() or "all"
    if raw_scope not in ("all", "host"):
        raw_scope = validate_profile_name(raw_scope)
    dry_run = bool(params.get("dry_run", False))
    reset_ledger = bool(params.get("reset_ledger", False))
    raw_lookback = params.get("lookback_hours", 12.0)
    try:
        lookback_hours = float(raw_lookback)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            "invalid_argument",
            "lookback_hours must be a finite number.",
            http_status=400,
        ) from exc
    if lookback_hours < 0.5 or lookback_hours > 72.0:
        raise ToolError(
            "invalid_argument",
            "lookback_hours must be between 0.5 and 72.0.",
            http_status=400,
        )

    report = recover_desktop_sessions_once(
        ctx,
        scope=raw_scope,
        dry_run=dry_run,
        reset_ledger=reset_ledger,
        lookback_hours=lookback_hours,
    )
    ev = EvidenceRecord(
        operation="session_recover",
        authority="hub-rpc-and-transcripts",
        confidence="observed",
        summary="Inspected Desktop Hub trajectories (scope={}, stalled={}, resumed={}, dry_run={}).".format(
            raw_scope,
            report.get("stalled_total", 0),
            report.get("resumed_total", 0),
            dry_run,
        ),
        facts={
            "scope": raw_scope,
            "dry_run": dry_run,
            "reset_ledger": reset_ledger,
            "lookback_hours": lookback_hours,
            "stalled_total": report.get("stalled_total", 0),
            "resumed_total": report.get("resumed_total", 0),
        },
        limitations=["Requires a reachable Antigravity Desktop Hub language_server process for live RPC recovery."],
    )
    return {**report, "evidence": ev.to_dict()}


TOOL_SPECS: List[ToolSpec] = [
    ToolSpec(
        name="profile_list",
        description="List all isolated Antigravity sandbox profiles, host binaries, and live status.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_handle_profile_list,
        mutates=False,
    ),
    ToolSpec(
        name="profile_inspect",
        description="Inspect one sandbox profile, its permissions, symlinks, runtime PIDs, and Evidence record.",
        input_schema={
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Profile slug."}},
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_inspect,
        mutates=False,
    ),
    ToolSpec(
        name="profile_create",
        description="Create a hardened isolated profile directory with 0700/0600 permissions and optional sanitized config inheritance.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "label": {"type": "string"},
                "accent": {"type": "string"},
                "default_target": {"type": "string", "enum": ["hub", "ide"]},
                "link_policy": {"type": "string", "enum": ["none", "minimal", "dev"]},
                "auth_mode": {"type": "string", "enum": ["isolated-file", "system-keychain"]},
                "keep_background_alive": {"type": "boolean"},
                "inherit_config": {"type": "boolean"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_create,
        mutates=True,
    ),
    ToolSpec(
        name="profile_update",
        description="Update profile metadata, auth mode, or symlink policy and reconcile sandbox directories.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "label": {"type": "string"},
                "accent": {"type": "string"},
                "default_target": {"type": "string", "enum": ["hub", "ide"]},
                "link_policy": {"type": "string", "enum": ["none", "minimal", "dev"]},
                "auth_mode": {"type": "string", "enum": ["isolated-file", "system-keychain"]},
                "keep_background_alive": {"type": "boolean"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_update,
        mutates=True,
    ),
    ToolSpec(
        name="profile_launch",
        description="Launch Antigravity Hub or IDE strictly sandboxed inside the profile directory.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string", "enum": ["hub", "ide"]},
                "workspace": {"type": "string"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_launch,
        mutates=True,
    ),
    ToolSpec(
        name="profile_stop",
        description="Stop verified running processes owned by a sandbox profile using staged SIGTERM then SIGKILL.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string", "enum": ["hub", "ide", "all"]},
                "timeout_sec": {"type": "number"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_stop,
        mutates=True,
    ),
    ToolSpec(
        name="profile_repair",
        description="Clean stale Chromium locks when stopped and reconcile sandbox .zshenv and permissions.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string", "enum": ["hub", "ide"]},
                "launch": {"type": "boolean", "default": True},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_repair,
        mutates=True,
    ),
    ToolSpec(
        name="profile_clone",
        description="Clone a stopped sandbox profile to a new profile slug with freshly locked .zshenv HOME.",
        input_schema={
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "target": {"type": "string"},
                "label": {"type": "string"},
                "fresh_auth": {"type": "boolean", "default": False},
            },
            "required": ["source", "target"],
            "additionalProperties": False,
        },
        handler=_handle_profile_clone,
        mutates=True,
    ),
    ToolSpec(
        name="profile_rename",
        description="Rename a sandbox profile slug and display label while preserving login credentials and relocking .zshenv HOME.",
        input_schema={
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "target": {"type": "string"},
                "label": {"type": "string"},
                "restart": {"type": "boolean", "default": False},
            },
            "required": ["source", "target"],
            "additionalProperties": False,
        },
        handler=_handle_profile_rename,
        mutates=True,
    ),
    ToolSpec(
        name="profile_delete",
        description="Delete a sandbox profile and its macOS launchers after unlinking managed symlinks safely.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "force_stop": {"type": "boolean"},
                "confirm": {"type": "boolean"},
            },
            "required": ["name", "confirm"],
            "additionalProperties": False,
        },
        handler=_handle_profile_delete,
        mutates=True,
    ),
    ToolSpec(
        name="launcher_build",
        description="Compile a macOS Spotlight/Dock .app shim for launching a sandboxed profile.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string", "enum": ["hub", "ide"]},
                "dest": {"type": "string"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_launcher_build,
        mutates=True,
    ),
    ToolSpec(
        name="launcher_remove",
        description="Remove the macOS .app launcher shim associated with a sandbox profile.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string", "enum": ["hub", "ide"]},
                "dest": {"type": "string"},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_launcher_remove,
        mutates=True,
    ),
    ToolSpec(
        name="profile_sync",
        description="Sync sanitized host projects, automations, plugins, agents, skills, rules, MCP JSON, optional clickable sidebar sessions, and handoff into a profile.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "include_sidecars": {"type": "boolean", "default": False},
                "automations_mode": {"type": "string", "enum": ["paused", "active", "strip"]},
                "include_handoff": {"type": "boolean", "default": True},
                "include_sessions": {"type": "boolean", "default": False},
                "session_limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                "from_source": {"type": "string", "default": "host"},
                "restart": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_sync,
        mutates=True,
    ),
    ToolSpec(
        name="profile_switch",
        description="Switch active quota onto a profile (or back to 'host') by checking git status, syncing clickable sidebar sessions, setup, handoff, and automations, and launching.",
        input_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "automations_mode": {"type": "string", "enum": ["paused", "active", "strip"], "default": "active"},
                "target": {"type": "string", "enum": ["hub", "ide"]},
                "workspace": {"type": "string"},
                "from_source": {"type": "string", "default": "host"},
                "include_sessions": {"type": "boolean", "default": True},
                "session_limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                "copy_prompt": {"type": "boolean", "default": False},
                "launch": {"type": "boolean", "default": True},
                "limit": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10},
            },
            "required": ["name"],
            "additionalProperties": False,
        },
        handler=_handle_profile_switch,
        mutates=True,
    ),
    ToolSpec(
        name="host_handoff",
        description="Read active Host or sandbox Antigravity conversations read-only to generate a resume digest.",
        input_schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10},
                "source": {"type": "string", "default": "host"},
            },
            "additionalProperties": False,
        },
        handler=_handle_host_handoff,
        mutates=False,
    ),
    ToolSpec(
        name="system_doctor",
        description="Inspect host Antigravity bundles, sandbox root permissions, launcher signatures, stale locks, and isolation state.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_handle_system_doctor,
        mutates=False,
    ),
    ToolSpec(
        name="obligations_verify",
        description="Run live security self-checks across isolation, MCP scrubbing, PID matching, and CSRF guards.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_handle_obligations_verify,
        mutates=False,
    ),
    ToolSpec(
        name="session_recover",
        description="Inspect running Antigravity Desktop Hub instances for conversations terminated by auth logout/login, model lookup, stream, or quota errors and automatically resume them.",
        input_schema={
            "type": "object",
            "properties": {
                "scope": {"type": "string", "default": "all"},
                "dry_run": {"type": "boolean", "default": False},
                "reset_ledger": {"type": "boolean", "default": False},
                "lookback_hours": {"type": "number", "minimum": 0.5, "maximum": 72.0, "default": 12.0},
            },
            "additionalProperties": False,
        },
        handler=_handle_session_recover,
        mutates=True,
    ),
]

TOOL_MAP: Dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_SPECS}


def list_tools() -> List[Dict[str, Any]]:
    """Return MCP-compatible tool descriptors for all registered tools."""
    return [
        {
            "name": spec.name,
            "description": spec.description,
            "inputSchema": spec.input_schema,
        }
        for spec in TOOL_SPECS
    ]


def call_tool(name: str, params: Optional[Dict[str, Any]], ctx: RuntimeContext) -> Dict[str, Any]:
    """Dispatch a tool invocation through the canonical ToolSpec registry."""
    spec = TOOL_MAP.get(name)
    if spec is None:
        raise ToolError(
            "invalid_argument",
            "Unknown tool {!r}.".format(name),
            "Inspect available tool names with 'tools/list'.",
            {"tool": name},
            http_status=404,
        )
    args = params if isinstance(params, dict) else {}
    if spec.mutates:
        invalidate_disk_size_cache()
    try:
        return spec.handler(ctx, args)
    finally:
        if spec.mutates:
            invalidate_disk_size_cache()
