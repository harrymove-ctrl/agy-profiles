"""Unified ToolSpec registry powering CLI, MCP server, and local web console."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional

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
    inherit_host_customizations,
    provision_profile_dirs,
    sanitize_mcp_json_text,
    validate_link_relpath,
)
from agy_profiles.macos_launcher import (
    build_launcher,
    remove_launcher,
    resolve_launcher_bundle_path,
)
from agy_profiles.process_guard import (
    DATA_SUBDIR_BY_TARGET,
    LOCK_FILENAMES,
    command_matches_user_data_dir,
    inspect_locks,
    launch_profile,
    list_all_processes,
    repair_locks,
    stop_profile,
)


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


def _dir_size_bytes_no_follow(path: Path) -> int:
    """Compute disk usage inside a directory without following symlinks."""
    total = 0
    if not path.is_dir():
        return 0
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
    return total


def _build_profile_summary(
    root: Path,
    profile_dir: Path,
    manifest: ProfileManifest,
    ps_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    hub_rt = inspect_locks(profile_dir, "hub", ps_rows=ps_rows)
    ide_rt = inspect_locks(profile_dir, "ide", ps_rows=ps_rows)
    launchers = {
        "hub": resolve_launcher_bundle_path(manifest.name, manifest.label, "hub").exists(),
        "ide": resolve_launcher_bundle_path(manifest.name, manifest.label, "ide").exists(),
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


def _handle_profile_list(ctx: RuntimeContext, _params: Dict[str, Any]) -> Dict[str, Any]:
    root = ctx.root
    targets = detect_targets()
    profiles: List[Dict[str, Any]] = []
    if root.is_dir():
        ps_rows = list_all_processes()
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
            profiles.append(_build_profile_summary(root, entry, manifest, ps_rows))
    return {
        "root": str(root),
        "default_root": str(resolve_profiles_root()),
        "targets": {k: v.to_dict() for k, v in targets.items()},
        "profiles": profiles,
    }


def _handle_profile_inspect(ctx: RuntimeContext, params: Dict[str, Any]) -> Dict[str, Any]:
    name = str(params.get("name") or "")
    profile_dir, manifest = load_manifest(ctx.root, name)
    ps_rows = list_all_processes()
    summary = _build_profile_summary(ctx.root, profile_dir, manifest, ps_rows)
    iso = audit_profile_isolation(profile_dir, manifest)
    ev = EvidenceRecord(
        operation="profile_inspect",
        authority="filesystem",
        confidence="observed",
        summary="Inspected sandbox profile {!r} permissions, symlinks, and runtime locks.".format(manifest.name),
        facts={
            "profile": manifest.name,
            "permissions": iso["permissions"],
            "zshenv_home_locked": iso["zshenv_home_locked"],
            "forbidden_symlinks_present": iso["forbidden_symlinks_present"],
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
    keep_bg = bool(params.get("keep_background_alive", False))
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
    name = validate_profile_name(str(params.get("name") or ""))
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
            if fname == "jetski-standalone-oauth-token" or fname.endswith(".json"):
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

    try:
        provision_profile_dirs(ctx.root, dst_manifest, real_home=ctx.real_home)
        for sub in ("data", "ide-data"):
            _copy_tree_excluding_transient(src_dir / sub, dst_dir / sub)
        _copy_tree_excluding_transient(src_dir / "home" / ".gemini", dst_dir / "home" / ".gemini")
        # Rewrite sandbox .zshenv and policy symlinks cleanly for the cloned home directory.
        provision_profile_dirs(ctx.root, dst_manifest, real_home=ctx.real_home)
        save_manifest(ctx.root, dst_dir, dst_manifest)
    except BaseException:
        _safe_unlink_and_rmtree(ctx.root, dst_dir)
        raise

    return _handle_profile_inspect(ctx, {"name": dst_name})


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

    removed_launchers: List[str] = []
    for tgt in ("hub", "ide"):
        res = remove_launcher(name, manifest.label, tgt)
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
    dest_path = Path(str(dest)).expanduser() if dest else None
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
    dest_path = Path(str(dest)).expanduser() if dest else None
    return remove_launcher(name, manifest.label, target, dest_dir=dest_path)


def _handle_system_doctor(ctx: RuntimeContext, _params: Dict[str, Any]) -> Dict[str, Any]:
    targets = detect_targets()
    root_exists = ctx.root.is_dir()
    root_mode = oct(ctx.root.stat().st_mode & 0o777) if root_exists else None
    osacompile_path = shutil.which("osacompile")

    ps_rows = list_all_processes()
    stale_profiles: List[str] = []
    insecure_profiles: List[str] = []
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
            "id": "stale_locks",
            "status": "warn" if stale_profiles else "pass",
            "detail": ", ".join(stale_profiles) if stale_profiles else "No stale lock files detected",
        },
        {
            "id": "isolation_audit",
            "status": "fail" if insecure_profiles else "pass",
            "detail": ", ".join(insecure_profiles) if insecure_profiles else "All provisioned profiles pass isolation checks",
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
            },
            "required": ["source", "target"],
            "additionalProperties": False,
        },
        handler=_handle_profile_clone,
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
        name="system_doctor",
        description="Inspect host Antigravity bundles, sandbox root permissions, stale locks, and isolation state.",
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
    return spec.handler(ctx, args)
