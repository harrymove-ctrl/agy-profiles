"""Profile validation, path containment, host bundle detection, and manifest I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

from agy_profiles.errors import ToolError
from agy_profiles.evidence import utc_now_iso

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
RESERVED_NAMES = {"default", "all", "system", "con", "prn", "aux", "nul"}

VALID_TARGETS: Tuple[str, ...] = ("hub", "ide")
VALID_LINK_POLICIES: Tuple[str, ...] = ("none", "minimal", "dev")
VALID_AUTH_MODES: Tuple[str, ...] = ("isolated-file", "system-keychain")

DEFAULT_ACCENTS: List[str] = [
    "#3B82F6",
    "#10B981",
    "#F59E0B",
    "#EC4899",
    "#8B5CF6",
    "#06B6D4",
]

CACHE_DIR_NAMES: Tuple[str, ...] = (
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GraphiteDawnCache",
)


def validate_profile_name(name: str) -> str:
    """Validate strict profile slug syntax and reject reserved or traversal names."""
    if not isinstance(name, str) or "\x00" in name:
        raise ToolError(
            "invalid_profile_name",
            "Profile name must be a valid string without null bytes.",
            "Choose a name matching ^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$.",
        )
    if not PROFILE_NAME_RE.match(name) or ".." in name:
        raise ToolError(
            "invalid_profile_name",
            "Invalid profile name: {!r}.".format(name),
            "Use 1 to 48 ASCII letters, numbers, dots, underscores, or single hyphens starting with a letter or digit.",
            {"name": name},
        )
    if name.lower() in RESERVED_NAMES:
        raise ToolError(
            "invalid_profile_name",
            "Profile name {!r} is reserved.".format(name),
            "Choose a distinct profile name not in reserved identifiers.",
            {"name": name},
        )
    return name


def validate_target(target: str) -> str:
    """Validate runtime target identifier."""
    if target not in VALID_TARGETS:
        raise ToolError(
            "invalid_argument",
            "Unsupported target {!r}.".format(target),
            "Use 'hub' or 'ide'.",
            {"target": target},
        )
    return target


def validate_link_policy(policy: str) -> str:
    """Validate sandbox symlink inheritance policy."""
    if policy not in VALID_LINK_POLICIES:
        raise ToolError(
            "invalid_argument",
            "Unsupported link policy {!r}.".format(policy),
            "Use 'none', 'minimal', or 'dev'.",
            {"link_policy": policy},
        )
    return policy


def validate_auth_mode(auth_mode: str) -> str:
    """Validate authentication storage mode."""
    if auth_mode not in VALID_AUTH_MODES:
        raise ToolError(
            "invalid_argument",
            "Unsupported auth mode {!r}.".format(auth_mode),
            "Use 'isolated-file' or 'system-keychain'.",
            {"auth_mode": auth_mode},
        )
    return auth_mode


def validate_accent(accent: Optional[str]) -> str:
    """Validate 6-digit hex accent color or return default accent."""
    if accent is None or accent == "":
        return DEFAULT_ACCENTS[0]
    if not isinstance(accent, str) or not HEX_COLOR_RE.match(accent.strip()):
        raise ToolError(
            "invalid_argument",
            "Invalid accent color {!r}.".format(accent),
            "Provide a 6-digit hex color such as '#3B82F6'.",
            {"accent": accent},
        )
    return accent.strip().upper()


def resolve_profiles_root(explicit_root: Optional[Union[str, Path]] = None) -> Path:
    """Resolve sandbox storage root with external /Volumes/Dev preference on macOS."""
    if explicit_root is not None and str(explicit_root).strip() != "":
        return Path(explicit_root).expanduser()
    env_root = os.environ.get("AGY_PROFILES_DIR", "").strip()
    if env_root:
        return Path(env_root).expanduser()
    if sys.platform == "darwin":
        dev_mount = Path("/Volumes/Dev")
        dev_root = dev_mount / ".antigravity-profiles"
        home_root = Path.home() / ".antigravity-profiles"
        try:
            if dev_mount.is_dir() and os.access(str(dev_mount), os.W_OK):
                if home_root.exists() and not dev_root.exists():
                    return home_root
                return dev_root
        except OSError:
            pass
    return Path.home() / ".antigravity-profiles"


def ensure_within_root(root: Path, candidate: Path) -> Path:
    """Verify resolved candidate path and parent stay inside resolved root."""
    cand_str = str(candidate)
    if "\x00" in cand_str or "\x00" in str(root):
        raise ToolError(
            "path_boundary_violation",
            "Null byte rejected in path boundary check.",
            "Pass clean filesystem paths inside the configured profiles root.",
        )
    try:
        root_resolved = root.resolve()
        cand_resolved = candidate.resolve()
        cand_resolved.relative_to(root_resolved)
        if cand_resolved != root_resolved:
            parent_resolved = candidate.parent.resolve()
            parent_resolved.relative_to(root_resolved)
    except (ValueError, OSError) as exc:
        raise ToolError(
            "path_boundary_violation",
            "Resolved path {!r} escapes sandbox root {!r}.".format(str(candidate), str(root)),
            "Keep all profile paths contained within the profiles root directory.",
            {"root": str(root), "candidate": str(candidate)},
        ) from exc
    return cand_resolved


def ensure_symlink_slot_within_root(root: Path, slot: Path) -> Path:
    """Verify the parent directory of a managed symlink stays inside resolved root."""
    slot_str = str(slot)
    if "\x00" in slot_str or slot.name in ("", ".", ".."):
        raise ToolError(
            "path_boundary_violation",
            "Invalid symlink slot path {!r}.".format(slot_str),
            "Target a concrete child path inside the sandbox home directory.",
        )
    try:
        root_resolved = root.resolve()
        parent_resolved = slot.parent.resolve()
        parent_resolved.relative_to(root_resolved)
        resolved_slot = parent_resolved / slot.name
        resolved_slot.relative_to(root_resolved)
    except (ValueError, OSError) as exc:
        raise ToolError(
            "path_boundary_violation",
            "Symlink slot {!r} escapes sandbox root {!r}.".format(slot_str, str(root)),
            "Restrict symlink placement to subdirectories inside the sandbox home.",
            {"root": str(root), "slot": slot_str},
        ) from exc
    return resolved_slot


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Atomically write bytes with explicit file permissions and fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=".{}.".format(path.name),
        suffix=".tmp",
    )
    try:
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, str(path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Atomically write UTF-8 text to disk."""
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    """Atomically write pretty JSON object to disk."""
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    atomic_write_text(path, rendered, mode=mode)


@dataclass
class TargetInfo:
    """Detected Google Antigravity application bundle metadata."""

    kind: str
    display_name: str
    app_path: Optional[str]
    binary_path: Optional[str]
    bundle_id: str
    version: str
    installed: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert target metadata to JSON dictionary."""
        return {
            "kind": self.kind,
            "display_name": self.display_name,
            "app_path": self.app_path,
            "binary_path": self.binary_path,
            "bundle_id": self.bundle_id,
            "version": self.version,
            "installed": self.installed,
        }


def _inspect_app_bundle(
    kind: str,
    display_name: str,
    candidates: List[Path],
    fallback_exec: str,
) -> TargetInfo:
    for app_dir in candidates:
        if not app_dir.is_dir():
            continue
        plist_path = app_dir / "Contents" / "Info.plist"
        bundle_id = ""
        version = ""
        exec_name = fallback_exec
        if plist_path.is_file():
            try:
                with open(str(plist_path), "rb") as fh:
                    pl = plistlib.load(fh)
                bundle_id = str(pl.get("CFBundleIdentifier") or "")
                version = str(pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or "")
                exec_name = str(pl.get("CFBundleExecutable") or fallback_exec)
            except (OSError, plistlib.InvalidFileException, ValueError):
                pass
        bin_path = app_dir / "Contents" / "MacOS" / exec_name
        if not bin_path.is_file():
            alt_bin = app_dir / "Contents" / "MacOS" / fallback_exec
            if alt_bin.is_file():
                bin_path = alt_bin
        if bin_path.is_file() and os.access(str(bin_path), os.X_OK):
            return TargetInfo(
                kind=kind,
                display_name=display_name,
                app_path=str(app_dir),
                binary_path=str(bin_path),
                bundle_id=bundle_id,
                version=version or "unknown",
                installed=True,
            )
    return TargetInfo(
        kind=kind,
        display_name=display_name,
        app_path=None,
        binary_path=None,
        bundle_id="",
        version="",
        installed=False,
    )


def detect_targets() -> Dict[str, TargetInfo]:
    """Detect installed Antigravity Hub and Antigravity IDE macOS bundles."""
    hub_candidates: List[Path] = []
    ide_candidates: List[Path] = []
    hub_env = os.environ.get("AGY_HUB_APP", "").strip()
    if hub_env:
        hub_candidates.append(Path(hub_env).expanduser())
    ide_env = os.environ.get("AGY_IDE_APP", "").strip()
    if ide_env:
        ide_candidates.append(Path(ide_env).expanduser())

    home = Path.home()
    hub_candidates.extend(
        [
            Path("/Applications/Antigravity.app"),
            home / "Applications" / "Antigravity.app",
        ]
    )
    ide_candidates.extend(
        [
            Path("/Applications/Antigravity IDE.app"),
            home / "Applications" / "Antigravity IDE.app",
        ]
    )
    return {
        "hub": _inspect_app_bundle("hub", "Antigravity Hub", hub_candidates, "Antigravity"),
        "ide": _inspect_app_bundle("ide", "Antigravity IDE", ide_candidates, "Electron"),
    }


@dataclass
class ProfileManifest:
    """Versioned sandbox profile manifest persisted at <profile>/profile.json."""

    schema_version: int = 1
    name: str = ""
    label: str = ""
    accent: str = "#3B82F6"
    default_target: str = "hub"
    link_policy: str = "minimal"
    auth_mode: str = "isolated-file"
    keep_background_alive: bool = False
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    last_launched_at: Optional[str] = None
    last_host_versions: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize manifest to dictionary."""
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "label": self.label,
            "accent": self.accent,
            "default_target": self.default_target,
            "link_policy": self.link_policy,
            "auth_mode": self.auth_mode,
            "keep_background_alive": self.keep_background_alive,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_launched_at": self.last_launched_at,
            "last_host_versions": dict(self.last_host_versions),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], expected_name: Optional[str] = None) -> "ProfileManifest":
        """Validate and construct manifest from parsed JSON object."""
        if not isinstance(data, dict):
            raise ToolError(
                "invalid_argument",
                "Profile manifest must be a JSON object.",
                "Repair or recreate the profile manifest file.",
            )
        name = validate_profile_name(str(data.get("name") or expected_name or ""))
        if expected_name is not None and name != expected_name:
            name = validate_profile_name(expected_name)
        label = str(data.get("label") or name).strip() or name
        accent = validate_accent(str(data.get("accent") or DEFAULT_ACCENTS[0]))
        default_target = validate_target(str(data.get("default_target") or "hub"))
        link_policy = validate_link_policy(str(data.get("link_policy") or "minimal"))
        auth_mode = validate_auth_mode(str(data.get("auth_mode") or "isolated-file"))
        keep_bg = bool(data.get("keep_background_alive", False))
        created_at = str(data.get("created_at") or utc_now_iso())
        updated_at = str(data.get("updated_at") or created_at)
        last_launched = data.get("last_launched_at")
        if last_launched is not None:
            last_launched = str(last_launched)
        raw_versions = data.get("last_host_versions")
        versions: Dict[str, str] = {}
        if isinstance(raw_versions, dict):
            for k, v in raw_versions.items():
                versions[str(k)] = str(v)
        schema_ver = int(data.get("schema_version") or 1)
        return cls(
            schema_version=schema_ver,
            name=name,
            label=label,
            accent=accent,
            default_target=default_target,
            link_policy=link_policy,
            auth_mode=auth_mode,
            keep_background_alive=keep_bg,
            created_at=created_at,
            updated_at=updated_at,
            last_launched_at=last_launched,
            last_host_versions=versions,
        )


def get_profile_dir(root: Path, name: str) -> Path:
    """Resolve and boundary-check a profile directory inside root."""
    valid_name = validate_profile_name(name)
    if not root.exists():
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(str(root), 0o700)
    profile_dir = ensure_within_root(root, root / valid_name)
    if profile_dir == root.resolve():
        raise ToolError(
            "invalid_profile_name",
            "Profile directory cannot alias the storage root.",
            "Provide a valid non-empty profile name.",
        )
    return profile_dir


def load_manifest(root: Path, name: str) -> Tuple[Path, ProfileManifest]:
    """Load an existing profile manifest or raise profile_not_found."""
    valid_name = validate_profile_name(name)
    if not root.exists():
        raise ToolError(
            "profile_not_found",
            "Profile {!r} does not exist because storage root is missing.".format(valid_name),
            "Run 'agy-profiles create {}' first.".format(valid_name),
            {"name": valid_name, "root": str(root)},
            http_status=404,
        )
    profile_dir = ensure_within_root(root, root / valid_name)
    manifest_path = ensure_within_root(profile_dir, profile_dir / "profile.json")
    if not profile_dir.is_dir() or not manifest_path.is_file():
        raise ToolError(
            "profile_not_found",
            "Profile {!r} was not found in {!r}.".format(valid_name, str(root)),
            "Run 'agy-profiles list' to inspect available profiles.",
            {"name": valid_name, "root": str(root)},
            http_status=404,
        )
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError(
            "invalid_argument",
            "Profile manifest for {!r} could not be parsed.".format(valid_name),
            "Inspect or recreate {}.".format(str(manifest_path)),
            {"name": valid_name},
        ) from exc
    return profile_dir, ProfileManifest.from_dict(raw, expected_name=valid_name)


def save_manifest(root: Path, profile_dir: Path, manifest: ProfileManifest) -> None:
    """Persist manifest inside verified profile directory with 0600 permissions."""
    verified_profile = ensure_within_root(root, profile_dir)
    manifest_path = ensure_within_root(verified_profile, verified_profile / "profile.json")
    manifest.updated_at = utc_now_iso()
    atomic_write_json(manifest_path, manifest.to_dict(), mode=0o600)
