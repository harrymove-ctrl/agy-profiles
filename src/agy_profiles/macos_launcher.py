"""macOS Spotlight and Dock .app launcher builder using osacompile."""

from __future__ import annotations

from pathlib import Path
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional

from agy_profiles.config import detect_targets, validate_profile_name, validate_target
from agy_profiles.errors import ToolError


def resolve_launcher_bundle_path(
    profile_name: str,
    label: str,
    target: str,
    dest_dir: Optional[Path] = None,
) -> Path:
    """Compute canonical ~/Applications/Antigravity (<label>).app bundle path."""
    clean_name = validate_profile_name(profile_name)
    valid_target = validate_target(target)
    safe_label = re.sub(r"[/:\\]+", " ", (label or clean_name)).strip() or clean_name
    prefix = "Antigravity" if valid_target == "hub" else "Antigravity IDE"
    base_dir = (dest_dir if dest_dir is not None else (Path.home() / "Applications")).expanduser()
    return base_dir / "{} ({}).app".format(prefix, safe_label)


def _escape_applescript_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def verify_launcher_signature(bundle_path: Path) -> bool:
    """Verify macOS code signature integrity for a compiled .app launcher bundle."""
    if sys.platform != "darwin" or not bundle_path.is_dir():
        return True
    codesign_bin = shutil.which("codesign") or "/usr/bin/codesign"
    if not Path(codesign_bin).exists():
        return True
    proc = subprocess.run(
        [codesign_bin, "--verify", "--deep", "--strict", str(bundle_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return proc.returncode == 0


def build_launcher(
    profile_name: str,
    label: str,
    target: str,
    cli_bin_path: str,
    dest_dir: Optional[Path] = None,
    root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Compile an LSUIElement macOS .app shim invoking agy-profiles launch."""
    if sys.platform != "darwin":
        raise ToolError(
            "launcher_error",
            "macOS .app launcher creation requires Darwin (macOS).",
            "Use 'agy-profiles launch' directly on non-macOS systems.",
            {"platform": sys.platform},
        )
    osacompile_bin = shutil.which("osacompile")
    if not osacompile_bin:
        raise ToolError(
            "launcher_error",
            "'osacompile' was not found on PATH.",
            "Ensure macOS developer scripting utilities are available.",
        )

    clean_name = validate_profile_name(profile_name)
    valid_target = validate_target(target)
    bundle_path = resolve_launcher_bundle_path(clean_name, label, valid_target, dest_dir=dest_dir)
    bundle_path.parent.mkdir(parents=True, exist_ok=True)

    cmd_parts = [cli_bin_path]
    if root is not None:
        cmd_parts.extend(["--root", str(root)])
    cmd_parts.extend(["launch", clean_name, "--target", valid_target])
    quoted_launch = " ".join(shlex.quote(part) for part in cmd_parts)
    shell_cmd = (
        'export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$HOME/.local/bin:$PATH"; '
        'mkdir -p "$HOME/Library/Logs" >/dev/null 2>&1 || true; '
        '{} >> "$HOME/Library/Logs/agy-profiles-launcher.log" 2>&1 &'
    ).format(quoted_launch)
    applescript = 'do shell script "{}"\n'.format(_escape_applescript_string(shell_cmd))

    if bundle_path.exists():
        shutil.rmtree(str(bundle_path))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".applescript", encoding="utf-8", delete=False) as tf:
        tf.write(applescript)
        script_path = Path(tf.name)

    try:
        proc = subprocess.run(
            [osacompile_bin, "-o", str(bundle_path), str(script_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode != 0:
            raise ToolError(
                "launcher_error",
                "osacompile failed: {}.".format(proc.stderr.strip() or proc.stdout.strip()),
                "Verify AppleScript compilation permissions and retry.",
            )
    finally:
        try:
            script_path.unlink()
        except OSError:
            pass

    plist_path = bundle_path / "Contents" / "Info.plist"
    if plist_path.is_file():
        with open(str(plist_path), "rb") as fh:
            pl = plistlib.load(fh)
        pl["CFBundleIdentifier"] = "io.github.harrymove-ctrl.agy-profiles.{}.{}".format(clean_name, valid_target)
        pl["CFBundleName"] = bundle_path.stem
        pl["LSUIElement"] = True
        pl["NSRemovableVolumesUsageDescription"] = (
            "Allows launching isolated Antigravity profiles stored on external volumes."
        )
        with open(str(plist_path), "wb") as fh:
            plistlib.dump(pl, fh)

    targets = detect_targets()
    target_info = targets.get(valid_target)
    if target_info and target_info.app_path:
        res_dir = Path(target_info.app_path) / "Contents" / "Resources"
        for icon_name in ("icon.icns", "electron.icns", "Code.icns"):
            src_icon = res_dir / icon_name
            dst_icon = bundle_path / "Contents" / "Resources" / "applet.icns"
            if src_icon.is_file() and dst_icon.parent.is_dir():
                shutil.copy2(str(src_icon), str(dst_icon))
                break

    # Ad-hoc re-sign after Info.plist and icon mutations so arm64 AMFI accepts the bundle.
    codesign_bin = shutil.which("codesign") or "/usr/bin/codesign"
    signed = False
    if Path(codesign_bin).exists():
        sign_proc = subprocess.run(
            [codesign_bin, "--force", "--deep", "--sign", "-", str(bundle_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if sign_proc.returncode != 0:
            raise ToolError(
                "launcher_error",
                "codesign failed: {}.".format(sign_proc.stderr.strip() or sign_proc.stdout.strip()),
                "Verify Apple developer command-line tools are available and retry.",
            )
        signed = True

    return {
        "profile": clean_name,
        "target": valid_target,
        "bundle_path": str(bundle_path),
        "bundle_id": "io.github.harrymove-ctrl.agy-profiles.{}.{}".format(clean_name, valid_target),
        "signed": signed,
    }


def remove_launcher(
    profile_name: str,
    label: str,
    target: str,
    dest_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Remove a compiled macOS .app launcher bundle if present."""
    bundle_path = resolve_launcher_bundle_path(profile_name, label, target, dest_dir=dest_dir)
    existed = bundle_path.exists()
    if existed:
        if bundle_path.suffix != ".app":
            raise ToolError(
                "launcher_error",
                "Refusing to remove non-.app path {!r}.".format(str(bundle_path)),
                "Verify destination directory contains only compiled .app launchers.",
            )
        shutil.rmtree(str(bundle_path))
    return {"removed": existed, "bundle_path": str(bundle_path)}
