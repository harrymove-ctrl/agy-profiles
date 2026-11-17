"""Zero-dependency SRCL and WebTUI inspired terminal dashboard and SVG snapshot exporter."""

from __future__ import annotations

from dataclasses import dataclass
import html
import json
import os
from pathlib import Path
import re
import select
import shutil
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from agy_profiles import __version__
from agy_profiles.errors import ToolError
from agy_profiles.quota_guard import poll_auto_failover_once
from agy_profiles.tools import RuntimeContext, call_tool

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_ANSI_TOKEN_RE = re.compile(r"(\x1b\[[0-9;]*m)")


@dataclass(frozen=True)
class TerminalTheme:
    """Color and glyph tokens for terminal ANSI rendering and standalone SVG export."""

    slug: str
    label: str
    ascii_only: bool
    svg_bg: str
    svg_panel: str
    svg_chrome: str
    border_hex: str
    accent_hex: str
    title_hex: str
    text_hex: str
    muted_hex: str
    ok_hex: str
    warn_hex: str
    err_hex: str
    select_hex: str


THEMES: Dict[str, TerminalTheme] = {
    "sacred": TerminalTheme(
        slug="sacred",
        label="SRCL Phosphor",
        ascii_only=False,
        svg_bg="#0B0D0E",
        svg_panel="#111418",
        svg_chrome="#161A20",
        border_hex="#3A4450",
        accent_hex="#34D399",
        title_hex="#6EE7B7",
        text_hex="#F4F4F5",
        muted_hex="#8E96A4",
        ok_hex="#4ADE80",
        warn_hex="#FBBF24",
        err_hex="#F87171",
        select_hex="#60A5FA",
    ),
    "gothic": TerminalTheme(
        slug="gothic",
        label="Gothic Studio",
        ascii_only=False,
        svg_bg="#0E0F12",
        svg_panel="#15171C",
        svg_chrome="#1B1E25",
        border_hex="#343946",
        accent_hex="#93C5FD",
        title_hex="#BFDBFE",
        text_hex="#ECEEF2",
        muted_hex="#8A909E",
        ok_hex="#86EFAC",
        warn_hex="#FCD34D",
        err_hex="#FCA5A5",
        select_hex="#A5B4FC",
    ),
    "catppuccin": TerminalTheme(
        slug="catppuccin",
        label="WebTUI Mocha",
        ascii_only=False,
        svg_bg="#1E1E2E",
        svg_panel="#181825",
        svg_chrome="#313244",
        border_hex="#45475A",
        accent_hex="#CBA6F7",
        title_hex="#89B4FA",
        text_hex="#CDD6F4",
        muted_hex="#9399B2",
        ok_hex="#A6E3A1",
        warn_hex="#F9E2AF",
        err_hex="#F38BA8",
        select_hex="#94E2D5",
    ),
    "amber": TerminalTheme(
        slug="amber",
        label="CRT Amber",
        ascii_only=False,
        svg_bg="#0D0A04",
        svg_panel="#141006",
        svg_chrome="#1E1708",
        border_hex="#785516",
        accent_hex="#FFB000",
        title_hex="#FFC947",
        text_hex="#FFE299",
        muted_hex="#B5892E",
        ok_hex="#FFB000",
        warn_hex="#FF7A2F",
        err_hex="#FF5252",
        select_hex="#FFF0C2",
    ),
    "ascii": TerminalTheme(
        slug="ascii",
        label="7-Bit ASCII",
        ascii_only=True,
        svg_bg="#0B0D0E",
        svg_panel="#0B0D0E",
        svg_chrome="#161A20",
        border_hex="#9CA3AF",
        accent_hex="#E5E7EB",
        title_hex="#FFFFFF",
        text_hex="#E5E7EB",
        muted_hex="#9CA3AF",
        ok_hex="#E5E7EB",
        warn_hex="#E5E7EB",
        err_hex="#E5E7EB",
        select_hex="#FFFFFF",
    ),
}

THEME_ORDER: Tuple[str, ...] = ("sacred", "gothic", "catppuccin", "amber", "ascii")


def validate_tui_theme(raw: Optional[str]) -> str:
    clean = str(raw or "sacred").strip().lower()
    if clean not in THEMES:
        raise ToolError(
            "invalid_argument",
            "Unsupported TUI theme {!r}.".format(raw),
            "Choose one of: {}.".format(", ".join(THEME_ORDER)),
        )
    return clean


def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    clean = hex_color.lstrip("#")
    if len(clean) != 6:
        return (220, 220, 220)
    return (int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16))


def _fg(hex_color: str, enabled: bool = True, bold: bool = False) -> str:
    if not enabled:
        return ""
    r, g, b = _hex_to_rgb(hex_color)
    prefix = "\x1b[1;" if bold else "\x1b["
    return "{}38;2;{};{};{}m".format(prefix, r, g, b)


def _reset(enabled: bool = True) -> str:
    return "\x1b[0m" if enabled else ""


def visible_len(text: str) -> int:
    """Return printable character length after stripping SGR ANSI sequences."""
    return len(_ANSI_RE.sub("", text))


def clip_plain(text: str, max_width: int) -> str:
    """Clip plain string cleanly to max_width cells without breaking alignment."""
    if max_width <= 0:
        return ""
    clean = text.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    if len(clean) <= max_width:
        return clean
    if max_width <= 3:
        return clean[:max_width]
    return clean[: max_width - 2] + ".."


def fit_ansi(text: str, width: int) -> str:
    """Clip or right-pad an ANSI-styled string to exact visible cell width."""
    if width <= 0:
        return ""
    vlen = visible_len(text)
    if vlen == width:
        return text
    if vlen < width:
        return text + (" " * (width - vlen))

    # Clip visible characters while preserving SGR sequences and appending reset if colored.
    has_ansi = "\x1b[" in text
    budget = max(0, width - 2) if width > 3 else width
    suffix = ".." if width > 3 else ""
    out_parts: List[str] = []
    seen = 0
    for tok in _ANSI_TOKEN_RE.split(text):
        if not tok:
            continue
        if tok.startswith("\x1b[") and tok.endswith("m"):
            out_parts.append(tok)
            continue
        if seen >= budget:
            break
        take = min(len(tok), budget - seen)
        out_parts.append(tok[:take])
        seen += take
    out_parts.append(suffix)
    if has_ansi:
        out_parts.append("\x1b[0m")
    clipped = "".join(out_parts)
    rem = width - visible_len(clipped)
    return clipped + (" " * max(0, rem))


def _mask_email(email: Optional[str], redact: bool) -> str:
    if not email:
        return "unsigned"
    if not redact or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 3:
        masked_local = local[:1] + "***"
    else:
        masked_local = local[:4] + "***"
    return "{}@{}".format(masked_local, domain)


def _mask_path(raw_path: str, redact: bool, host_home: Path) -> str:
    if not redact:
        return raw_path
    home_str = str(host_home)
    if raw_path.startswith(home_str):
        return "~" + raw_path[len(home_str) :]
    return raw_path


def _bar_meter(active: int, total: int, width: int, ascii_only: bool) -> str:
    safe_total = max(total, active, 1)
    filled = int(round((float(active) / float(safe_total)) * width))
    filled = max(0, min(width, filled))
    if active > 0 and filled == 0:
        filled = 1
    fill_ch = "#" if ascii_only else "█"
    empty_ch = "." if ascii_only else "░"
    return (fill_ch * filled) + (empty_ch * (width - filled))


def _box_chars(ascii_only: bool) -> Dict[str, str]:
    if ascii_only:
        return {
            "tl": "+",
            "tr": "+",
            "bl": "+",
            "br": "+",
            "h": "-",
            "v": "|",
            "ml": "+",
            "mr": "+",
        }
    return {
        "tl": "┌",
        "tr": "┐",
        "bl": "└",
        "br": "┘",
        "h": "─",
        "v": "│",
        "ml": "├",
        "mr": "┤",
    }


def _render_box(
    title: str,
    right_meta: str,
    body_lines: Sequence[str],
    width: int,
    theme: TerminalTheme,
    color: bool,
) -> List[str]:
    bc = _box_chars(theme.ascii_only)
    inner = max(10, width - 2)
    b_col = _fg(theme.border_hex, color)
    t_col = _fg(theme.title_hex, color, bold=True)
    m_col = _fg(theme.muted_hex, color)
    rst = _reset(color)

    title_seg = " {} ".format(clip_plain(title, max(4, inner - 6))) if title else ""
    meta_seg = " {} ".format(clip_plain(right_meta, max(0, inner - len(title_seg) - 4))) if right_meta else ""
    fill_len = max(0, inner - len(title_seg) - len(meta_seg) - 1)

    top = (
        "{}{}{}".format(b_col, bc["tl"] + bc["h"], rst)
        + "{}{}{}".format(t_col, title_seg, rst)
        + "{}{}{}".format(b_col, bc["h"] * fill_len, rst)
        + ("{}{}{}".format(m_col, meta_seg, rst) if meta_seg else "")
        + "{}{}{}".format(b_col, bc["tr"], rst)
    )
    out = [top]
    content_width = max(1, inner - 2)
    for line in body_lines:
        padded = fit_ansi(line, content_width)
        out.append(
            "{}{} {}".format(b_col, bc["v"], rst)
            + padded
            + " {}{}{}".format(b_col, bc["v"], rst)
        )
    bottom = "{}{}{}{}".format(b_col, bc["bl"], bc["h"] * inner, bc["br"] + rst)
    out.append(bottom)
    return out


def _probe_ecosystem_channels(ctx: RuntimeContext, ps_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Inspect local Web Console, Hub Aux Sidecars, agy-tele, and discord-radar state read-only."""
    repo_parent = Path(__file__).resolve().parents[3]

    # 1. Standalone Web Console (.web-session.json + PID check)
    web_session_file = ctx.root / ".web-session.json"
    web_online = False
    web_origin = "127.0.0.1:47920"
    live_pids = {int(r["pid"]) for r in ps_rows}
    if web_session_file.is_file():
        try:
            sess = json.loads(web_session_file.read_text(encoding="utf-8"))
            if int(sess.get("pid") or -1) in live_pids:
                web_online = True
                raw_orig = str(sess.get("origin") or "").replace("http://", "")
                if raw_orig:
                    web_origin = raw_orig
        except (OSError, ValueError, TypeError):
            pass
    if not web_online:
        for row in ps_rows:
            cmd = str(row.get("command") or "")
            if "agy-profiles web" in cmd and "--sidecar" not in cmd:
                web_online = True
                break

    # 2. Embedded Antigravity Hub Aux Sidecar instances
    sidecar_pids = [
        int(r["pid"])
        for r in ps_rows
        if "agy-profiles web" in str(r.get("command") or "")
        and "--sidecar" in str(r.get("command") or "")
    ]

    # 3. Sibling agy-tele daemon and persisted bindings
    tele_dir_env = os.environ.get("AGY_TELE_DIR", "").strip()
    tele_dir = Path(tele_dir_env).expanduser() if tele_dir_env else (repo_parent / "agy-tele")
    tele_installed = tele_dir.is_dir()
    tele_running = any(
        "agy-tele" in str(r.get("command") or "") and "grep" not in str(r.get("command") or "")
        for r in ps_rows
    )
    tele_bindings = 0
    if tele_installed:
        tele_state = tele_dir / ".state" / "agy-tele-state.json"
        if tele_state.is_file():
            try:
                parsed_ts = json.loads(tele_state.read_text(encoding="utf-8"))
                bindings = parsed_ts.get("bindings")
                if isinstance(bindings, dict):
                    tele_bindings = len(bindings)
            except (OSError, ValueError):
                pass

    # 4. Sibling discord-radar vault and 2-day scheduler
    radar_dir_env = os.environ.get("DISCORD_RADAR_DIR", "").strip()
    radar_dir = Path(radar_dir_env).expanduser() if radar_dir_env else (repo_parent / "discord-radar")
    radar_installed = radar_dir.is_dir()
    radar_cron_live = any("discord-radar" in str(r.get("command") or "") for r in ps_rows)
    radar_next_date = "--"
    radar_last_date = "--"
    radar_messages = 0
    if radar_installed:
        sched_file = radar_dir / ".state" / "schedule-state.json"
        if sched_file.is_file():
            try:
                sched = json.loads(sched_file.read_text(encoding="utf-8"))
                radar_next_date = str(sched.get("nextEligibleDate") or "--")
                radar_last_date = str(sched.get("lastCompletedDate") or "--")
            except (OSError, ValueError):
                pass
        radar_db = radar_dir / ".state" / "radar.db"
        if radar_db.is_file():
            conn: Optional[sqlite3.Connection] = None
            try:
                conn = sqlite3.connect("file:{}?mode=ro".format(radar_db), uri=True, timeout=1.0)
                row = conn.execute("SELECT COUNT(*) FROM messages").fetchone()
                if row:
                    radar_messages = int(row[0])
            except sqlite3.Error:
                pass
            finally:
                if conn is not None:
                    conn.close()

    return {
        "web_online": web_online,
        "web_origin": web_origin,
        "sidecar_count": len(sidecar_pids),
        "tele_installed": tele_installed,
        "tele_running": tele_running,
        "tele_bindings": tele_bindings,
        "radar_installed": radar_installed,
        "radar_cron_live": radar_cron_live,
        "radar_last_date": radar_last_date,
        "radar_next_date": radar_next_date,
        "radar_messages": radar_messages,
    }


def collect_tui_snapshot(ctx: RuntimeContext, selected_slot: str = "host") -> Dict[str, Any]:
    """Gather a complete read-only telemetry snapshot for TUI rendering."""
    from agy_profiles.process_guard import list_all_processes

    overview = call_tool("profile_list", {}, ctx)
    ps_rows = list_all_processes()
    channels = _probe_ecosystem_channels(ctx, ps_rows)

    valid_slots = ["host"] + [p["manifest"]["name"] for p in overview.get("profiles") or []]
    effective_slot = selected_slot if selected_slot in valid_slots else "host"
    try:
        handoff = call_tool("host_handoff", {"limit": 5, "source": effective_slot}, ctx)
    except ToolError:
        handoff = {"available": False, "count": 0, "conversations": [], "source": effective_slot}

    return {
        "observed_at": time.strftime("%H:%M:%S"),
        "overview": overview,
        "channels": channels,
        "handoff": handoff,
        "selected_slot": effective_slot,
        "slots": valid_slots,
    }


def render_tui_lines(
    snapshot: Dict[str, Any],
    theme_slug: str = "sacred",
    width: int = 104,
    color: bool = True,
    redact: bool = False,
    status_note: str = "",
    interactive_hint: bool = False,
) -> List[str]:
    """Render a complete aligned SRCL/WebTUI frame as a list of lines."""
    theme = THEMES[validate_tui_theme(theme_slug)]
    use_color = bool(color and not theme.ascii_only)
    cols = max(78, min(132, int(width)))
    inner_content = cols - 4

    c_acc = _fg(theme.accent_hex, use_color, bold=True)
    c_txt = _fg(theme.text_hex, use_color)
    c_bold = _fg(theme.text_hex, use_color, bold=True)
    c_mut = _fg(theme.muted_hex, use_color)
    c_ok = _fg(theme.ok_hex, use_color, bold=True)
    c_wrn = _fg(theme.warn_hex, use_color, bold=True)
    c_sel = _fg(theme.select_hex, use_color, bold=True)
    rst = _reset(use_color)

    dot_run = "[RUN]" if theme.ascii_only else "●"
    dot_stp = "[STP]" if theme.ascii_only else "○"
    arrow = "==>" if theme.ascii_only else "══►"

    overview = snapshot["overview"]
    host_acct = overview.get("host_account") or {}
    host_rt = overview.get("host_runtime") or {}
    flow = overview.get("flow") or {}
    profiles: List[Dict[str, Any]] = overview.get("profiles") or []
    channels = snapshot["channels"]
    handoff = snapshot["handoff"]
    selected_slot = snapshot["selected_slot"]
    host_home = Path.home().resolve()

    lines: List[str] = []

    # 1. Header Banner (SRCL + ascii.rest style)
    root_disp = _mask_path(str(overview.get("root") or ""), redact, host_home)
    web_badge = "ONLINE" if channels["web_online"] else "OFFLINE"
    web_col = c_ok if channels["web_online"] else c_mut
    if theme.ascii_only:
        mark_1 = "AGY//PROFILES"
        mark_2 = "CONTROL PLANE"
    else:
        mark_1 = "▄▀█ █▀▀ █▄█"
        mark_2 = "█▀█ █▄█  █ "

    hdr_line_1 = (
        "{}{}{}".format(c_acc, mark_1, rst)
        + "  "
        + "{}{}{}".format(
            c_bold,
            clip_plain(
                "Google Antigravity Multi-Account Sandbox, Automations & Channel Telemetry",
                max(20, inner_content - 14),
            ),
            rst,
        )
    )
    root_clip = clip_plain(root_disp, max(16, inner_content - 46))
    hdr_line_2 = (
        "{}{}{}".format(c_acc, mark_2, rst)
        + "  "
        + "{}Root:{} {}{}{}  {}Web:{} {}{} [{}]{}".format(
            c_mut,
            rst,
            c_txt,
            root_clip,
            rst,
            c_mut,
            rst,
            web_col,
            channels["web_origin"],
            web_badge,
            rst,
        )
    )
    lines.extend(
        _render_box(
            "AGY-PROFILES // TERMINAL TELEMETRY",
            "THEME: {} · v{} · {}".format(theme.slug.upper(), __version__, snapshot["observed_at"]),
            [hdr_line_1, hdr_line_2],
            cols,
            theme,
            use_color,
        )
    )

    # 2. Quota & Automation Flow Box
    host_email = _mask_email(host_acct.get("email"), redact)
    host_hub_state = (host_rt.get("hub") or {}).get("state") or "stopped"
    host_ide_state = (host_rt.get("ide") or {}).get("state") or "stopped"
    host_running = host_hub_state == "running" or host_ide_state == "running"
    host_crons = int(flow.get("host_schedule_count") or 0)
    flow_mode = str(flow.get("mode") or "host_primary")

    if flow.get("dual_automations_warning"):
        mode_tag = "[DUAL CRONS WARNING]"
        mode_col = c_wrn
    elif flow_mode == "backup_active":
        mode_tag = "[BACKUP QUOTA ACTIVE]"
        mode_col = c_sel
    else:
        mode_tag = "[HOST PRIMARY ACTIVE]"
        mode_col = c_ok

    primary_backup = profiles[0] if profiles else None
    if primary_backup:
        b_email = _mask_email((primary_backup.get("account") or {}).get("email"), redact)
        b_rt = primary_backup.get("runtime") or {}
        b_run = (b_rt.get("hub") or {}).get("state") == "running" or (
            b_rt.get("ide") or {}
        ).get("state") == "running"
        b_auto_en = int((primary_backup.get("sync_state") or {}).get("automations_enabled") or 0)
        b_state_txt = "{} active".format(b_auto_en) if b_auto_en > 0 else "standby paused"
        b_col = c_wrn if (b_auto_en > 0 and host_crons > 0) else (c_ok if b_run else c_mut)
        backup_node = "{} {} ({})".format(
            dot_run if b_run else dot_stp,
            clip_plain(b_email, 24),
            b_state_txt,
        )
    else:
        b_col = c_mut
        backup_node = "{} no backup profile".format(dot_stp)

    host_node = "{} {} ({} {})".format(
        dot_run if host_running else dot_stp,
        clip_plain(host_email, 24),
        host_crons,
        "cron" if host_crons == 1 else "crons",
    )
    flow_line_1 = (
        "{}{}{}".format(mode_col, mode_tag, rst)
        + "  "
        + "{}{}{}".format(c_ok if host_running else c_mut, host_node, rst)
        + "  {}{}{}  ".format(c_acc, arrow, rst)
        + "{}{}{}".format(b_col, backup_node, rst)
    )
    flow_line_2 = "{}{}{}".format(
        c_mut,
        clip_plain(str(flow.get("summary") or ""), inner_content),
        rst,
    )
    lines.extend(
        _render_box(
            "QUOTA & AUTOMATION FLOW",
            "OWNER: {}".format(str(flow.get("active_owner") or "host").upper()),
            [flow_line_1, flow_line_2],
            cols,
            theme,
            use_color,
        )
    )

    # 3. Workspaces & Live Runtimes DataTable
    # Fixed responsive column widths summing to inner_content
    w_sel = 2
    w_slot = 11
    w_role = 8
    w_hub = 14
    w_ide = 14
    w_cron = 14
    fixed_sum = w_sel + w_slot + w_role + w_hub + w_ide + w_cron + (6 * 2)
    w_acct = max(14, inner_content - fixed_sum)

    header_row = "  ".join(
        [
            clip_plain("", w_sel).ljust(w_sel),
            clip_plain("SLOT", w_slot).ljust(w_slot),
            clip_plain("GOOGLE ACCOUNT", w_acct).ljust(w_acct),
            clip_plain("ROLE", w_role).ljust(w_role),
            clip_plain("HUB TARGET", w_hub).ljust(w_hub),
            clip_plain("IDE TARGET", w_ide).ljust(w_ide),
            clip_plain("AUTOMATIONS", w_cron).ljust(w_cron),
        ]
    )
    sep_ch = "-" if theme.ascii_only else "─"
    table_lines: List[str] = [
        "{}{}{}".format(c_mut, clip_plain(header_row, inner_content), rst),
        "{}{}{}".format(c_mut, sep_ch * inner_content, rst),
    ]

    def _fmt_target_cell(rt_dict: Dict[str, Any], cell_w: int) -> str:
        st = str(rt_dict.get("state") or "stopped")
        roots = rt_dict.get("root_pids") or rt_dict.get("pids") or []
        if st == "running":
            pid_txt = str(roots[0]) if roots else "live"
            raw = "{} run ({})".format("*" if theme.ascii_only else "●", pid_txt)
            clipped = clip_plain(raw, cell_w).ljust(cell_w)
            return "{}{}{}".format(c_ok, clipped, rst)
        if st == "stale-lock":
            clipped = clip_plain("! stale", cell_w).ljust(cell_w)
            return "{}{}{}".format(c_wrn, clipped, rst)
        raw = "{} stopped".format("-" if theme.ascii_only else "○")
        clipped = clip_plain(raw, cell_w).ljust(cell_w)
        return "{}{}{}".format(c_mut, clipped, rst)

    # Row 0: Primary Host
    is_host_sel = selected_slot == "host"
    host_auto_tot = int(host_acct.get("automations_count") or 0)
    host_bar = _bar_meter(host_crons, max(host_auto_tot, 1), 6, theme.ascii_only)
    host_cron_cell = clip_plain("{} {}/{}".format(host_bar, host_crons, host_auto_tot), w_cron).ljust(w_cron)
    host_row = "  ".join(
        [
            "{}{}{}".format(c_sel, (">" if is_host_sel else " ").ljust(w_sel), rst),
            "{}{}{}".format(c_sel if is_host_sel else c_bold, clip_plain("host", w_slot).ljust(w_slot), rst),
            "{}{}{}".format(c_txt, clip_plain(host_email, w_acct).ljust(w_acct), rst),
            "{}{}{}".format(c_acc, clip_plain("PRIMARY", w_role).ljust(w_role), rst),
            _fmt_target_cell(host_rt.get("hub") or {}, w_hub),
            _fmt_target_cell(host_rt.get("ide") or {}, w_ide),
            "{}{}{}".format(c_ok if host_crons > 0 else c_mut, host_cron_cell, rst),
        ]
    )
    table_lines.append(host_row)

    # Rows 1..N: Sandbox Backup Profiles
    for p in profiles:
        m = p.get("manifest") or {}
        slug = str(m.get("name") or "")
        is_sel = selected_slot == slug
        p_email = _mask_email((p.get("account") or {}).get("email"), redact)
        p_sync = p.get("sync_state") or {}
        p_rt = p.get("runtime") or {}
        p_auto_tot = int(p_sync.get("automations_count") or 0)
        p_auto_en = int(p_sync.get("automations_enabled") or 0)
        p_bar = _bar_meter(p_auto_en, max(p_auto_tot, 1), 6, theme.ascii_only)
        p_cron_cell = clip_plain("{} {}/{}".format(p_bar, p_auto_en, p_auto_tot), w_cron).ljust(w_cron)
        role_txt = "TAKEOVER" if p_auto_en > 0 else "STANDBY"
        role_col = c_wrn if (p_auto_en > 0 and host_crons > 0) else (c_sel if p_auto_en > 0 else c_mut)
        p_row = "  ".join(
            [
                "{}{}{}".format(c_sel, (">" if is_sel else " ").ljust(w_sel), rst),
                "{}{}{}".format(c_sel if is_sel else c_bold, clip_plain(slug, w_slot).ljust(w_slot), rst),
                "{}{}{}".format(c_txt, clip_plain(p_email, w_acct).ljust(w_acct), rst),
                "{}{}{}".format(role_col, clip_plain(role_txt, w_role).ljust(w_role), rst),
                _fmt_target_cell(p_rt.get("hub") or {}, w_hub),
                _fmt_target_cell(p_rt.get("ide") or {}, w_ide),
                "{}{}{}".format(c_wrn if p_auto_en > 0 else c_mut, p_cron_cell, rst),
            ]
        )
        table_lines.append(p_row)

    lines.extend(
        _render_box(
            "WORKSPACES & LIVE RUNTIMES",
            "1 HOST + {} {}".format(len(profiles), "BACKUP" if len(profiles) == 1 else "BACKUPS"),
            table_lines,
            cols,
            theme,
            use_color,
        )
    )

    # 4. Side-by-side Split Boxes: CHANNELS & SIGNALS | RECENT HANDOFF THREADS
    gap = 2
    left_w = (cols - gap) // 2
    right_w = cols - gap - left_w
    left_inner = max(12, left_w - 4)
    right_inner = max(12, right_w - 4)

    sc_count = int(channels["sidecar_count"])
    tele_status = (
        "RUNNING ({} bound)".format(channels["tele_bindings"])
        if channels["tele_running"]
        else ("STOPPED ({} saved)".format(channels["tele_bindings"]) if channels["tele_installed"] else "NOT FOUND")
    )
    radar_status = (
        "CRON LIVE ({} msgs)".format(channels["radar_messages"])
        if channels["radar_cron_live"]
        else ("IDLE ({} msgs)".format(channels["radar_messages"]) if channels["radar_installed"] else "NOT FOUND")
    )
    left_rows = [
        "{}Hub Sidecar:{}  {}{}{}".format(
            c_mut,
            rst,
            c_ok if sc_count > 0 else c_mut,
            clip_plain(
                "{} Aux {} online".format(sc_count, "pane" if sc_count == 1 else "panes"),
                max(8, left_inner - 14),
            ),
            rst,
        ),
        "{}Web Console:{}  {}{}{}".format(
            c_mut,
            rst,
            c_ok if channels["web_online"] else c_mut,
            clip_plain(
                "{} ({})".format(channels["web_origin"], "active" if channels["web_online"] else "stopped"),
                max(8, left_inner - 14),
            ),
            rst,
        ),
        "{}agy-tele:{}     {}{}{}".format(
            c_mut,
            rst,
            c_ok if channels["tele_running"] else c_txt,
            clip_plain(tele_status, max(8, left_inner - 14)),
            rst,
        ),
        "{}discord-radar:{}{}{}{}".format(
            c_mut,
            rst + " ",
            c_ok if channels["radar_cron_live"] else c_txt,
            clip_plain(radar_status, max(8, left_inner - 14)),
            rst,
        ),
        "{}Next Crawl:{}   {}{}{}".format(
            c_mut,
            rst,
            c_txt,
            clip_plain(
                "{} (last {})".format(channels["radar_next_date"], channels["radar_last_date"]),
                max(8, left_inner - 14),
            ),
            rst,
        ),
    ]

    convs: List[Dict[str, Any]] = (handoff.get("conversations") or [])[:5]
    right_rows: List[str] = []
    for idx in range(5):
        if idx < len(convs):
            item = convs[idx]
            proj = str(item.get("project") or "general")
            title = str(item.get("title") or "Untitled")
            entry_plain = "{}. [{}] {}".format(idx + 1, proj, title)
            right_rows.append(
                "{}{}{}".format(
                    c_txt if idx == 0 else c_mut,
                    clip_plain(entry_plain, right_inner),
                    rst,
                )
            )
        elif idx == 0:
            right_rows.append(
                "{}{}{}".format(
                    c_mut,
                    clip_plain("No SQLite threads recorded on this slot yet.", right_inner),
                    rst,
                )
            )
        else:
            right_rows.append("")

    left_box = _render_box(
        "CHANNELS & RADAR",
        "ECOSYSTEM",
        left_rows,
        left_w,
        theme,
        use_color,
    )
    right_box = _render_box(
        "HANDOFF THREADS",
        "SRC: {}".format(selected_slot.upper()),
        right_rows,
        right_w,
        theme,
        use_color,
    )
    for l_line, r_line in zip(left_box, right_box):
        lines.append(fit_ansi(l_line, left_w) + (" " * gap) + fit_ansi(r_line, right_w))

    # 5. Bottom SRCL ActionBar
    if interactive_hint:
        key_line = (
            "{}[j/k]{} Slot  {}[t]{} Theme  {}[s]{} Sync  "
            "{}[w]{} Switch  {}[a]{} AutoGuard  {}[e]{} SVG  {}[r]{} Refresh  {}[q]{} Quit"
        ).format(
            c_acc, rst, c_acc, rst, c_acc, rst, c_acc, rst, c_acc, rst, c_acc, rst, c_acc, rst, c_acc, rst
        )
    else:
        key_line = (
            "{}Run interactive TUI:{} {}agyp top{}   "
            "{}Switch theme:{} {}agyp top --theme gothic|catppuccin|amber|ascii{}   "
            "{}Export X/README SVG:{} {}agyp top --export-svg agyp.svg{}"
        ).format(c_mut, rst, c_acc, rst, c_mut, rst, c_txt, rst, c_mut, rst, c_acc, rst)

    if visible_len(key_line) > inner_content:
        plain_bar = _ANSI_RE.sub("", key_line)
        key_line = "{}{}{}".format(c_mut, clip_plain(plain_bar, inner_content), rst)

    footer_rows = [key_line]
    if status_note:
        footer_rows.append("{}{}{}".format(c_sel, clip_plain(status_note, inner_content), rst))

    lines.extend(
        _render_box(
            "ACTION BAR",
            "SELECT: {}".format(selected_slot.upper()),
            footer_rows,
            cols,
            theme,
            use_color,
        )
    )
    return lines


def _ansi_line_to_svg_tspans(line: str, default_hex: str) -> str:
    """Convert SGR 24-bit foreground ANSI sequences inside one line into escaped SVG tspans."""
    tokens = _ANSI_TOKEN_RE.split(line)
    cur_hex = default_hex
    cur_bold = False
    chunks: List[str] = []

    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("\x1b[") and tok.endswith("m"):
            code_body = tok[2:-1]
            if code_body in ("", "0"):
                cur_hex = default_hex
                cur_bold = False
            else:
                parts = code_body.split(";")
                idx = 0
                while idx < len(parts):
                    if parts[idx] == "1":
                        cur_bold = True
                        idx += 1
                    elif parts[idx] == "38" and idx + 4 < len(parts) and parts[idx + 1] == "2":
                        try:
                            r = max(0, min(255, int(parts[idx + 2])))
                            g = max(0, min(255, int(parts[idx + 3])))
                            b = max(0, min(255, int(parts[idx + 4])))
                            cur_hex = "#{:02X}{:02X}{:02X}".format(r, g, b)
                        except ValueError:
                            pass
                        idx += 5
                    else:
                        idx += 1
            continue

        escaped = html.escape(tok).replace(" ", "&#160;")
        weight_attr = ' font-weight="700"' if cur_bold else ""
        chunks.append('<tspan fill="{}"{}>{}</tspan>'.format(cur_hex, weight_attr, escaped))

    return "".join(chunks)


def render_tui_svg(
    snapshot: Dict[str, Any],
    theme_slug: str = "sacred",
    width: int = 104,
    redact: bool = False,
) -> str:
    """Render a self-contained dark terminal window SVG for GitHub READMEs and X posts."""
    theme = THEMES[validate_tui_theme(theme_slug)]
    cols = max(78, min(132, int(width)))
    ansi_lines = render_tui_lines(
        snapshot,
        theme_slug=theme.slug,
        width=cols,
        color=not theme.ascii_only,
        redact=redact,
        interactive_hint=True,
    )

    char_w = 8.4
    line_h = 19.0
    pad_x = 22.0
    pad_top = 56.0
    pad_bottom = 22.0
    svg_w = int(round(cols * char_w + pad_x * 2))
    svg_h = int(round(len(ansi_lines) * line_h + pad_top + pad_bottom))

    svg_rows: List[str] = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="agy-profiles terminal telemetry">'.format(
            w=svg_w, h=svg_h
        ),
        '  <rect width="{w}" height="{h}" rx="12" fill="{bg}" stroke="{border}" stroke-width="1.5"/>'.format(
            w=svg_w, h=svg_h, bg=theme.svg_bg, border=theme.border_hex
        ),
        '  <rect x="1" y="1" width="{w}" height="38" rx="11" fill="{chrome}"/>'.format(
            w=svg_w - 2, chrome=theme.svg_chrome
        ),
        '  <rect x="1" y="28" width="{w}" height="11" fill="{chrome}"/>'.format(
            w=svg_w - 2, chrome=theme.svg_chrome
        ),
        '  <line x1="0" y1="39" x2="{w}" y2="39" stroke="{border}" stroke-width="1"/>'.format(
            w=svg_w, border=theme.border_hex
        ),
        '  <circle cx="20" cy="20" r="5.5" fill="#EF4444"/>',
        '  <circle cx="38" cy="20" r="5.5" fill="#F59E0B"/>',
        '  <circle cx="56" cy="20" r="5.5" fill="#22C55E"/>',
        '  <text x="{cx}" y="24" text-anchor="middle" fill="{muted}" font-family="JetBrains Mono, SFMono-Regular, ui-monospace, Menlo, monospace" font-size="12" font-weight="600">agyp top · {label}</text>'.format(
            cx=svg_w // 2,
            muted=theme.muted_hex,
            label=html.escape(theme.label),
        ),
        '  <g font-family="JetBrains Mono, SFMono-Regular, ui-monospace, Menlo, Monaco, Consolas, monospace" font-size="13.5" xml:space="preserve">',
    ]

    for idx, line in enumerate(ansi_lines):
        y_pos = int(round(pad_top + idx * line_h))
        spans = _ansi_line_to_svg_tspans(line, theme.text_hex)
        svg_rows.append('    <text x="{x}" y="{y}">{spans}</text>'.format(x=int(pad_x), y=y_pos, spans=spans))

    svg_rows.append("  </g>")
    svg_rows.append("</svg>")
    return "\n".join(svg_rows) + "\n"


def run_tui(
    ctx: RuntimeContext,
    theme_slug: str = "sacred",
    interval_sec: float = 2.0,
    once: bool = False,
    width: Optional[int] = None,
    redact: bool = False,
    export_svg: Optional[str] = None,
    auto_failover: bool = True,
) -> int:
    """Run one-shot or interactive full-screen terminal telemetry loop."""
    current_theme = validate_tui_theme(theme_slug)
    no_color_env = bool(os.environ.get("NO_COLOR", "").strip())
    is_tty = sys.stdout.isatty() and sys.stdin.isatty()

    if export_svg:
        snap = collect_tui_snapshot(ctx, selected_slot="host")
        svg_cols = width if width is not None else 104
        svg_content = render_tui_svg(snap, theme_slug=current_theme, width=svg_cols, redact=redact)
        out_path = Path(export_svg).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(svg_content, encoding="utf-8")

    if once or not is_tty:
        snap = collect_tui_snapshot(ctx, selected_slot="host")
        term_cols = width if width is not None else shutil.get_terminal_size((104, 32)).columns
        note = "Saved SVG snapshot to {}".format(export_svg) if export_svg else ""
        rendered = render_tui_lines(
            snap,
            theme_slug=current_theme,
            width=term_cols,
            color=(sys.stdout.isatty() and not no_color_env),
            redact=redact,
            status_note=note,
            interactive_hint=False,
        )
        sys.stdout.write("\n".join(rendered) + "\n")
        sys.stdout.flush()
        return 0

    import termios
    import tty

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    selected_idx = 0
    guard_enabled = bool(auto_failover)
    status_note = (
        "Saved SVG to {}".format(export_svg)
        if export_svg
        else ("AutoGuard ON (watches Host quota and switches automatically)." if guard_enabled else "")
    )
    refresh_wait = max(0.4, float(interval_sec))

    sys.stdout.write("\x1b[?1049h\x1b[?25l")
    sys.stdout.flush()
    try:
        tty.setcbreak(fd)
        while True:
            if guard_enabled:
                try:
                    wd = poll_auto_failover_once(ctx, call_tool, launch=True)
                    if wd.get("switched_to"):
                        status_note = "AutoGuard switched quota onto {} ({})".format(
                            wd["switched_to"],
                            wd.get("reason") or "quota exhausted",
                        )
                except ToolError:
                    pass
            probe_snap = collect_tui_snapshot(ctx, selected_slot="host")
            slots: List[str] = probe_snap["slots"]
            if selected_idx >= len(slots):
                selected_idx = 0
            chosen_slot = slots[selected_idx]
            if chosen_slot != "host":
                snap = collect_tui_snapshot(ctx, selected_slot=chosen_slot)
            else:
                snap = probe_snap

            term_cols = width if width is not None else shutil.get_terminal_size((104, 32)).columns
            frame_lines = render_tui_lines(
                snap,
                theme_slug=current_theme,
                width=term_cols,
                color=not no_color_env,
                redact=redact,
                status_note=status_note,
                interactive_hint=True,
            )
            sys.stdout.write("\x1b[H" + "\n".join(frame_lines) + "\x1b[J")
            sys.stdout.flush()

            ready, _, _ = select.select([sys.stdin], [], [], refresh_wait)
            if not ready:
                continue

            ch = os.read(fd, 1).decode("utf-8", errors="ignore")
            if ch == "\x1b":
                # Handle arrow escape sequences (\x1b[A / \x1b[B)
                extra_ready, _, _ = select.select([sys.stdin], [], [], 0.03)
                if extra_ready:
                    seq = os.read(fd, 2).decode("utf-8", errors="ignore")
                    if seq == "[A":
                        selected_idx = (selected_idx - 1) % max(1, len(slots))
                    elif seq == "[B":
                        selected_idx = (selected_idx + 1) % max(1, len(slots))
                    continue
                break

            low = ch.lower()
            if low in ("q", "\x03", "\x04"):
                break
            if low in ("j",):
                selected_idx = (selected_idx + 1) % max(1, len(slots))
            elif low in ("k",):
                selected_idx = (selected_idx - 1) % max(1, len(slots))
            elif ch.isdigit() and int(ch) >= 1 and int(ch) <= len(slots):
                selected_idx = int(ch) - 1
            elif low == "t":
                next_idx = (THEME_ORDER.index(current_theme) + 1) % len(THEME_ORDER)
                current_theme = THEME_ORDER[next_idx]
                status_note = "Switched theme to {} ({})".format(
                    current_theme, THEMES[current_theme].label
                )
            elif low == "r":
                status_note = "Refreshed live process and SQLite telemetry."
            elif low == "a":
                guard_enabled = not guard_enabled
                status_note = "AutoGuard automatic quota failover: {}".format(
                    "ON" if guard_enabled else "OFF"
                )
            elif low == "e":
                svg_dest = Path.cwd() / "agyp-telemetry-{}.svg".format(current_theme)
                svg_cols = width if width is not None else max(96, min(112, term_cols))
                svg_txt = render_tui_svg(snap, theme_slug=current_theme, width=svg_cols, redact=redact)
                svg_dest.write_text(svg_txt, encoding="utf-8")
                status_note = "Exported X and GitHub SVG card: {}".format(svg_dest)
            elif low == "s":
                target_profile = chosen_slot if chosen_slot != "host" else (slots[1] if len(slots) > 1 else "")
                if not target_profile:
                    status_note = "Provision a backup profile first with: agyp create backup"
                else:
                    try:
                        res = call_tool(
                            "profile_sync",
                            {
                                "name": target_profile,
                                "automations_mode": "paused",
                                "include_handoff": True,
                                "include_sessions": True,
                            },
                            ctx,
                        )
                        sy = res["sync"]
                        status_note = "Synced {} projects, {} sessions, and {} paused automations into {}.".format(
                            sy["projects_synced"],
                            sy.get("sessions_synced", 0),
                            sy["automations_synced"],
                            target_profile,
                        )
                    except ToolError as exc:
                        status_note = "Sync error: {}".format(exc.message)
            elif low == "w":
                flow_info = snap["overview"].get("flow") or {}
                active_profs = flow_info.get("active_profiles") or []
                try:
                    if chosen_slot == "host" and active_profs:
                        ret = call_tool(
                            "profile_switch",
                            {
                                "name": "host",
                                "from_source": active_profs[0],
                                "include_sessions": True,
                                "copy_prompt": True,
                                "launch": True,
                            },
                            ctx,
                        )
                        ret_sess = (ret.get("sessions") or {}).get("synced_sessions", 0)
                        status_note = "Returned quota to Main Antigravity ({} sessions merged); paused {} automations.".format(
                            ret_sess,
                            active_profs[0],
                        )
                    else:
                        target_profile = chosen_slot if chosen_slot != "host" else (slots[1] if len(slots) > 1 else "")
                        if not target_profile:
                            status_note = "No backup profile available for quota switchover."
                        else:
                            sw_res = call_tool(
                                "profile_switch",
                                {
                                    "name": target_profile,
                                    "automations_mode": "active",
                                    "include_sessions": True,
                                    "copy_prompt": True,
                                    "launch": True,
                                },
                                ctx,
                            )
                            sw_sess = (sw_res.get("sync") or {}).get("sessions_synced", 0)
                            status_note = "Switched quota onto {} ({} sessions synced, prompt copied).".format(
                                target_profile,
                                sw_sess,
                            )
                except ToolError as exc:
                    status_note = "Switch error: {}".format(exc.message)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        sys.stdout.write("\x1b[?25h\x1b[?1049l")
        sys.stdout.flush()

    return 0
