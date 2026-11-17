//! Pure policy engine for CPU/GPU QoS pacing and orphaned runaway PID reaping.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    KeepProtected,
    KeepNormal,
    ReniceBatch { target_nice: i32, darwin_bg: bool, reason: &'static str },
    RecycleGpuHelper { reason: &'static str },
    ReapOrphan { sigkill: bool, reason: &'static str },
}

#[derive(Debug, Clone, Copy)]
pub struct EvalContext {
    pub self_pid: u32,
    pub ncpu: u32,
    pub load_1m: f64,
    pub vm_pressure_level: i32,
    pub owns_watchdog_lock: bool,
    pub now_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct CandidateProc {
    pub pid: u32,
    pub ppid: u32,
    pub start_tvsec: u64,
    pub age_secs: u64,
    pub nice: i32,
    pub rss_bytes: u64,
    pub cpu_pct: f64,
    pub comm: String,
    pub name: String,
    pub cmdline: String,
}

#[derive(Debug, Default)]
pub struct PolicyTracker {
    reniced_set: HashSet<(u32, u64)>,
    darwin_bg_set: HashSet<(u32, u64)>,
    sigterm_sent_at: HashMap<(u32, u64), u64>,
}

impl PolicyTracker {
    pub fn prune_dead(&mut self, live_identities: &HashSet<(u32, u64)>) {
        self.reniced_set.retain(|id| live_identities.contains(id));
        self.darwin_bg_set.retain(|id| live_identities.contains(id));
        self.sigterm_sent_at.retain(|id, _| live_identities.contains(id));
    }

    pub fn mark_reniced(&mut self, pid: u32, start_tvsec: u64, darwin_bg: bool) {
        self.reniced_set.insert((pid, start_tvsec));
        if darwin_bg {
            self.darwin_bg_set.insert((pid, start_tvsec));
        }
    }

    pub fn mark_sigterm(&mut self, pid: u32, start_tvsec: u64, now_epoch: u64) {
        self.sigterm_sent_at.entry((pid, start_tvsec)).or_insert(now_epoch);
    }
}

pub fn needs_cmdline_inspection(comm: &str, name: &str, ppid: u32, nice: i32) -> bool {
    if ppid == 1 {
        return true;
    }
    let lower_comm = comm.to_ascii_lowercase();
    let lower_name = name.to_ascii_lowercase();
    if is_batch_compiler_binary(&lower_comm, &lower_name) && nice < 10 {
        return true;
    }
    let inspect_tokens = [
        "python",
        "node",
        "bun",
        "deno",
        "chrome",
        "chromium",
        "ai-video-studio",
        "playwright",
        "ffmpeg",
        "ffprobe",
    ];
    inspect_tokens
        .iter()
        .any(|tok| lower_comm.contains(tok) || lower_name.contains(tok))
}

fn is_batch_compiler_binary(lower_comm: &str, lower_name: &str) -> bool {
    matches!(
        lower_comm,
        "rustc" | "cargo" | "clang" | "clang++" | "cc1" | "ld" | "lld" | "rust-lld" | "ffmpeg" | "ffprobe"
    ) || matches!(
        lower_name,
        "rustc" | "cargo" | "clang" | "clang++" | "cc1" | "ld" | "lld" | "rust-lld" | "ffmpeg" | "ffprobe"
    )
}

fn is_batch_node_build(lower_cmd: &str) -> bool {
    lower_cmd.contains("vite build")
        || lower_cmd.contains("tsc --noemit")
        || lower_cmd.contains("/esbuild")
        || lower_cmd.contains("remotion render")
}

pub fn is_protected_interactive(proc: &CandidateProc, self_pid: u32) -> bool {
    if proc.pid <= 1 || proc.pid == self_pid {
        return true;
    }
    let cmd = proc.cmdline.as_str();
    let lower_cmd = cmd.to_ascii_lowercase();
    let lower_name = proc.name.to_ascii_lowercase();

    if lower_cmd.contains("agyp-guard") || lower_name == "agyp-guard" {
        return true;
    }
    if lower_cmd.contains("caffeinate") {
        return true;
    }
    if (lower_cmd.contains("agy-profiles") || lower_cmd.contains("agyp"))
        && (lower_cmd.contains(" web") || lower_cmd.contains(" mcp") || lower_cmd.contains("--sidecar"))
    {
        return true;
    }
    if cmd.contains("/Applications/Antigravity.app/") || cmd.contains("/Applications/Antigravity IDE.app/") {
        return true;
    }
    if cmd.contains("/Applications/AI Video Studio.app/") && !lower_cmd.contains("--ui-shot") {
        return true;
    }
    if cmd.contains("/Applications/Google Chrome.app/")
        && !lower_cmd.contains("--headless")
        && !lower_cmd.contains("chrome for testing")
    {
        return true;
    }
    matches!(
        lower_name.as_str(),
        "windowserver" | "finder" | "dock" | "terminal" | "iterm2" | "ghostty" | "warp" | "loginwindow"
    )
}

fn classify_orphan_reap_reason(
    proc: &CandidateProc,
    vm_pressure_level: i32,
    owns_watchdog_lock: bool,
) -> Option<&'static str> {
    let lower_cmd = proc.cmdline.to_ascii_lowercase();

    // Legacy duplicate Python watchdog loop when Rust agyp-guard owns .watchdog.lock.
    if owns_watchdog_lock
        && (lower_cmd.contains("agyp ") || lower_cmd.contains("agy-profiles ") || lower_cmd.contains("agy_profiles"))
        && lower_cmd.contains(" watchdog")
        && !lower_cmd.contains("--once")
    {
        return Some("duplicate_python_watchdog");
    }

    if proc.ppid != 1 {
        return None;
    }

    // 1. Orphaned headless Metal GPU Studio screenshot tour (--ui-shot reparented to PID 1).
    if lower_cmd.contains("ai-video-studio") && lower_cmd.contains("--ui-shot") {
        let ttl = if vm_pressure_level >= 4 { 30 } else { 180 };
        if proc.age_secs >= ttl {
            return Some("orphaned_metal_ui_shot");
        }
    }

    // 2. Orphaned headless browser / Playwright / Chrome for Testing eating GPU/RAM.
    let is_headless_browser = lower_cmd.contains("--headless")
        || lower_cmd.contains("chrome-headless-shell")
        || (lower_cmd.contains("chrome for testing") && lower_cmd.contains("--remote-debugging"));
    if is_headless_browser {
        let ttl = if vm_pressure_level >= 4 {
            30
        } else if vm_pressure_level >= 2 {
            120
        } else {
            600
        };
        if proc.age_secs >= ttl {
            return Some("orphaned_headless_browser");
        }
    }

    // 3. Orphaned Node/Bun test worker spinning CPU or bloated RSS after parent exited.
    let is_test_worker = lower_cmd.contains("vitest")
        || lower_cmd.contains("jest-worker")
        || (lower_cmd.contains("@playwright/test") && !lower_cmd.contains("mcp"));
    if is_test_worker {
        let high_mem_or_cpu = proc.rss_bytes >= 512 * 1024 * 1024 || proc.cpu_pct >= 80.0;
        let ttl = if vm_pressure_level >= 2 && high_mem_or_cpu { 180 } else { 900 };
        if proc.age_secs >= ttl {
            return Some("orphaned_test_worker");
        }
    }

    None
}

pub fn evaluate_process(
    proc: &CandidateProc,
    ctx: &EvalContext,
    tracker: &PolicyTracker,
) -> GuardDecision {
    let id = (proc.pid, proc.start_tvsec);
    let lower_cmd = proc.cmdline.to_ascii_lowercase();

    // Proactively recycle bloated Electron Metal GPU compositor (> 3.5 GiB RSS) before black-screen swapchain corruption.
    if (proc.cmdline.contains("/Applications/Antigravity.app/")
        || proc.cmdline.contains("/Applications/Antigravity IDE.app/"))
        && lower_cmd.contains("--type=gpu-process")
        && proc.rss_bytes >= 3584 * 1024 * 1024
        && proc.age_secs >= 60
        && !tracker.sigterm_sent_at.contains_key(&id)
    {
        return GuardDecision::RecycleGpuHelper {
            reason: "bloated_electron_gpu_compositor",
        };
    }

    if is_protected_interactive(proc, ctx.self_pid) {
        return GuardDecision::KeepProtected;
    }

    if let Some(reason) = classify_orphan_reap_reason(proc, ctx.vm_pressure_level, ctx.owns_watchdog_lock) {
        let sigkill = match tracker.sigterm_sent_at.get(&id) {
            Some(&sent_at) => ctx.now_epoch.saturating_sub(sent_at) >= 3,
            None => false,
        };
        return GuardDecision::ReapOrphan { sigkill, reason };
    }

    let lower_comm = proc.comm.to_ascii_lowercase();
    let lower_name = proc.name.to_ascii_lowercase();

    let is_heavy_batch = is_batch_compiler_binary(&lower_comm, &lower_name) || is_batch_node_build(&lower_cmd);
    if is_heavy_batch {
        let heavy_pressure = ctx.vm_pressure_level >= 4 || ctx.load_1m >= (ctx.ncpu as f64) * 1.5;
        let already_reniced = tracker.reniced_set.contains(&id) || proc.nice >= 10;
        let already_bg = tracker.darwin_bg_set.contains(&id);

        if !already_reniced || (heavy_pressure && !already_bg) {
            return GuardDecision::ReniceBatch {
                target_nice: 10,
                darwin_bg: heavy_pressure,
                reason: if heavy_pressure {
                    "batch_compiler_efficiency_qos"
                } else {
                    "batch_compiler_nice_10"
                },
            };
        }
    }

    GuardDecision::KeepNormal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proc(pid: u32, ppid: u32, name: &str, cmdline: &str, age_secs: u64) -> CandidateProc {
        CandidateProc {
            pid,
            ppid,
            start_tvsec: 1_700_000_000,
            age_secs,
            nice: 0,
            rss_bytes: 200 * 1024 * 1024,
            cpu_pct: 15.0,
            comm: name.to_string(),
            name: name.to_string(),
            cmdline: cmdline.to_string(),
        }
    }

    fn ctx(load_1m: f64, vm_pressure_level: i32, now_epoch: u64) -> EvalContext {
        EvalContext {
            self_pid: 99,
            ncpu: 12,
            load_1m,
            vm_pressure_level,
            owns_watchdog_lock: true,
            now_epoch,
        }
    }

    #[test]
    fn protects_antigravity_chrome_and_interactive_studio_and_recycles_bloated_gpu_helper() {
        let tracker = PolicyTracker::default();
        let hub = sample_proc(
            500,
            1,
            "Antigravity",
            "/Applications/Antigravity.app/Contents/MacOS/Antigravity",
            86_400,
        );
        assert_eq!(
            evaluate_process(&hub, &ctx(4.0, 4, 1_700_086_400), &tracker),
            GuardDecision::KeepProtected
        );

        let chrome = sample_proc(
            725,
            1,
            "Google Chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            86_400,
        );
        assert_eq!(
            evaluate_process(&chrome, &ctx(4.0, 4, 1_700_086_400), &tracker),
            GuardDecision::KeepProtected
        );

        let studio = sample_proc(
            900,
            1,
            "ai-video-studio",
            "/Applications/AI Video Studio.app/Contents/MacOS/ai-video-studio",
            3600,
        );
        assert_eq!(
            evaluate_process(&studio, &ctx(4.0, 4, 1_700_003_600), &tracker),
            GuardDecision::KeepProtected
        );

        let mut bloated_gpu = sample_proc(
            512,
            500,
            "Antigravity Helper (GPU)",
            "/Applications/Antigravity.app/Contents/Frameworks/Antigravity Helper.app/Contents/MacOS/Antigravity Helper --type=gpu-process",
            600,
        );
        bloated_gpu.rss_bytes = 4 * 1024 * 1024 * 1024;
        assert_eq!(
            evaluate_process(&bloated_gpu, &ctx(4.0, 2, 1_700_000_600), &tracker),
            GuardDecision::RecycleGpuHelper {
                reason: "bloated_electron_gpu_compositor"
            }
        );
    }

    #[test]
    fn renices_rustc_and_escalates_to_darwin_bg_under_heavy_load() {
        let mut tracker = PolicyTracker::default();
        let rustc = sample_proc(
            77665,
            77644,
            "rustc",
            "/Users/dev/.rustup/toolchains/stable/bin/rustc --crate-name demo",
            8,
        );
        let d1 = evaluate_process(&rustc, &ctx(6.0, 1, 1_700_000_008), &tracker);
        assert_eq!(
            d1,
            GuardDecision::ReniceBatch {
                target_nice: 10,
                darwin_bg: false,
                reason: "batch_compiler_nice_10",
            }
        );
        tracker.mark_reniced(rustc.pid, rustc.start_tvsec, false);
        assert_eq!(
            evaluate_process(&rustc, &ctx(6.0, 1, 1_700_000_011), &tracker),
            GuardDecision::KeepNormal
        );

        let d2 = evaluate_process(&rustc, &ctx(20.5, 2, 1_700_000_014), &tracker);
        assert_eq!(
            d2,
            GuardDecision::ReniceBatch {
                target_nice: 10,
                darwin_bg: true,
                reason: "batch_compiler_efficiency_qos",
            }
        );
    }

    #[test]
    fn reaps_orphaned_headless_browser_and_ui_shot_with_staged_sigkill() {
        let mut tracker = PolicyTracker::default();
        let orphan_chrome = sample_proc(
            4100,
            1,
            "chrome-headless-shell",
            "/cache/chrome-headless-shell --headless --remote-debugging-pipe",
            150,
        );
        let d1 = evaluate_process(&orphan_chrome, &ctx(5.0, 2, 1_700_000_150), &tracker);
        assert_eq!(
            d1,
            GuardDecision::ReapOrphan {
                sigkill: false,
                reason: "orphaned_headless_browser",
            }
        );
        tracker.mark_sigterm(orphan_chrome.pid, orphan_chrome.start_tvsec, 1_700_000_150);

        let d2 = evaluate_process(&orphan_chrome, &ctx(5.0, 2, 1_700_000_154), &tracker);
        assert_eq!(
            d2,
            GuardDecision::ReapOrphan {
                sigkill: true,
                reason: "orphaned_headless_browser",
            }
        );

        let active_headless = sample_proc(
            4101,
            4050,
            "chrome-headless-shell",
            "/cache/chrome-headless-shell --headless",
            300,
        );
        assert_eq!(
            evaluate_process(&active_headless, &ctx(5.0, 2, 1_700_000_300), &tracker),
            GuardDecision::KeepNormal
        );
    }
}
