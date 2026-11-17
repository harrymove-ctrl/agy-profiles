//! Native Apple Silicon CPU, GPU, Unified Memory, and PID guardian daemon for agy-profiles.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod ffi;
mod policy;
mod quota_watch;

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use policy::{
    evaluate_process, needs_cmdline_inspection, CandidateProc, EvalContext, GuardDecision,
    PolicyTracker,
};
use quota_watch::{invoke_python_failover_once, TranscriptLogScanner};

const TELEMETRY_FILENAME: &str = ".guard-telemetry.json";
const LOCK_FILENAME: &str = ".watchdog.lock";

struct GuardRuntime {
    uid: u32,
    self_pid: u32,
    cmdline_cache: HashMap<(u32, u64), String>,
    cpu_sample_cache: HashMap<(u32, u64), (u64, Instant)>,
    tracker: PolicyTracker,
    scanner: TranscriptLogScanner,
    total_reniced: u64,
    total_reaped: u64,
    total_quota_triggers: u64,
    recent_events: Vec<String>,
}

#[derive(Debug)]
struct SweepReport {
    checked_at_epoch: u64,
    ncpu: u32,
    mem_total_mb: u64,
    vm_pressure_level: i32,
    vm_pressure_label: &'static str,
    load_1m: f64,
    load_5m: f64,
    load_15m: f64,
    total_pids: usize,
    user_pids: usize,
    gpu_window_rss_mb: u64,
    reniced_this_sweep: usize,
    reaped_this_sweep: usize,
    total_reniced: u64,
    total_reaped: u64,
    total_quota_triggers: u64,
    sweep_duration_us: u64,
    recent_events: Vec<String>,
}

impl GuardRuntime {
    fn new() -> Self {
        Self {
            uid: ffi::current_uid(),
            self_pid: ffi::current_pid(),
            cmdline_cache: HashMap::new(),
            cpu_sample_cache: HashMap::new(),
            tracker: PolicyTracker::default(),
            scanner: TranscriptLogScanner::default(),
            total_reniced: 0,
            total_reaped: 0,
            total_quota_triggers: 0,
            recent_events: Vec::new(),
        }
    }

    fn push_event(&mut self, msg: String) {
        if self.recent_events.len() >= 12 {
            self.recent_events.remove(0);
        }
        self.recent_events.push(msg);
    }

    fn run_sweep(
        &mut self,
        host_home: &Path,
        profiles_root: &Path,
        agyp_bin: &Path,
        owns_watchdog_lock: bool,
    ) -> SweepReport {
        let t0 = Instant::now();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let all_pids = ffi::list_all_pids();
        let metrics = ffi::read_host_metrics(all_pids.len());
        let now_inst = Instant::now();

        let mut live_ids: HashSet<(u32, u64)> = HashSet::with_capacity(all_pids.len());
        let mut user_pids: usize = 0;
        let mut gpu_window_rss_bytes: u64 = 0;
        let mut reniced_now: usize = 0;
        let mut reaped_now: usize = 0;

        for raw_pid in all_pids {
            let Some(basic) = ffi::inspect_pid_basic(raw_pid) else {
                continue;
            };
            let id = (basic.pid, basic.start_tvsec);
            live_ids.insert(id);

            let lower_name = basic.name.to_ascii_lowercase();
            if lower_name.contains("gpu") || lower_name == "windowserver" || lower_name == "ai-video-studio" {
                gpu_window_rss_bytes = gpu_window_rss_bytes.saturating_add(basic.rss_bytes);
            }

            if basic.uid != self.uid {
                continue;
            }
            user_pids += 1;

            let cpu_pct = if let Some(&(prev_ns, prev_t)) = self.cpu_sample_cache.get(&id) {
                let dt_ns = now_inst.duration_since(prev_t).as_nanos() as f64;
                if dt_ns > 1_000_000.0 && basic.cpu_total_ns >= prev_ns {
                    ((basic.cpu_total_ns - prev_ns) as f64 / dt_ns) * 100.0
                } else {
                    0.0
                }
            } else {
                0.0
            };
            self.cpu_sample_cache.insert(id, (basic.cpu_total_ns, now_inst));

            let cmdline = if let Some(cached) = self.cmdline_cache.get(&id) {
                cached.clone()
            } else if needs_cmdline_inspection(&basic.comm, &basic.name, basic.ppid, basic.nice) {
                let fetched = ffi::read_pid_cmdline(basic.pid).unwrap_or_else(|| basic.name.clone());
                self.cmdline_cache.insert(id, fetched.clone());
                fetched
            } else {
                basic.name.clone()
            };

            let age_secs = now_epoch.saturating_sub(basic.start_tvsec);
            let candidate = CandidateProc {
                pid: basic.pid,
                ppid: basic.ppid,
                start_tvsec: basic.start_tvsec,
                age_secs,
                nice: basic.nice,
                rss_bytes: basic.rss_bytes,
                cpu_pct,
                comm: basic.comm,
                name: basic.name,
                cmdline,
            };

            let eval_ctx = EvalContext {
                self_pid: self.self_pid,
                ncpu: metrics.ncpu,
                load_1m: metrics.load_1m,
                vm_pressure_level: metrics.vm_pressure_level,
                owns_watchdog_lock,
                now_epoch,
            };

            match evaluate_process(&candidate, &eval_ctx, &self.tracker) {
                GuardDecision::KeepProtected | GuardDecision::KeepNormal => {}
                GuardDecision::ReniceBatch {
                    target_nice,
                    darwin_bg,
                    reason,
                } => {
                    let ok_nice = ffi::renice_process(candidate.pid, target_nice);
                    let ok_bg = if darwin_bg {
                        ffi::set_darwin_background_qos(candidate.pid)
                    } else {
                        false
                    };
                    if ok_nice || ok_bg {
                        self.tracker.mark_reniced(candidate.pid, candidate.start_tvsec, darwin_bg);
                        reniced_now += 1;
                        self.total_reniced += 1;
                        self.push_event(format!(
                            "{}: paced pid={} ({}) via {}",
                            now_epoch, candidate.pid, candidate.name, reason
                        ));
                    }
                }
                GuardDecision::RecycleGpuHelper { reason } => {
                    if ffi::send_process_signal(candidate.pid, ffi::SIGTERM) {
                        self.tracker.mark_sigterm(candidate.pid, candidate.start_tvsec, now_epoch);
                        reaped_now += 1;
                        self.total_reaped += 1;
                        self.push_event(format!(
                            "{}: recycled bloated GPU helper pid={} ({}) ({})",
                            now_epoch, candidate.pid, candidate.name, reason
                        ));
                    }
                }
                GuardDecision::ReapOrphan { sigkill, reason } => {
                    let sig = if sigkill { ffi::SIGKILL } else { ffi::SIGTERM };
                    if ffi::send_process_signal(candidate.pid, sig) {
                        self.tracker.mark_sigterm(candidate.pid, candidate.start_tvsec, now_epoch);
                        reaped_now += 1;
                        self.total_reaped += 1;
                        let sig_name = if sigkill { "SIGKILL" } else { "SIGTERM" };
                        self.push_event(format!(
                            "{}: reaped pid={} ({}) with {} ({})",
                            now_epoch, candidate.pid, candidate.name, sig_name, reason
                        ));
                    }
                }
            }
        }

        self.cmdline_cache.retain(|id, _| live_ids.contains(id));
        self.cpu_sample_cache.retain(|id, _| live_ids.contains(id));
        self.tracker.prune_dead(&live_ids);

        if owns_watchdog_lock {
            if let Some(marker) = self.scanner.poll_for_quota_signal(host_home, profiles_root) {
                self.total_quota_triggers += 1;
                let ok = invoke_python_failover_once(agyp_bin, profiles_root);
                self.push_event(format!(
                    "{}: quota marker '{}' triggered failover (ok={})",
                    now_epoch, marker, ok
                ));
            }
        }

        let vm_label = match metrics.vm_pressure_level {
            1 => "normal",
            2 => "warn",
            4 => "critical",
            _ => "unknown",
        };

        SweepReport {
            checked_at_epoch: now_epoch,
            ncpu: metrics.ncpu,
            mem_total_mb: metrics.mem_total_bytes / (1024 * 1024),
            vm_pressure_level: metrics.vm_pressure_level,
            vm_pressure_label: vm_label,
            load_1m: metrics.load_1m,
            load_5m: metrics.load_5m,
            load_15m: metrics.load_15m,
            total_pids: metrics.total_pids,
            user_pids,
            gpu_window_rss_mb: gpu_window_rss_bytes / (1024 * 1024),
            reniced_this_sweep: reniced_now,
            reaped_this_sweep: reaped_now,
            total_reniced: self.total_reniced,
            total_reaped: self.total_reaped,
            total_quota_triggers: self.total_quota_triggers,
            sweep_duration_us: t0.elapsed().as_micros() as u64,
            recent_events: self.recent_events.clone(),
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn render_report_json(r: &SweepReport, pid: u32) -> String {
    let events_json: Vec<String> = r
        .recent_events
        .iter()
        .map(|e| format!("\"{}\"", json_escape(e)))
        .collect();
    format!(
        concat!(
            "{{\n",
            "  \"engine\": \"rust-agyp-guard\",\n",
            "  \"guard_pid\": {},\n",
            "  \"checked_at_epoch\": {},\n",
            "  \"ncpu\": {},\n",
            "  \"mem_total_mb\": {},\n",
            "  \"vm_pressure_level\": {},\n",
            "  \"vm_pressure_label\": \"{}\",\n",
            "  \"load_avg\": [{:.2}, {:.2}, {:.2}],\n",
            "  \"total_pids\": {},\n",
            "  \"user_pids\": {},\n",
            "  \"gpu_window_rss_mb\": {},\n",
            "  \"reniced_this_sweep\": {},\n",
            "  \"reaped_this_sweep\": {},\n",
            "  \"total_reniced\": {},\n",
            "  \"total_reaped\": {},\n",
            "  \"total_quota_triggers\": {},\n",
            "  \"sweep_duration_us\": {},\n",
            "  \"recent_events\": [{}]\n",
            "}}\n"
        ),
        pid,
        r.checked_at_epoch,
        r.ncpu,
        r.mem_total_mb,
        r.vm_pressure_level,
        r.vm_pressure_label,
        r.load_1m,
        r.load_5m,
        r.load_15m,
        r.total_pids,
        r.user_pids,
        r.gpu_window_rss_mb,
        r.reniced_this_sweep,
        r.reaped_this_sweep,
        r.total_reniced,
        r.total_reaped,
        r.total_quota_triggers,
        r.sweep_duration_us,
        events_json.join(", ")
    )
}

fn write_telemetry_atomic(profiles_root: &Path, json_body: &str) {
    let _ = fs::create_dir_all(profiles_root);
    let tmp_path = profiles_root.join(".guard-telemetry.json.tmp");
    let dst_path = profiles_root.join(TELEMETRY_FILENAME);
    if let Ok(mut fh) = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)
    {
        if fh.write_all(json_body.as_bytes()).is_ok() && fh.sync_all().is_ok() {
            let _ = fs::rename(tmp_path, dst_path);
        }
    }
}

fn default_profiles_root(home: &Path) -> PathBuf {
    if let Ok(env_dir) = env::var("AGY_PROFILES_DIR") {
        if !env_dir.trim().is_empty() {
            return PathBuf::from(env_dir.trim());
        }
    }
    let dev_root = PathBuf::from("/Volumes/Dev/.antigravity-profiles");
    if dev_root.exists() {
        return dev_root;
    }
    home.join(".antigravity-profiles")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let home = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    let mut mode = "daemon".to_string();
    let mut root = default_profiles_root(&home);
    let mut agyp_bin = home.join(".local").join("bin").join("agyp");
    let mut interval_secs: f64 = 3.0;
    let mut as_json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "daemon" | "once" | "status" => {
                mode = args[i].clone();
                i += 1;
            }
            "--root" if i + 1 < args.len() => {
                root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--agyp" if i + 1 < args.len() => {
                agyp_bin = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--interval" if i + 1 < args.len() => {
                interval_secs = args[i + 1].parse::<f64>().unwrap_or(3.0).max(1.0);
                i += 2;
            }
            "--json" => {
                as_json = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if mode == "status" {
        let tele_path = root.join(TELEMETRY_FILENAME);
        if let Ok(raw) = fs::read_to_string(&tele_path) {
            print!("{}", raw);
            return;
        }
        let mut rt = GuardRuntime::new();
        let rep = rt.run_sweep(&home, &root, &agyp_bin, false);
        print!("{}", render_report_json(&rep, rt.self_pid));
        return;
    }

    if mode == "once" {
        let mut rt = GuardRuntime::new();
        let rep = rt.run_sweep(&home, &root, &agyp_bin, false);
        let body = render_report_json(&rep, rt.self_pid);
        write_telemetry_atomic(&root, &body);
        if as_json {
            print!("{}", body);
        } else {
            println!(
                "agyp-guard (Rust): pids={}/{} load={:.2} vm_pressure={} gpu_rss={}MB reniced={} reaped={} ({}us)",
                rep.user_pids,
                rep.total_pids,
                rep.load_1m,
                rep.vm_pressure_label,
                rep.gpu_window_rss_mb,
                rep.reniced_this_sweep,
                rep.reaped_this_sweep,
                rep.sweep_duration_us
            );
        }
        return;
    }

    let _ = fs::create_dir_all(&root);
    let lock_path = root.join(LOCK_FILENAME);
    let Ok(mut lock_file) = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
    else {
        eprintln!("agyp-guard: unable to open lock file {}", lock_path.display());
        return;
    };
    if !ffi::acquire_exclusive_flock(&lock_file) {
        println!("agyp-guard: another guardian instance holds {}; exiting cleanly.", lock_path.display());
        return;
    }
    let self_pid = ffi::current_pid();
    let _ = lock_file.set_len(0);
    let _ = writeln!(lock_file, "{}", self_pid);
    let _ = lock_file.flush();

    println!(
        "AGY Profiles Rust Guardian (agyp-guard pid={}) active every {:.1}s (zero-fork libproc + CPU/GPU QoS).",
        self_pid, interval_secs
    );

    let mut rt = GuardRuntime::new();
    let sleep_dur = Duration::from_secs_f64(interval_secs);
    loop {
        let rep = rt.run_sweep(&home, &root, &agyp_bin, true);
        let body = render_report_json(&rep, self_pid);
        write_telemetry_atomic(&root, &body);
        if rep.reniced_this_sweep > 0 || rep.reaped_this_sweep > 0 {
            println!(
                "[{}] paced={} reaped={} pids={} load={:.2} vm={} ({}us)",
                rep.checked_at_epoch,
                rep.reniced_this_sweep,
                rep.reaped_this_sweep,
                rep.total_pids,
                rep.load_1m,
                rep.vm_pressure_label,
                rep.sweep_duration_us
            );
        }
        thread::sleep(sleep_dur);
    }
}
