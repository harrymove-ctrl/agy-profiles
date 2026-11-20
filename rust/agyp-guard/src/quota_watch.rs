//! Zero-Python-overhead transcript and Hub log byte offset scanner triggering `agyp watchdog --once`.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

const AUTH_REFRESH_MARKER: &str = "auth succeeded, refreshing features and managers";

const QUOTA_MARKERS: &[&str] = &[
    "resource_exhausted",
    "individual quota reached",
    "429 too many requests",
    "quota exceeded",
    "insufficient_quota",
    "ratelimitexceeded",
    "credit balance is too low",
    "run out of credit",
    "exhausted your capacity",
    "stream idle timeout",
    "context deadline exceeded",
    "encountered an error and has either stopped",
    "failed to construct executor",
    "unknown model key",
    "you are not logged into antigravity",
    "agent execution terminated due to error",
    "stream reading error",
    "http2: server sent goaway",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSignal {
    pub marker: String,
    pub is_auth_refresh: bool,
}

#[derive(Default)]
pub struct TranscriptLogScanner {
    offsets: HashMap<PathBuf, u64>,
    initialized: bool,
}

impl TranscriptLogScanner {
    fn discover_watched_logs(host_home: &Path, profiles_root: &Path) -> Vec<PathBuf> {
        let mut logs = Vec::new();
        Self::collect_brain_logs(&host_home.join(".gemini").join("antigravity").join("brain"), &mut logs);
        let host_ls_log = host_home
            .join("Library")
            .join("Logs")
            .join("Antigravity")
            .join("language_server.log");
        if host_ls_log.is_file() {
            logs.push(host_ls_log);
        }
        if let Ok(entries) = fs::read_dir(profiles_root) {
            for entry in entries.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with('.') || name_str == "logs" {
                    continue;
                }
                let prof_home = p.join("home");
                let brain_dir = prof_home.join(".gemini").join("antigravity").join("brain");
                Self::collect_brain_logs(&brain_dir, &mut logs);
                let prof_ls_log = prof_home
                    .join("Library")
                    .join("Logs")
                    .join("Antigravity")
                    .join("language_server.log");
                if prof_ls_log.is_file() {
                    logs.push(prof_ls_log);
                }
            }
        }
        logs
    }

    fn collect_brain_logs(brain_dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(conv_dirs) = fs::read_dir(brain_dir) else {
            return;
        };
        for entry in conv_dirs.flatten() {
            let log_path = entry
                .path()
                .join(".system_generated")
                .join("logs")
                .join("transcript.jsonl");
            if log_path.is_file() {
                out.push(log_path);
            }
        }
    }

    /// Scan appended bytes across transcript and Hub logs. First pass records current EOF offsets without triggering.
    pub fn poll_for_quota_signal(&mut self, host_home: &Path, profiles_root: &Path) -> Option<LogSignal> {
        let paths = Self::discover_watched_logs(host_home, profiles_root);
        if !self.initialized {
            for p in paths {
                if let Ok(meta) = fs::metadata(&p) {
                    self.offsets.insert(p, meta.len());
                }
            }
            self.initialized = true;
            return None;
        }

        let mut matched_signal: Option<LogSignal> = None;
        for p in paths {
            let Ok(meta) = fs::metadata(&p) else {
                continue;
            };
            let len = meta.len();
            let prev = match self.offsets.get(&p).copied() {
                Some(off) if len >= off => off,
                Some(_) => len.saturating_sub(64 * 1024),
                None => len.saturating_sub(64 * 1024),
            };
            if len == prev {
                self.offsets.insert(p, len);
                continue;
            }
            let read_from = prev.max(len.saturating_sub(256 * 1024));
            if let Ok(mut fh) = File::open(&p) {
                if fh.seek(SeekFrom::Start(read_from)).is_ok() {
                    let mut buf = Vec::with_capacity((len - read_from) as usize);
                    if fh.read_to_end(&mut buf).is_ok() {
                        let chunk = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                        if chunk.contains(AUTH_REFRESH_MARKER) {
                            matched_signal = Some(LogSignal {
                                marker: AUTH_REFRESH_MARKER.to_string(),
                                is_auth_refresh: true,
                            });
                        } else if matched_signal.is_none() {
                            for &marker in QUOTA_MARKERS {
                                if chunk.contains(marker) {
                                    matched_signal = Some(LogSignal {
                                        marker: marker.to_string(),
                                        is_auth_refresh: false,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            self.offsets.insert(p, len);
        }
        matched_signal
    }
}

pub fn invoke_python_failover_once(agyp_bin: &Path, profiles_root: &Path) -> bool {
    if !agyp_bin.is_file() {
        return false;
    }
    let status = Command::new(agyp_bin)
        .arg("--root")
        .arg(profiles_root)
        .arg("watchdog")
        .arg("--once")
        .arg("--json")
        .status();
    matches!(status, Ok(st) if st.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_newly_appended_quota_marker_only_after_baseline() {
        let tmp = std::env::temp_dir().join(format!("agyp_guard_test_{}", std::process::id()));
        let log_dir = tmp
            .join("home")
            .join(".gemini")
            .join("antigravity")
            .join("brain")
            .join("conv-1")
            .join(".system_generated")
            .join("logs");
        let root_dir = tmp.join("profiles");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&log_dir).unwrap();
        fs::create_dir_all(&root_dir).unwrap();

        let log_file = log_dir.join("transcript.jsonl");
        fs::write(&log_file, "{\"content\":\"RESOURCE_EXHAUSTED old\"}\n").unwrap();

        let mut scanner = TranscriptLogScanner::default();
        // Baseline initialization ignores historical markers.
        assert_eq!(scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir), None);
        // No new bytes -> None.
        assert_eq!(scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir), None);

        // Append fresh 429 marker -> detected!
        let mut fh = fs::OpenOptions::new().append(true).open(&log_file).unwrap();
        writeln!(fh, "{{\"error\":\"429 Too Many Requests\"}}").unwrap();
        fh.flush().unwrap();

        let hit = scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir);
        assert_eq!(
            hit,
            Some(LogSignal {
                marker: "429 too many requests".to_string(),
                is_auth_refresh: false,
            })
        );
        // Subsequent poll without new bytes -> None.
        assert_eq!(scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir), None);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn detects_auth_refresh_and_model_errors_in_language_server_log() {
        let tmp = std::env::temp_dir().join(format!("agyp_guard_ls_test_{}", std::process::id()));
        let ls_dir = tmp.join("home").join("Library").join("Logs").join("Antigravity");
        let root_dir = tmp.join("profiles");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&ls_dir).unwrap();
        fs::create_dir_all(&root_dir).unwrap();

        let ls_log = ls_dir.join("language_server.log");
        fs::write(
            &ls_log,
            "E1120 01:00:00 errorreport.go:273] failed to construct executor: unknown model key MODEL_PLACEHOLDER_M532\n",
        )
        .unwrap();

        let mut scanner = TranscriptLogScanner::default();
        // Historical lines at boot are ignored.
        assert_eq!(scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir), None);

        // Fresh executor model error is detected cleanly.
        let mut fh = fs::OpenOptions::new().append(true).open(&ls_log).unwrap();
        writeln!(
            fh,
            "E1120 11:45:42 errorreport.go:273] failed to construct executor: unknown model key MODEL_PLACEHOLDER_M532: model not found"
        )
        .unwrap();
        fh.flush().unwrap();

        let err_hit = scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir);
        assert_eq!(
            err_hit,
            Some(LogSignal {
                marker: "failed to construct executor".to_string(),
                is_auth_refresh: false,
            })
        );

        // Auth refresh marker triggers is_auth_refresh = true so caller schedules post-login settle recovery.
        writeln!(
            fh,
            "I1120 11:45:44 server.go:4464] Auth succeeded, refreshing features and managers"
        )
        .unwrap();
        fh.flush().unwrap();

        let auth_hit = scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir);
        assert_eq!(
            auth_hit,
            Some(LogSignal {
                marker: "auth succeeded, refreshing features and managers".to_string(),
                is_auth_refresh: true,
            })
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
