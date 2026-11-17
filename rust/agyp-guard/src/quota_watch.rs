//! Zero-Python-overhead transcript byte offset scanner triggering `agyp watchdog --once` only on new quota events.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

const QUOTA_MARKERS: &[&str] = &[
    "resource_exhausted",
    "429 too many requests",
    "quota exceeded",
    "insufficient_quota",
    "ratelimitexceeded",
    "credit balance is too low",
    "run out of credit",
    "exhausted your capacity",
];

#[derive(Default)]
pub struct TranscriptLogScanner {
    offsets: HashMap<PathBuf, u64>,
    initialized: bool,
}

impl TranscriptLogScanner {
    fn discover_transcript_logs(host_home: &Path, profiles_root: &Path) -> Vec<PathBuf> {
        let mut logs = Vec::new();
        Self::collect_brain_logs(&host_home.join(".gemini").join("antigravity").join("brain"), &mut logs);
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
                let brain_dir = p.join("home").join(".gemini").join("antigravity").join("brain");
                Self::collect_brain_logs(&brain_dir, &mut logs);
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

    /// Scan appended bytes across transcript logs. First pass records current EOF offsets without triggering.
    pub fn poll_for_quota_signal(&mut self, host_home: &Path, profiles_root: &Path) -> Option<String> {
        let paths = Self::discover_transcript_logs(host_home, profiles_root);
        if !self.initialized {
            for p in paths {
                if let Ok(meta) = fs::metadata(&p) {
                    self.offsets.insert(p, meta.len());
                }
            }
            self.initialized = true;
            return None;
        }

        let mut matched_marker: Option<String> = None;
        for p in paths {
            let Ok(meta) = fs::metadata(&p) else {
                continue;
            };
            let len = meta.len();
            let prev = self.offsets.get(&p).copied().unwrap_or(len);
            if len <= prev {
                self.offsets.insert(p, len);
                continue;
            }
            let read_from = prev.max(len.saturating_sub(256 * 1024));
            if let Ok(mut fh) = File::open(&p) {
                if fh.seek(SeekFrom::Start(read_from)).is_ok() {
                    let mut buf = Vec::with_capacity((len - read_from) as usize);
                    if fh.read_to_end(&mut buf).is_ok() {
                        let chunk = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                        for &marker in QUOTA_MARKERS {
                            if chunk.contains(marker) && matched_marker.is_none() {
                                matched_marker = Some(marker.to_string());
                            }
                        }
                    }
                }
            }
            self.offsets.insert(p, len);
        }
        matched_marker
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
        assert_eq!(hit.as_deref(), Some("429 too many requests"));
        // Subsequent poll without new bytes -> None.
        assert_eq!(scanner.poll_for_quota_signal(&tmp.join("home"), &root_dir), None);

        let _ = fs::remove_dir_all(&tmp);
    }
}
