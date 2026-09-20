// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Process log output with Go-compatible file rotation (CP-ADMIN B0).
//!
//! Every structured log line in the Rust process goes through [`emit_line`].
//! Without a configured file the line is written to stderr, as before. With
//! `log.log-file.filename` set, lines go to that file and rotate exactly like
//! the Go `lumberjack` writer `TiProxy` uses: a write that would exceed
//! `max-size` megabytes first renames the current file to
//! `<name>-<timestamp><ext>` and starts a new one, then prunes backups beyond
//! `max-backups` and older than `max-days`. The backup timestamp uses the same
//! `2006-01-02T15-04-05.000` layout in local time (`LocalTime: true` in the
//! Go configuration), read through `chrono::Local`.
//! Reconfiguration is atomic per line: a reload swaps the writer between two
//! lines and never drops or duplicates one.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

/// `max-size` used when the configuration leaves it at zero (Go default).
pub const DEFAULT_MAX_SIZE_MB: u64 = 300;
const MEGABYTE: u64 = 1024 * 1024;
const BACKUP_TIMESTAMP_LEN: usize = "2006-01-02T15-04-05.000".len();
const BACKUP_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H-%M-%S%.3f";

/// Log file settings mirroring `log.log-file.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogFileSettings {
    /// Log file path; the process writes and rotates this file.
    pub filename: PathBuf,
    /// Rotate when the file would exceed this many megabytes; zero means the
    /// Go default of 300.
    pub max_size_mb: u64,
    /// Delete backups whose rotation timestamp is older than this many days;
    /// zero disables age pruning.
    pub max_days: u64,
    /// Keep at most this many backups; zero keeps all.
    pub max_backups: u64,
}

enum Output {
    Stderr,
    File(RotatingFile),
}

static OUTPUT: OnceLock<Mutex<Output>> = OnceLock::new();

fn output() -> &'static Mutex<Output> {
    OUTPUT.get_or_init(|| Mutex::new(Output::Stderr))
}

/// Writes one log line (a newline is appended) to the configured output. A
/// file write failure falls back to stderr for that line so the event is
/// never silently lost; the file stays configured for the next line.
pub fn emit_line(line: &str) {
    let mut guard = output()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &mut *guard {
        Output::Stderr => eprintln!("{line}"),
        Output::File(file) => {
            if file.write_line(line).is_err() {
                eprintln!("{line}");
            }
        }
    }
}

/// Switches the process log output: `None` restores stderr, `Some` opens (or
/// reopens) the rotating file. Returns the open error and leaves the previous
/// output in place when the file cannot be opened.
///
/// # Errors
///
/// Returns a diagnostic when the log directory or file cannot be opened.
pub fn configure(settings: Option<&LogFileSettings>) -> Result<(), String> {
    // Open, rotate, and prune under the same lock that serializes writes, so
    // the previous writer can never append to a file this call has just
    // renamed or removed.
    let mut guard = output()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let next = match settings {
        None => Output::Stderr,
        Some(settings) => Output::File(RotatingFile::open(settings)?),
    };
    *guard = next;
    Ok(())
}

/// Size-rotated log file with lumberjack-compatible naming and pruning.
struct RotatingFile {
    path: PathBuf,
    dir: PathBuf,
    prefix: String,
    ext: String,
    file: Option<File>,
    size: u64,
    max_bytes: u64,
    max_days: u64,
    max_backups: u64,
}

impl RotatingFile {
    fn open(settings: &LogFileSettings) -> Result<Self, String> {
        let path = settings.filename.clone();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err("log file name must be a valid UTF-8 file name".to_owned());
        };
        if path.is_dir() {
            return Err("can't use directory as log file name".to_owned());
        }
        let (prefix, ext) = match name.rfind('.') {
            Some(index) if index > 0 => (name[..index].to_owned(), name[index..].to_owned()),
            _ => (name.to_owned(), String::new()),
        };
        let max_size_mb = if settings.max_size_mb == 0 {
            DEFAULT_MAX_SIZE_MB
        } else {
            settings.max_size_mb
        };
        let mut file = Self {
            dir: parent_dir(&path),
            path,
            prefix,
            ext,
            file: None,
            size: 0,
            max_bytes: max_size_mb.saturating_mul(MEGABYTE),
            max_days: settings.max_days,
            max_backups: settings.max_backups,
        };
        file.open_existing_or_new()
            .map_err(|error| format!("open log file {}: {error}", file.path.display()))?;
        Ok(file)
    }

    /// Mirrors lumberjack `openExistingOrNew`: prune first, then append to an
    /// existing file below the limit or rotate/create one.
    fn open_existing_or_new(&mut self) -> std::io::Result<()> {
        self.mill();
        match fs::metadata(&self.path) {
            Ok(info) => {
                if info.len() >= self.max_bytes {
                    return self.rotate();
                }
                match OpenOptions::new().append(true).open(&self.path) {
                    Ok(file) => {
                        self.file = Some(file);
                        self.size = info.len();
                        Ok(())
                    }
                    Err(_) => self.open_new(),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.open_new(),
            Err(error) => Err(error),
        }
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let write_len = line.len() as u64 + 1;
        if write_len > self.max_bytes {
            return Err(std::io::Error::other(format!(
                "write length {write_len} exceeds maximum file size {}",
                self.max_bytes
            )));
        }
        if self.file.is_none() {
            self.open_existing_or_new()?;
        }
        if self.size + write_len > self.max_bytes {
            self.rotate()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("log file is not open"));
        };
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        self.size += write_len;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file = None;
        self.open_new()?;
        self.mill();
        Ok(())
    }

    /// Mirrors lumberjack `openNew`: rename the existing file to its backup
    /// name (keeping its mode for the replacement) and create a fresh one.
    fn open_new(&mut self) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut mode = 0o600;
        if let Ok(info) = fs::metadata(&self.path) {
            mode = info.permissions().mode() & 0o777;
            fs::rename(&self.path, self.backup_name(SystemTime::now()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(mode)
            .open(&self.path)?;
        self.file = Some(file);
        self.size = 0;
        Ok(())
    }

    fn backup_name(&self, at: SystemTime) -> PathBuf {
        self.dir.join(format!(
            "{}-{}{}",
            self.prefix,
            format_backup_timestamp(at),
            self.ext
        ))
    }

    /// Mirrors lumberjack `millRunOnce` without compression: keep the newest
    /// `max_backups`, then drop what is older than `max_days`.
    fn mill(&self) {
        if self.max_backups == 0 && self.max_days == 0 {
            return;
        }
        let mut backups = self.old_log_files();
        backups.sort_by(|a, b| b.0.cmp(&a.0));
        let mut remove = Vec::new();
        if self.max_backups > 0 && backups.len() as u64 > self.max_backups {
            let keep = usize::try_from(self.max_backups).unwrap_or(usize::MAX);
            remove.extend(backups.drain(keep..));
        }
        if self.max_days > 0 {
            let cutoff = SystemTime::now()
                .checked_sub(Duration::from_secs(
                    self.max_days.saturating_mul(24 * 60 * 60),
                ))
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |elapsed| elapsed.as_millis());
            let (old, fresh): (Vec<_>, Vec<_>) =
                backups.into_iter().partition(|(stamp, _)| *stamp < cutoff);
            remove.extend(old);
            backups = fresh;
        }
        drop(backups);
        for (_, name) in remove {
            let _ = fs::remove_file(self.dir.join(name));
        }
    }

    /// Backups of this file, as `(timestamp millis, file name)`.
    fn old_log_files(&self) -> Vec<(u128, String)> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_owned();
                let stamp = self.time_from_name(&name)?;
                Some((stamp, name))
            })
            .collect()
    }

    fn time_from_name(&self, name: &str) -> Option<u128> {
        let rest = name.strip_prefix(&self.prefix)?.strip_prefix('-')?;
        let stamp = rest.strip_suffix(&self.ext)?;
        parse_backup_timestamp(stamp)
    }
}

/// The directory that holds `path`; a bare relative file name lives in the
/// current directory, which `Path::parent` reports as an empty path that
/// `read_dir` would reject.
fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Renders `2006-01-02T15-04-05.000` in local time for a backup file name,
/// like lumberjack with `LocalTime: true`.
#[must_use]
pub fn format_backup_timestamp(at: SystemTime) -> String {
    DateTime::<Local>::from(at)
        .format(BACKUP_TIMESTAMP_FORMAT)
        .to_string()
}

/// Parses the backup timestamp layout as local time (Go's
/// `time.ParseInLocation(..., time.Local)`) into milliseconds since the
/// epoch; an ambiguous wall-clock time takes its earlier instant.
#[must_use]
pub fn parse_backup_timestamp(stamp: &str) -> Option<u128> {
    if stamp.len() != BACKUP_TIMESTAMP_LEN || !stamp.is_ascii() {
        return None;
    }
    let naive = NaiveDateTime::parse_from_str(stamp, BACKUP_TIMESTAMP_FORMAT).ok()?;
    let local = Local.from_local_datetime(&naive).earliest()?;
    u128::try_from(local.timestamp_millis()).ok()
}

#[cfg(test)]
#[allow(clippy::case_sensitive_file_extension_comparisons)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tiproxy-logging-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn settings(dir: &Path, max_size_mb: u64, max_days: u64, max_backups: u64) -> LogFileSettings {
        LogFileSettings {
            filename: dir.join("tiproxy.log"),
            max_size_mb,
            max_days,
            max_backups,
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn a_bare_file_name_prunes_in_the_current_directory() {
        assert_eq!(parent_dir(Path::new("tiproxy.log")), PathBuf::from("."));
        assert_eq!(
            parent_dir(Path::new("logs/tiproxy.log")),
            PathBuf::from("logs")
        );
        assert_eq!(
            parent_dir(Path::new("/var/log/tiproxy.log")),
            PathBuf::from("/var/log")
        );
    }

    #[test]
    fn timestamps_round_trip_through_the_lumberjack_layout_in_local_time() {
        for millis in [
            0_u128,
            1_700_000_000_123,
            951_782_400_000,
            4_107_542_399_999,
        ] {
            let at = UNIX_EPOCH + Duration::from_millis(u64::try_from(millis).unwrap_or(0));
            let text = format_backup_timestamp(at);
            assert_eq!(text.len(), BACKUP_TIMESTAMP_LEN, "{text}");
            assert_eq!(&text[10..11], "T");
            assert_eq!(parse_backup_timestamp(&text), Some(millis), "{text}");
            // The rendered wall clock is the local one, not UTC.
            let expected = DateTime::<Local>::from(at);
            assert_eq!(text, expected.format("%Y-%m-%dT%H-%M-%S%.3f").to_string());
        }
        assert_eq!(parse_backup_timestamp("2023-11-14T22-13-20"), None);
        assert_eq!(parse_backup_timestamp("2023-13-14T22-13-20.123"), None);
        assert_eq!(parse_backup_timestamp("2023-11-14 22-13-20.123"), None);
    }

    #[test]
    fn rotates_when_a_line_would_exceed_the_limit_and_keeps_backups_bounded() {
        let dir = temp_dir();
        // One megabyte limit: the test shrinks the effective limit through the
        // private field to keep the fixture small.
        let mut file = RotatingFile::open(&settings(&dir, 1, 0, 2))
            .unwrap_or_else(|error| unreachable!("open: {error}"));
        file.max_bytes = 64;
        let line = "x".repeat(30);
        for _ in 0..7 {
            assert!(file.write_line(&line).is_ok());
            std::thread::sleep(Duration::from_millis(2));
        }
        let entries = names(&dir);
        assert!(entries.contains(&"tiproxy.log".to_owned()));
        let backups: Vec<&String> = entries
            .iter()
            .filter(|name| name.starts_with("tiproxy-") && name.ends_with(".log"))
            .collect();
        assert_eq!(
            backups.len(),
            2,
            "max-backups keeps the two newest: {entries:?}"
        );
        for backup in backups {
            let stamp = &backup["tiproxy-".len()..backup.len() - ".log".len()];
            assert!(parse_backup_timestamp(stamp).is_some(), "{backup}");
        }
        let content = fs::read_to_string(dir.join("tiproxy.log")).unwrap_or_default();
        assert_eq!(
            content.lines().count(),
            1,
            "the live file holds the last line only"
        );
        assert!(
            file.write_line(&"y".repeat(100)).is_err(),
            "an oversize line is refused like Go"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prunes_backups_older_than_max_days_and_appends_to_an_existing_file() {
        let dir = temp_dir();
        let old = dir.join("tiproxy-2001-01-01T00-00-00.000.log");
        let fresh = dir.join(format!(
            "tiproxy-{}.log",
            format_backup_timestamp(SystemTime::now())
        ));
        let unrelated = dir.join("other-2001-01-01T00-00-00.000.log");
        for path in [&old, &fresh, &unrelated] {
            assert!(fs::write(path, b"old\n").is_ok());
        }
        assert!(fs::write(dir.join("tiproxy.log"), b"existing\n").is_ok());
        let mut file = RotatingFile::open(&settings(&dir, 1, 3, 0))
            .unwrap_or_else(|error| unreachable!("open: {error}"));
        assert!(
            !old.exists(),
            "a backup older than max-days is pruned at open"
        );
        assert!(fresh.exists(), "a recent backup survives");
        assert!(unrelated.exists(), "files of other prefixes are untouched");
        assert!(file.write_line("appended").is_ok());
        let content = fs::read_to_string(dir.join("tiproxy.log")).unwrap_or_default();
        assert_eq!(content, "existing\nappended\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn configure_switches_between_stderr_and_file_without_losing_lines() {
        let dir = temp_dir();
        assert!(configure(Some(&settings(&dir, 1, 0, 0))).is_ok());
        emit_line("{\"event\":\"one\"}");
        assert!(configure(None).is_ok());
        emit_line("{\"event\":\"two\"}");
        let content = fs::read_to_string(dir.join("tiproxy.log")).unwrap_or_default();
        assert_eq!(content, "{\"event\":\"one\"}\n");
        assert!(
            configure(Some(&LogFileSettings {
                filename: dir.clone(),
                max_size_mb: 1,
                max_days: 0,
                max_backups: 0,
            }))
            .is_err(),
            "a directory is not a log file"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
