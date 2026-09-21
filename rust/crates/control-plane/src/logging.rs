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
//! Without a configured file the line is written to stderr, as before. With a
//! file configured (the binary's `--log-file` path plus the `log.log-file.*`
//! limits), lines go to that file and rotate exactly like the Go `lumberjack`
//! writer `TiProxy` uses: a write that would exceed
//! `max-size` megabytes first renames the current file to
//! `<name>-<timestamp><ext>` and starts a new one, then prunes backups beyond
//! `max-backups` and older than `max-days`. The backup timestamp uses the same
//! `2006-01-02T15-04-05.000` layout rendered in local time (`LocalTime: true`
//! in the Go configuration) and, exactly like lumberjack, parsed back as UTC
//! when deciding `max-days` retention.
//! Reconfiguration is atomic per line: a reload swaps the writer between two
//! lines and never drops or duplicates one.
//!
//! Line contract (CP-ADMIN slice 4a). Every line carries the Go logger's
//! header so `SearchLog`-style readers (`sysutil`, the `TiDB` dashboard) parse Rust
//! logs exactly like Go ones. With `log.encoder = "tidb"` a line is
//! `[2006/01/02 15:04:05.000 -07:00] [LEVEL] <body>` where the body is the
//! structured JSON object the Rust process always produced (this is a
//! declared format difference: Go renders `[key=value]` fields there). With
//! `log.encoder = "json"` the line is the zap object shape
//! `{"level":"LEVEL","ts":"<same layout>",...body fields}`, and with
//! `log.encoder = "console"` zap's `ts<TAB>LEVEL<TAB><body>`; the spellings
//! are case-sensitive like Go's `buildEncoder`. `log.simple` drops the header
//! (Go drops the time, level, caller and message keys). `log.level` is parsed
//! exactly like zap (`dpanic`/`panic`/`fatal` thresholds suppress every line
//! this process emits; misspellings are rejected) and filters like the Go
//! logger. The fixture `testdata/log-format-go.json`, recorded from the
//! production Go builder by `tests/controlplane/cplog/format-probe`, pins
//! these rules.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, NaiveDateTime};

/// Go `pingcap/log` timestamp layout (`2006/01/02 15:04:05.000 -07:00`),
/// rendered in local time like the Go logger.
const LINE_TIMESTAMP_FORMAT: &str = "%Y/%m/%d %H:%M:%S%.3f %:z";

/// zap level, in zap's order. Lines are emitted at `Debug`..`Error`; the
/// three higher levels exist only as `log.level` thresholds that suppress
/// every emitted line, exactly like the Go logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Diagnostic detail; suppressed unless `log.level = "debug"`.
    Debug,
    /// Normal lifecycle events.
    Info,
    /// Recoverable problems and rejected requests.
    Warn,
    /// Failures the process could not carry out.
    Error,
    /// zap `dpanic` threshold (nothing this process emits reaches it).
    DPanic,
    /// zap `panic` threshold.
    Panic,
    /// zap `fatal` threshold.
    Fatal,
}

/// A `log.level` spelling zap's `ParseLevel` rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLevel(pub String);

impl fmt::Display for InvalidLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unrecognized level: {:?}", self.0)
    }
}

impl Level {
    /// The zap capital level tag as written between brackets and in `"level"`.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::DPanic => "DPANIC",
            Self::Panic => "PANIC",
            Self::Fatal => "FATAL",
        }
    }

    /// Parses `log.level` exactly like zap's `Level.UnmarshalText`, which the
    /// Go `BuildLogger` and reload path use: the text as written first, then
    /// its lowercase form; the empty string is `info`; nothing is trimmed.
    ///
    /// # Errors
    ///
    /// Returns the rejected spelling, which fails startup and leaves the
    /// running level untouched on reload, as in Go.
    pub fn parse(text: &str) -> Result<Self, InvalidLevel> {
        fn exact(text: &str) -> Option<Level> {
            Some(match text {
                "debug" => Level::Debug,
                "info" | "" => Level::Info,
                "warn" | "warning" => Level::Warn,
                "error" => Level::Error,
                "dpanic" => Level::DPanic,
                "panic" => Level::Panic,
                "fatal" => Level::Fatal,
                _ => return None,
            })
        }
        exact(text)
            .or_else(|| exact(&text.to_lowercase()))
            .ok_or_else(|| InvalidLevel(text.to_owned()))
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// Line encoder mirroring the Go `buildEncoder` switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoder {
    /// `[ts] [LEVEL] <json body>` (every spelling but the two below).
    Tidb,
    /// zap JSON: `{"level":..,"ts":..,<body fields>}`.
    Json,
    /// zap console: `ts<TAB>LEVEL<TAB><json body>`.
    Console,
}

impl Encoder {
    /// Selects the encoder exactly like Go: the case-sensitive spellings
    /// `json` and `console`; anything else is the `TiDB` text encoder.
    #[must_use]
    pub fn from_config(encoder: &str) -> Self {
        match encoder {
            "json" => Self::Json,
            "console" => Self::Console,
            _ => Self::Tidb,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LineFormat {
    encoder: Encoder,
    simple: bool,
    min_level: Level,
}

static FORMAT: Mutex<LineFormat> = Mutex::new(LineFormat {
    encoder: Encoder::Tidb,
    simple: false,
    min_level: Level::Info,
});

fn format() -> LineFormat {
    *FORMAT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Selects the line encoder and `log.simple` (both fixed for the process
/// lifetime, like Go's restart-required `log.encoder`/`log.simple`).
pub fn set_format(encoder: Encoder, simple: bool) {
    let mut format = FORMAT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    format.encoder = encoder;
    format.simple = simple;
}

/// Sets the minimum level a line needs to be written (`log.level`, reloadable).
pub fn set_level(level: Level) {
    FORMAT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .min_level = level;
}

/// Renders one complete line for `body` (a JSON object text) at `level`
/// under `encoder`, stamped with the local time `at`. With `simple` the Go
/// encoders drop the time, level, caller and message keys, so only the
/// structured body remains.
#[must_use]
pub fn render_line(
    encoder: Encoder,
    simple: bool,
    level: Level,
    at: DateTime<Local>,
    body: &str,
) -> String {
    if simple {
        return body.to_owned();
    }
    let stamp = at.format(LINE_TIMESTAMP_FORMAT);
    match encoder {
        Encoder::Tidb => format!("[{stamp}] [{}] {body}", level.tag()),
        Encoder::Console => format!("{stamp}\t{}\t{body}", level.tag()),
        Encoder::Json => {
            let body = body.trim();
            if let Some(rest) = body.strip_prefix('{').filter(|rest| rest.ends_with('}')) {
                if rest.trim_start() == "}" {
                    format!("{{\"level\":\"{}\",\"ts\":\"{stamp}\"}}", level.tag())
                } else {
                    format!("{{\"level\":\"{}\",\"ts\":\"{stamp}\",{rest}", level.tag())
                }
            } else {
                let msg = serde_json::Value::String(body.to_owned());
                format!(
                    "{{\"level\":\"{}\",\"ts\":\"{stamp}\",\"msg\":{msg}}}",
                    level.tag()
                )
            }
        }
    }
}

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

/// Writes one structured log line at `info` level; see [`emit`].
pub fn emit_line(body: &str) {
    emit(Level::Info, body);
}

/// Writes one structured log line (`body` is a JSON object text) at `level`
/// with the Go header of the configured encoder; a line below `log.level`
/// is dropped. A file write failure falls back to stderr for that line so
/// the event is never silently lost; the file stays configured for the next
/// line.
pub fn emit(level: Level, body: &str) {
    let format = format();
    if level < format.min_level {
        return;
    }
    let line = render_line(format.encoder, format.simple, level, Local::now(), body);
    let mut guard = output()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &mut *guard {
        Output::Stderr => eprintln!("{line}"),
        Output::File(file) => {
            if file.write_line(&line).is_err() {
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

/// Forces a rotation of the configured log file (lumberjack `Rotate`): the
/// current file becomes a backup and pruning runs. A stderr output is a no-op.
///
/// # Errors
///
/// Returns the rotation error; the output stays configured.
pub fn rotate_now() -> Result<(), String> {
    let mut guard = output()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match &mut *guard {
        Output::Stderr => Ok(()),
        Output::File(file) => file.rotate().map_err(|error| error.to_string()),
    }
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

/// Parses the backup timestamp layout into milliseconds since the epoch the
/// way lumberjack's `timeFromName` does: with `time.Parse`, which reads a
/// zone-less name as UTC even though the name was rendered in local time.
/// Age pruning therefore keeps lumberjack's exact retention boundary in
/// non-UTC zones; this is a deliberate reproduction of the Go behaviour.
#[must_use]
pub fn parse_backup_timestamp(stamp: &str) -> Option<u128> {
    if stamp.len() != BACKUP_TIMESTAMP_LEN || !stamp.is_ascii() {
        return None;
    }
    let naive = NaiveDateTime::parse_from_str(stamp, BACKUP_TIMESTAMP_FORMAT).ok()?;
    u128::try_from(naive.and_utc().timestamp_millis()).ok()
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
    fn backup_names_render_local_time_and_are_parsed_as_utc_like_lumberjack() {
        for millis in [
            86_400_000_u128,
            1_700_000_000_123,
            951_782_400_000,
            4_107_542_399_999,
        ] {
            let at = UNIX_EPOCH + Duration::from_millis(u64::try_from(millis).unwrap_or(0));
            let text = format_backup_timestamp(at);
            assert_eq!(text.len(), BACKUP_TIMESTAMP_LEN, "{text}");
            assert_eq!(
                text,
                DateTime::<Local>::from(at)
                    .format("%Y-%m-%dT%H-%M-%S%.3f")
                    .to_string(),
                "names carry the local wall clock"
            );
            // Parsing is zone-less (Go time.Parse): the local wall clock is
            // read back as if it were UTC, so the round trip differs from the
            // original instant by exactly the local offset at that time.
            let offset_millis =
                i128::from(DateTime::<Local>::from(at).offset().local_minus_utc()) * 1000;
            let parsed = parse_backup_timestamp(&text).map(i128::try_from);
            assert_eq!(
                parsed,
                Some(Ok(i128::try_from(millis).unwrap_or(0) + offset_millis)),
                "{text}"
            );
        }
        assert_eq!(
            parse_backup_timestamp("2023-11-14T22-13-20.123"),
            Some(1_700_000_000_123)
        );
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
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "exactly the line written while the file was configured"
        );
        assert!(
            lines[0].ends_with("] [INFO] {\"event\":\"one\"}"),
            "{}",
            lines[0]
        );
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

    /// The `tidb` header is the Go `pingcap/log` layout: the timestamp parses
    /// back with the same layout `sysutil` uses, the level tag follows, and
    /// the JSON body is untouched. `simple` drops the header entirely.
    #[test]
    fn tidb_lines_carry_the_go_header_and_the_json_body() {
        let at = Local::now();
        let body = "{\"event\":\"x\",\"n\":1}";
        let line = render_line(Encoder::Tidb, false, Level::Warn, at, body);
        let Some(rest) = line.strip_prefix('[') else {
            unreachable!("header starts with the timestamp: {line}")
        };
        let Some((stamp, rest)) = rest.split_once("] ") else {
            unreachable!("timestamp is bracketed: {line}")
        };
        assert_eq!(
            stamp.len(),
            "2006/01/02 15:04:05.000 -07:00".len(),
            "{stamp}"
        );
        let parsed = DateTime::parse_from_str(stamp, LINE_TIMESTAMP_FORMAT)
            .unwrap_or_else(|error| unreachable!("{stamp}: {error}"));
        assert_eq!(parsed.timestamp_millis(), at.timestamp_millis());
        assert_eq!(rest, "[WARN] {\"event\":\"x\",\"n\":1}");
        assert_eq!(
            render_line(Encoder::Tidb, true, Level::Warn, at, body),
            body
        );
        assert_eq!(
            render_line(Encoder::Json, true, Level::Warn, at, body),
            body
        );
        assert_eq!(
            render_line(Encoder::Console, true, Level::Warn, at, body),
            body
        );
    }

    /// The `json` encoder produces the zap object shape with `level` and
    /// `ts` first and the body's fields spliced in (a non-object body
    /// becomes the `msg` string); `console` is zap's tab-separated shape.
    #[test]
    fn json_and_console_lines_follow_the_zap_shapes() {
        let at = Local::now();
        let stamp = at.format(LINE_TIMESTAMP_FORMAT).to_string();
        assert_eq!(
            render_line(Encoder::Json, false, Level::Error, at, "{\"event\":\"x\"}"),
            format!("{{\"level\":\"ERROR\",\"ts\":\"{stamp}\",\"event\":\"x\"}}")
        );
        assert_eq!(
            render_line(Encoder::Json, false, Level::Info, at, "{}"),
            format!("{{\"level\":\"INFO\",\"ts\":\"{stamp}\"}}")
        );
        assert_eq!(
            render_line(Encoder::Json, false, Level::Debug, at, "plain \"text\""),
            format!("{{\"level\":\"DEBUG\",\"ts\":\"{stamp}\",\"msg\":\"plain \\\"text\\\"\"}}")
        );
        let value: serde_json::Value = serde_json::from_str(&render_line(
            Encoder::Json,
            false,
            Level::Info,
            at,
            "{\"event\":\"x\"}",
        ))
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(value["level"], "INFO");
        assert_eq!(value["ts"], stamp);
        assert_eq!(
            render_line(
                Encoder::Console,
                false,
                Level::Warn,
                at,
                "{\"event\":\"x\"}"
            ),
            format!("{stamp}\tWARN\t{{\"event\":\"x\"}}")
        );
    }

    /// Level spellings, level filtering, encoder selection, `simple` and the
    /// line header follow the production Go `BuildLogger`, recorded by
    /// `tests/controlplane/cplog/format-probe` into `log-format-go.json`.
    #[test]
    fn level_encoder_and_header_follow_the_go_logger_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/log-format-go.json"))
                .unwrap_or_else(|error| unreachable!("{error}"));
        let text = |value: &serde_json::Value, key: &str| {
            value[key].as_str().map(str::to_owned).unwrap_or_default()
        };
        let levels = fixture["levels"].as_array().cloned().unwrap_or_default();
        let encoders = fixture["encoders"].as_array().cloned().unwrap_or_default();
        assert_eq!(levels.len(), 18);
        assert_eq!(encoders.len(), 16);
        let emitted_levels = [
            ("debug", Level::Debug),
            ("info", Level::Info),
            ("warn", Level::Warn),
            ("error", Level::Error),
        ];
        for case in &levels {
            let spelling = text(case, "text");
            let parsed = Level::parse(&spelling);
            assert_eq!(
                parsed.is_ok(),
                case["accepted"].as_bool().unwrap_or(false),
                "level {spelling:?}"
            );
            let Ok(threshold) = parsed else { continue };
            for (name, level) in emitted_levels {
                assert_eq!(
                    level >= threshold,
                    case["emitted"][name].as_bool().unwrap_or(false),
                    "level {spelling:?} emits {name}"
                );
            }
        }
        let at = Local::now();
        let stamp = at.format(LINE_TIMESTAMP_FORMAT).to_string();
        for case in &encoders {
            let spelling = text(case, "text");
            let simple = case["simple"].as_bool().unwrap_or(false);
            let go_line = text(case, "first_line");
            let go = go_line.as_str();
            let encoder = Encoder::from_config(&spelling);
            let rendered = render_line(encoder, simple, Level::Info, at, "{\"k\":\"v\"}")
                .replace(&stamp, "<TS>");
            assert!(
                !go.is_empty(),
                "Go accepts every encoder spelling: {spelling:?}"
            );
            if simple {
                // Go drops the time, level, caller and message keys: the Go
                // line is only the field, and so is the Rust line.
                assert!(!go.contains("<TS>"), "{spelling:?} simple: {go}");
                assert!(!go.contains("INFO"), "{spelling:?} simple: {go}");
                assert_eq!(rendered, "{\"k\":\"v\"}", "{spelling:?} simple");
                continue;
            }
            let (prefix, go_prefix_ok) = match encoder {
                Encoder::Tidb => ("[<TS>] [INFO] ", go.starts_with("[<TS>] [INFO] [")),
                Encoder::Json => (
                    "{\"level\":\"INFO\",\"ts\":\"<TS>\",",
                    go.starts_with("{\"level\":\"INFO\",\"ts\":\"<TS>\",\"caller\":"),
                ),
                Encoder::Console => ("<TS>\tINFO\t", go.starts_with("<TS>\tINFO\t")),
            };
            assert!(go_prefix_ok, "{spelling:?}: Go line {go} for {encoder:?}");
            assert!(
                rendered.starts_with(prefix),
                "{spelling:?}: Rust line {rendered} for {encoder:?}"
            );
        }
    }
}
