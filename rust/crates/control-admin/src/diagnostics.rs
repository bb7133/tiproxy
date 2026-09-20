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

//! `SearchLog` over the process log file, ported one to one from the Go
//! `sysutil` diagnostics server (`search_log.go`, `service.go`) that the Go
//! API registers: file resolution by name prefix and extension (plain and
//! `.gz`), first/last valid line probing (ten attempts each, backward chunked
//! reads for the last line), time-window file selection, the line grammar
//! `[2006/01/02 15:04:05.000 -07:00] [LEVEL] message`, continuation lines
//! inheriting the previous item's time and level, level bitmask and regular
//! expression filters, and 1024-message batches with a final (possibly
//! empty) batch.
//!
//! Declared differences (see `docs/design/rust-control-admin.md`): Go's
//! `regexp` and the `regex` crate share the RE2 syntax family but differ in
//! the listed details; Go error texts from the file system and the regexp
//! compiler are not reproduced verbatim.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use chrono::DateTime;
use control_external::diagnostics::{LogLevel, LogMessage, SearchLogRequest};
use flate2::read::MultiGzDecoder;

/// Go `pingcap/log` line timestamp layout (`2006/01/02 15:04:05.000 -07:00`).
const TIMESTAMP_LAYOUT: &str = "%Y/%m/%d %H:%M:%S%.3f %:z";
/// `len(TimeStampLayout)`: a line shorter than this cannot start an item.
const TIMESTAMP_LAYOUT_LEN: usize = "2006/01/02 15:04:05.000 -07:00".len();
/// Go `maxReadCacheSize`: the largest backward read chunk.
const MAX_READ_CACHE_SIZE: u64 = 16 * 1024 * 1024;
/// Messages per `SearchLogResponse` (Go sends batches of 1024).
pub const BATCH_SIZE: usize = 1024;
const COMPRESS_SUFFIX: &str = ".gz";

/// A search failure, carrying the Go-shaped message where Go's text is
/// deterministic (`empty log file location configuration`) and a bounded
/// description otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchError(pub String);

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The consumer stopped reading (the gRPC stream was cancelled): stop
/// scanning, like Go's `ctx.Done()` checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

/// One resolved log file, as Go's `logFile` (opened lazily here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFile {
    /// Full path.
    pub path: PathBuf,
    /// Timestamp of the first valid line (milliseconds).
    pub begin: i64,
    /// Timestamp of the last valid line, or `i64::MAX` for a compressed file.
    pub end: i64,
    /// Whether the file is gzip-compressed.
    pub compressed: bool,
}

/// Runs one search: every batch of up to [`BATCH_SIZE`] messages is handed to
/// `emit`, and after the last batch a final (possibly empty) batch follows,
/// exactly like the Go server's send loop. `emit` returning [`Cancelled`]
/// stops the scan.
///
/// # Errors
///
/// A missing log path, an unreadable directory, or an invalid pattern.
pub fn search(
    log_file: &Path,
    request: &SearchLogRequest,
    emit: &mut dyn FnMut(Vec<LogMessage>) -> Result<(), Cancelled>,
) -> Result<(), SearchError> {
    let begin = request.start_time;
    let end = if request.end_time == 0 {
        i64::MAX
    } else {
        request.end_time
    };
    let files = resolve_files(log_file, begin, end)?;
    let mut level_flag: i64 = 0;
    for level in &request.levels {
        if (0..63).contains(level) {
            level_flag |= 1_i64 << level;
        }
    }
    let mut patterns = Vec::with_capacity(request.patterns.len());
    for pattern in &request.patterns {
        patterns.push(regex::Regex::new(pattern).map_err(|error| SearchError(error.to_string()))?);
    }
    let mut iterator = LogIterator {
        begin,
        end,
        level_flag,
        patterns,
        pending: files,
        file_index: 0,
        reader: None,
        previous: None,
    };
    loop {
        let mut messages = Vec::new();
        let mut drained = false;
        for _ in 0..BATCH_SIZE {
            let Some(item) = iterator.next()? else {
                drained = true;
                break;
            };
            messages.push(item);
        }
        if emit(messages).is_err() {
            return Ok(());
        }
        if drained {
            return Ok(());
        }
    }
}

/// Go `resolveFiles`: every regular entry of the log directory whose full
/// path starts with the configured path minus its extension and ends with
/// that extension (optionally `.gz`), probed for its first and last valid
/// line, kept when it overlaps `[begin, end]`, sorted by first timestamp,
/// and trimmed to the last file that starts before `begin` plus everything
/// after it.
///
/// # Errors
///
/// An empty path or an unreadable directory.
pub fn resolve_files(
    log_file: &Path,
    begin: i64,
    end: i64,
) -> Result<Vec<ResolvedFile>, SearchError> {
    let log_path = log_file.to_string_lossy().into_owned();
    if log_path.is_empty() {
        return Err(SearchError(
            "empty log file location configuration".to_owned(),
        ));
    }
    let dir = go_dir(&log_path);
    let ext = go_ext(&log_path);
    let prefix = &log_path[..log_path.len() - ext.len()];
    let entries = fs::read_dir(&dir).map_err(|error| SearchError(error.to_string()))?;
    let mut names: Vec<(String, bool)> = entries
        .filter_map(Result::ok)
        .map(|entry| {
            let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            (entry.file_name().to_string_lossy().into_owned(), is_dir)
        })
        .collect();
    // os.ReadDir returns entries sorted by file name.
    names.sort();
    let mut files = Vec::new();
    for (name, is_dir) in names {
        if is_dir {
            continue;
        }
        let path = go_join(&dir, &name);
        if !path.starts_with(prefix) {
            continue;
        }
        let compressed = path.ends_with(COMPRESS_SUFFIX);
        if !path.ends_with(&ext) && !path.ends_with(&format!("{ext}{COMPRESS_SUFFIX}")) {
            continue;
        }
        let Ok(mut file) = File::open(&path) else {
            continue;
        };
        let first = if compressed {
            read_first_valid_log(&mut BufReader::new(MultiGzDecoder::new(&mut file)), 10)
        } else {
            read_first_valid_log(&mut BufReader::new(&mut file), 10)
        };
        let Some(first) = first else {
            continue;
        };
        let last = if compressed {
            i64::MAX
        } else {
            match read_last_valid_log(&mut file, 10) {
                Some(item) => item.time,
                None => continue,
            }
        };
        if begin > last || end < first.time {
            continue;
        }
        files.push(ResolvedFile {
            path: PathBuf::from(path),
            begin: first.time,
            end: last,
            compressed,
        });
    }
    files.sort_by(|a, b| a.begin.cmp(&b.begin));
    let mut index = 0;
    for (i, file) in files.iter().enumerate().skip(1) {
        if file.begin < begin {
            index = i;
        } else {
            break;
        }
    }
    Ok(files.split_off(index))
}

/// Go `filepath.Dir`: the path minus its last element, `.` for a bare name.
fn go_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_owned(),
        Some(index) => path[..index].to_owned(),
        None => ".".to_owned(),
    }
}

/// Go `filepath.Ext`: from the final dot of the last element, or empty.
fn go_ext(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.rfind('.') {
        Some(index) => base[index..].to_owned(),
        None => String::new(),
    }
}

/// Go `filepath.Join(dir, name)` for a directory that came from `go_dir`.
fn go_join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Go `readLine`: one line without its `\n` or `\r\n`; `None` at EOF.
fn read_line(reader: &mut impl BufRead) -> Option<String> {
    let mut bytes = Vec::new();
    match reader.read_until(b'\n', &mut bytes) {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
                if bytes.last() == Some(&b'\r') {
                    bytes.pop();
                }
            }
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

/// Go `readFirstValidLog`: the first parseable line within `try_lines`.
fn read_first_valid_log(reader: &mut impl BufRead, try_lines: usize) -> Option<LogMessage> {
    let mut tried = 0;
    loop {
        let line = read_line(reader)?;
        if let Some(item) = parse_log_item(&line) {
            return Some(item);
        }
        tried += 1;
        if tried >= try_lines {
            return None;
        }
    }
}

/// Go `readLastValidLog`: the last parseable line, reading backwards in
/// growing chunks and scanning at most `try_lines` lines.
fn read_last_valid_log(file: &mut File, try_lines: usize) -> Option<LogMessage> {
    let mut tried = 0;
    let mut end_cursor = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    loop {
        let (lines, read_bytes) = read_last_lines(file, end_cursor)?;
        if read_bytes == 0 {
            break;
        }
        end_cursor -= read_bytes as u64;
        for line in lines.iter().rev() {
            if let Some(item) = parse_log_item(line) {
                return Some(item);
            }
        }
        tried += lines.len();
        if tried >= try_lines {
            break;
        }
    }
    None
}

/// Go `readLastLines`: reads backwards from `end_cursor` in doubling chunks
/// until a line boundary precedes the collected bytes, and returns the lines
/// after that boundary plus the byte count they cover.
fn read_last_lines(file: &mut File, end_cursor: u64) -> Option<(Vec<String>, usize)> {
    let mut lines: Vec<u8> = Vec::new();
    let mut first_non_newline_pos = 0usize;
    let mut cursor = end_cursor;
    let mut size: u64 = 256;
    loop {
        if cursor == 0 {
            break;
        }
        size *= 2;
        if size > MAX_READ_CACHE_SIZE {
            size = MAX_READ_CACHE_SIZE;
        }
        if cursor < size {
            size = cursor;
        }
        cursor -= size;
        file.seek(SeekFrom::Start(cursor)).ok()?;
        let mut chars = vec![0_u8; usize::try_from(size).ok()?];
        // Go reads once and keeps whatever arrived (a short read leaves
        // zero bytes in the buffer); a regular file returns the full chunk.
        file.read_exact(&mut chars).ok()?;
        let mut merged = chars.clone();
        merged.extend_from_slice(&lines);
        lines = merged;
        for i in 0..chars.len().saturating_sub(1) {
            if i >= lines.len().saturating_sub(1) {
                break;
            }
            if (chars[i] == 10 || chars[i] == 13) && chars[i + 1] != 10 && chars[i + 1] != 13 {
                first_non_newline_pos = i + 1;
                break;
            }
        }
        if first_non_newline_pos > 0 {
            break;
        }
    }
    let final_str =
        String::from_utf8_lossy(&lines[first_non_newline_pos.min(lines.len())..]).into_owned();
    let count = final_str.len();
    let split: Vec<String> = final_str
        .replace("\r\n", "\n")
        .split('\n')
        .map(str::to_owned)
        .collect();
    Some((split, count))
}

/// Go `ParseLogLevel`: exact lower/upper spellings, anything else `UNKNOWN`.
#[must_use]
pub fn parse_log_level(text: &str) -> LogLevel {
    match text {
        "debug" | "DEBUG" => LogLevel::Debug,
        "info" | "INFO" => LogLevel::Info,
        "warn" | "WARN" => LogLevel::Warn,
        "trace" | "TRACE" => LogLevel::Trace,
        "critical" | "CRITICAL" => LogLevel::Critical,
        "error" | "ERROR" => LogLevel::Error,
        _ => LogLevel::Unknown,
    }
}

/// Go `parseLogItem`: `[time] [level] message`, located by the first `[`/`]`
/// pair for the time and the first pair after it for the level; the message
/// is the rest, whitespace-trimmed. Byte offsets follow Go's `strings.Index`.
#[must_use]
pub fn parse_log_item(line: &str) -> Option<LogMessage> {
    let bytes = line.as_bytes();
    let time_left = bytes.iter().position(|&b| b == b'[')?;
    let time_right = bytes.iter().position(|&b| b == b']')?;
    if time_left > time_right {
        return None;
    }
    let time = parse_timestamp(&line[time_left + 1..time_right])?;
    let rest = &bytes[time_right + 1..];
    let level_left = rest.iter().position(|&b| b == b'[')?;
    let level_right = rest.iter().position(|&b| b == b']')?;
    if level_left > level_right {
        return None;
    }
    let level =
        parse_log_level(&line[time_right + 1 + level_left + 1..time_right + 1 + level_right]);
    let message = line[time_right + level_right + 2..].trim();
    Some(LogMessage {
        time,
        level: level as i32,
        message: message.to_owned(),
    })
}

/// Go `parseTimeStamp` with `time.Parse(TimeStampLayout, s)`: the exact
/// fixed-width layout (two-digit fields, three fractional digits, a signed
/// `hh:mm` offset) to milliseconds since the epoch.
#[must_use]
pub fn parse_timestamp(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != TIMESTAMP_LAYOUT_LEN {
        return None;
    }
    let digits = [
        0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22, 25, 26, 28, 29,
    ];
    if !digits.iter().all(|&i| bytes[i].is_ascii_digit()) {
        return None;
    }
    if bytes[4] != b'/' || bytes[7] != b'/' || bytes[10] != b' ' || bytes[13] != b':' {
        return None;
    }
    if bytes[16] != b':' || bytes[19] != b'.' || bytes[23] != b' ' || bytes[27] != b':' {
        return None;
    }
    if bytes[24] != b'+' && bytes[24] != b'-' {
        return None;
    }
    let parsed = DateTime::parse_from_str(text, TIMESTAMP_LAYOUT).ok()?;
    Some(parsed.timestamp_millis())
}

enum LineReader {
    Plain(BufReader<File>),
    Gzip(BufReader<MultiGzDecoder<File>>),
}

impl LineReader {
    fn open(file: &ResolvedFile) -> Result<Self, SearchError> {
        let handle = File::open(&file.path).map_err(|error| SearchError(error.to_string()))?;
        Ok(if file.compressed {
            Self::Gzip(BufReader::new(MultiGzDecoder::new(handle)))
        } else {
            Self::Plain(BufReader::new(handle))
        })
    }

    fn read_line(&mut self) -> Option<String> {
        match self {
            Self::Plain(reader) => read_line(reader),
            Self::Gzip(reader) => read_line(reader),
        }
    }
}

/// Go `logIterator`: walks the pending files in order, applies the time
/// window, level bitmask and patterns, and turns unparseable lines that
/// follow a valid item into continuation messages of that item.
struct LogIterator {
    begin: i64,
    end: i64,
    level_flag: i64,
    patterns: Vec<regex::Regex>,
    pending: Vec<ResolvedFile>,
    file_index: usize,
    reader: Option<LineReader>,
    previous: Option<LogMessage>,
}

impl LogIterator {
    fn next(&mut self) -> Result<Option<LogMessage>, SearchError> {
        if self.reader.is_none() {
            if self.pending.is_empty() {
                return Ok(None);
            }
            self.reader = Some(LineReader::open(&self.pending[self.file_index])?);
        }
        'next_line: loop {
            let Some(reader) = self.reader.as_mut() else {
                return Ok(None);
            };
            let Some(line) = reader.read_line() else {
                self.file_index += 1;
                if self.file_index >= self.pending.len() {
                    return Ok(None);
                }
                self.reader = Some(LineReader::open(&self.pending[self.file_index])?);
                continue;
            };
            let line = line.trim();
            if self.previous.is_none() && line.len() < TIMESTAMP_LAYOUT_LEN {
                continue;
            }
            let item = if let Some(item) = parse_log_item(line) {
                self.previous = Some(item.clone());
                item
            } else {
                let Some(previous) = &self.previous else {
                    continue;
                };
                LogMessage {
                    time: previous.time,
                    level: previous.level,
                    message: line.to_owned(),
                }
            };
            if item.time > self.end {
                return Ok(None);
            }
            if item.time < self.begin {
                continue;
            }
            if item.level > LogLevel::Unknown as i32
                && self.level_flag != 0
                && (0..63).contains(&item.level)
                && self.level_flag & (1_i64 << item.level) == 0
            {
                continue;
            }
            for pattern in &self.patterns {
                if !pattern.is_match(&item.message) {
                    continue 'next_line;
                }
            }
            return Ok(Some(item));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tiproxy-cpdiag-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn write(dir: &Path, name: &str, lines: &[&str]) {
        let mut file = File::create(dir.join(name)).unwrap_or_else(|e| unreachable!("{e}"));
        for line in lines {
            writeln!(file, "{line}").unwrap_or_else(|e| unreachable!("{e}"));
        }
    }

    fn write_gz(dir: &Path, name: &str, lines: &[&str]) {
        let file = File::create(dir.join(name)).unwrap_or_else(|e| unreachable!("{e}"));
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        for line in lines {
            writeln!(encoder, "{line}").unwrap_or_else(|e| unreachable!("{e}"));
        }
        encoder.finish().unwrap_or_else(|e| unreachable!("{e}"));
    }

    fn ts(text: &str) -> i64 {
        parse_timestamp(text).unwrap_or_else(|| unreachable!("{text}"))
    }

    fn request(start: &str, end: &str, levels: &[LogLevel], patterns: &[&str]) -> SearchLogRequest {
        SearchLogRequest {
            start_time: ts(start),
            end_time: ts(end),
            levels: levels.iter().map(|level| *level as i32).collect(),
            patterns: patterns.iter().map(|p| (*p).to_owned()).collect(),
            target: 0,
        }
    }

    fn collect(dir: &Path, request: &SearchLogRequest) -> Vec<Vec<LogMessage>> {
        let mut batches = Vec::new();
        search(&dir.join("tidb.log"), request, &mut |batch| {
            batches.push(batch);
            Ok(())
        })
        .unwrap_or_else(|e| unreachable!("{e}"));
        batches
    }

    fn times(batches: &[Vec<LogMessage>]) -> Vec<i64> {
        batches.iter().flatten().map(|item| item.time).collect()
    }

    const WELCOME: &str = "[printer.go:41] [\"Welcome to TiDB.\"]";

    fn welcome(stamp: &str, level: &str) -> String {
        format!("[{stamp}] [{level}] {WELCOME}")
    }

    /// The sysutil `TestResolveFiles` fixture: file selection by time window,
    /// plus a gzip backup whose end is unbounded.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn resolves_files_like_sysutil() {
        let dir = temp_dir();
        let lines: Vec<String> = [
            "2019/08/26 06:19:13.011 -04:00",
            "2019/08/26 06:19:14.011 -04:00",
            "2019/08/26 06:19:15.011 -04:00",
            "2019/08/26 06:19:16.011 -04:00",
            "2019/08/26 06:19:17.011 -04:00",
        ]
        .iter()
        .map(|stamp| welcome(stamp, "INFO"))
        .collect();
        write(
            &dir,
            "tidb.log",
            &lines.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        write(
            &dir,
            "tidb-1.log",
            &[&welcome("2019/08/26 06:20:14.011 -04:00", "INFO")],
        );
        write(
            &dir,
            "tidb-2.log",
            &[
                &welcome("2019/08/26 06:21:14.011 -04:00", "INFO"),
                &welcome("2019/08/26 06:21:15.011 -04:00", "INFO"),
            ],
        );
        write(&dir, "tidb-3.log", &[""]);
        let lines: Vec<String> = [
            "2019/08/26 06:22:14.011 -04:00",
            "2019/08/26 06:22:14.011 -04:00",
            "2019/08/26 06:22:15.011 -04:00",
            "2019/08/26 06:22:16.011 -04:00",
            "2019/08/26 06:22:17.011 -04:00",
        ]
        .iter()
        .map(|stamp| welcome(stamp, "INFO"))
        .collect();
        write(
            &dir,
            "tidb-4.log",
            &lines.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        write(
            &dir,
            "other.log",
            &[&welcome("2019/08/26 06:22:14.011 -04:00", "INFO")],
        );
        let resolve = |start: &str, end: &str| -> Vec<(i64, i64)> {
            resolve_files(&dir.join("tidb.log"), ts(start), ts(end))
                .unwrap_or_else(|e| unreachable!("{e}"))
                .iter()
                .map(|file| (file.begin, file.end))
                .collect()
        };
        let span = |a: &str, b: &str| (ts(a), ts(b));
        assert_eq!(
            resolve(
                "2019/08/26 06:19:13.011 -04:00",
                "2019/08/26 06:22:17.011 -04:00"
            ),
            vec![
                span(
                    "2019/08/26 06:19:13.011 -04:00",
                    "2019/08/26 06:19:17.011 -04:00"
                ),
                span(
                    "2019/08/26 06:20:14.011 -04:00",
                    "2019/08/26 06:20:14.011 -04:00"
                ),
                span(
                    "2019/08/26 06:21:14.011 -04:00",
                    "2019/08/26 06:21:15.011 -04:00"
                ),
                span(
                    "2019/08/26 06:22:14.011 -04:00",
                    "2019/08/26 06:22:17.011 -04:00"
                ),
            ]
        );
        assert!(
            resolve(
                "2019/08/26 06:29:13.011 -04:00",
                "2019/08/26 06:32:17.011 -04:00"
            )
            .is_empty()
        );
        assert_eq!(
            resolve(
                "2019/08/26 06:20:14.011 -04:00",
                "2019/08/26 06:20:14.011 -04:00"
            ),
            vec![span(
                "2019/08/26 06:20:14.011 -04:00",
                "2019/08/26 06:20:14.011 -04:00"
            )]
        );
        assert_eq!(
            resolve(
                "2019/08/26 06:22:14.011 -04:00",
                "2019/08/26 06:22:16.011 -04:00"
            ),
            vec![span(
                "2019/08/26 06:22:14.011 -04:00",
                "2019/08/26 06:22:17.011 -04:00"
            )]
        );
        // A gzip backup's end is unbounded (Go `math.MaxInt64`): it joins
        // every window at or after its first line, and as the last file that
        // starts before a later window it stays selected for that window.
        write_gz(
            &dir,
            "tidb-5.log.gz",
            &[&welcome("2019/08/26 06:23:14.011 -04:00", "INFO")],
        );
        assert_eq!(
            resolve(
                "2019/08/26 06:29:13.011 -04:00",
                "2019/08/26 06:32:17.011 -04:00"
            ),
            vec![(ts("2019/08/26 06:23:14.011 -04:00"), i64::MAX)]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The sysutil `TestLogIterator` fixture: invalid lines, continuation
    /// lines, level and pattern filters, and the stop at the first item past
    /// the window, with sysutil's own expected outputs.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn iterates_like_sysutil() {
        let dir = temp_dir();
        write(
            &dir,
            "tidb.log",
            &[
                &welcome("2019/08/26 06:19:13.011 -04:00", "INFO"),
                &welcome("2019/08/26 06:19:14.011 -04:00", "WARN"),
                &welcome("2019/08/26 06:19:15.011 -04:00", "ERROR"),
                &welcome("2019/08/26 06:19:16.011 -04:00", "DEBUG"),
                "This is an invalid log blablabla][",
                "[2019/08/26 06:19:17.011 -04:00] ] [INFO] invalid log\"]",
                &welcome("2019/08/26 06:19:17.011 -04:00", "TRACE"),
            ],
        );
        write(
            &dir,
            "tidb-1.log",
            &[&welcome("2019/08/26 06:20:14.011 -04:00", "INFO")],
        );
        write(
            &dir,
            "tidb-2.log",
            &[
                &welcome("2019/08/26 06:21:14.011 -04:00", "WARN"),
                &welcome("2019/08/26 06:21:15.011 -04:00", "INFO"),
            ],
        );
        write(&dir, "tidb-3.log", &[""]);
        write(
            &dir,
            "tidb-4.log",
            &[
                &welcome("2019/08/26 06:22:14.011 -04:00", "INFO"),
                "This is also an invalid log contains partern ...",
                &welcome("2019/08/26 06:22:14.011 -04:00", "WARN"),
                &welcome("2019/08/26 06:22:15.011 -04:00", "ERROR"),
                &welcome("2019/08/26 06:22:16.011 -04:00", "DEBUG"),
                &welcome("2019/08/26 06:22:17.011 -04:00", "TRACE"),
            ],
        );
        write(
            &dir,
            "tidb-5.log",
            &[
                "[2019/08/26 06:23:14.011 -04:00] [INFO] [printer.go:41] [\"partern test to TiDB.\"]",
                "[2019/08/27 06:23:14.011 -04:00] [INFO] [printer.go:41] [\"partern test txn to TiDB.\"]",
            ],
        );
        let all = collect(
            &dir,
            &request(
                "2000/08/26 06:19:13.011 -04:00",
                "2099/08/26 06:22:17.011 -04:00",
                &[],
                &[],
            ),
        );
        // sysutil case 1: every valid line plus the continuation lines that
        // inherit the previous item's time and level (the invalid lines of
        // tidb.log follow the DEBUG item; tidb-4's follows its first INFO).
        let items: Vec<&LogMessage> = all.iter().flatten().collect();
        assert_eq!(items.len(), 18, "{items:?}");
        let continuation = items
            .iter()
            .find(|item| item.message == "This is also an invalid log contains partern ...")
            .unwrap_or_else(|| unreachable!());
        assert_eq!(continuation.time, ts("2019/08/26 06:22:14.011 -04:00"));
        assert_eq!(continuation.level, LogLevel::Info as i32);
        let malformed = items
            .iter()
            .find(|item| item.message == "[2019/08/26 06:19:17.011 -04:00] ] [INFO] invalid log\"]")
            .unwrap_or_else(|| unreachable!());
        assert_eq!(malformed.time, ts("2019/08/26 06:19:16.011 -04:00"));
        assert_eq!(malformed.level, LogLevel::Debug as i32);

        // sysutil case 6: the two continuation lines after the DEBUG item
        // stay inside the window at its time.
        assert_eq!(
            times(&collect(
                &dir,
                &request(
                    "2019/08/26 06:19:14.011 -04:00",
                    "2019/08/26 06:19:16.011 -04:00",
                    &[],
                    &[]
                )
            )),
            vec![
                ts("2019/08/26 06:19:14.011 -04:00"),
                ts("2019/08/26 06:19:15.011 -04:00"),
                ts("2019/08/26 06:19:16.011 -04:00"),
                ts("2019/08/26 06:19:16.011 -04:00"),
                ts("2019/08/26 06:19:16.011 -04:00"),
            ]
        );
        // sysutil case 5: an exact window boundary is inclusive.
        assert_eq!(
            times(&collect(
                &dir,
                &request(
                    "2019/08/26 06:19:14.011 -04:00",
                    "2019/08/26 06:19:15.011 -04:00",
                    &[],
                    &[]
                )
            )),
            vec![
                ts("2019/08/26 06:19:14.011 -04:00"),
                ts("2019/08/26 06:19:15.011 -04:00")
            ]
        );
        // Level bitmask: only DEBUG items (continuations carry their item's
        // level, so tidb.log's two follow the DEBUG item here).
        let debug = collect(
            &dir,
            &request(
                "2019/08/26 06:19:15.011 -04:00",
                "2019/08/26 06:22:14.011 -04:00",
                &[LogLevel::Debug],
                &[],
            ),
        );
        assert_eq!(
            times(&debug),
            vec![
                ts("2019/08/26 06:19:16.011 -04:00"),
                ts("2019/08/26 06:19:16.011 -04:00"),
                ts("2019/08/26 06:19:16.011 -04:00"),
            ]
        );
        // Patterns must all match the message.
        let pattern = collect(
            &dir,
            &request(
                "2000/08/26 06:19:13.011 -04:00",
                "2099/08/26 06:22:17.011 -04:00",
                &[],
                &["partern.*txn"],
            ),
        );
        assert_eq!(times(&pattern), vec![ts("2019/08/27 06:23:14.011 -04:00")]);
        assert_eq!(all.len(), 1);
        assert_eq!(pattern.len(), 1);
        let none = collect(
            &dir,
            &request(
                "2019/08/26 06:29:13.011 -04:00",
                "2019/08/26 06:32:17.011 -04:00",
                &[],
                &[],
            ),
        );
        assert_eq!(none, vec![Vec::new()], "one empty batch");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Batches follow the Go send loop: 1024 messages per response, then a
    /// final response with the remainder or none at all.
    #[test]
    fn batches_of_1024_then_a_final_possibly_empty_batch() {
        let dir = temp_dir();
        let lines: Vec<String> = (0..2048)
            .map(|i| {
                format!(
                    "[2019/08/26 06:19:13.{:03} -04:00] [INFO] [p.go:1] [\"line {i}\"]",
                    i % 1000
                )
            })
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        write(&dir, "tidb.log", &refs);
        let batches = collect(
            &dir,
            &SearchLogRequest {
                start_time: 0,
                end_time: 0,
                levels: Vec::new(),
                patterns: Vec::new(),
                target: 0,
            },
        );
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![1024, 1024, 0]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A consumer that stops reading (the gRPC stream was cancelled) stops
    /// the scan after the batch it refused, like Go's `ctx.Done()` checks.
    #[test]
    fn a_cancelled_consumer_stops_the_scan() {
        let dir = temp_dir();
        let lines: Vec<String> = (0..3000)
            .map(|i| {
                format!(
                    "[2019/08/26 06:19:13.{:03} -04:00] [INFO] [p.go:1] [\"{i}\"]",
                    i % 1000
                )
            })
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        write(&dir, "tidb.log", &refs);
        let mut delivered = 0;
        let outcome = search(
            &dir.join("tidb.log"),
            &SearchLogRequest::default(),
            &mut |_| {
                delivered += 1;
                Err(Cancelled)
            },
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(delivered, 1, "the scan stops at the first refused batch");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Errors and the Go-fixed message for a missing path.
    #[test]
    fn errors_follow_go() {
        assert_eq!(
            search(Path::new(""), &SearchLogRequest::default(), &mut |_| Ok(())),
            Err(SearchError(
                "empty log file location configuration".to_owned()
            ))
        );
        assert!(
            search(
                Path::new("/nonexistent-dir-xyz/tidb.log"),
                &SearchLogRequest::default(),
                &mut |_| Ok(())
            )
            .is_err()
        );
        let dir = temp_dir();
        write(
            &dir,
            "tidb.log",
            &["[2019/08/26 06:19:13.011 -04:00] [INFO] [p.go:1] [x]"],
        );
        let bad = SearchLogRequest {
            patterns: vec!["(".to_owned()],
            ..SearchLogRequest::default()
        };
        assert!(search(&dir.join("tidb.log"), &bad, &mut |_| Ok(())).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The timestamp grammar is Go's fixed layout: no single-digit fields,
    /// no `Z`, no missing fraction.
    #[test]
    fn timestamp_layout_is_strict() {
        assert!(parse_timestamp("2019/08/26 06:19:13.011 -04:00").is_some());
        assert!(parse_timestamp("2019/8/26 06:19:13.011 -04:00").is_none());
        assert!(parse_timestamp("2019/08/26 06:19:13.011 Z").is_none());
        assert!(parse_timestamp("2019/08/26 06:19:13 -04:00").is_none());
        assert!(parse_timestamp("2019/08/26 06:19:13.011 +08:00").is_some());
        assert_eq!(parse_log_level("WARN"), LogLevel::Warn);
        assert_eq!(parse_log_level("Warn"), LogLevel::Unknown);
    }
}
