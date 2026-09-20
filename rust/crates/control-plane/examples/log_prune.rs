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

//! Rotates a log file through the native writer and lists the directory, the
//! Rust half of the lumberjack retention parity check.

use std::path::PathBuf;

use control_plane::logging::{LogFileSettings, configure, emit_line};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(file), Some(max_days), Some(max_backups)) = (args.get(1), args.get(2), args.get(3))
    else {
        eprintln!("usage: log_prune LOG_FILE MAX_DAYS MAX_BACKUPS");
        std::process::exit(2);
    };
    let settings = LogFileSettings {
        filename: PathBuf::from(file),
        max_size_mb: 300,
        max_days: max_days.parse().unwrap_or(0),
        max_backups: max_backups.parse().unwrap_or(0),
    };
    if let Err(error) = configure(Some(&settings)) {
        eprintln!("{error}");
        std::process::exit(1);
    }
    emit_line("probe");
    if let Err(error) = control_plane::logging::rotate_now() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    let dir = settings
        .filename
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        println!("{name}");
    }
}
