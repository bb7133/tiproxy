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

//! Generates version metadata for the `tiproxy-rs` executable.

use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    for name in [
        "TIPROXY_VERSION",
        "TIPROXY_COMMIT",
        "TIPROXY_BUILD_TIME",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=../../../.git/HEAD");

    let version = env::var("TIPROXY_VERSION")
        .unwrap_or_else(|_| env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into()));
    let commit = env::var("TIPROXY_COMMIT").unwrap_or_else(|_| git_commit());
    let build_time = env::var("TIPROXY_BUILD_TIME").unwrap_or_else(|_| build_time());

    export("TIPROXY_BUILD_VERSION", &version);
    export("TIPROXY_BUILD_COMMIT", &commit);
    export("TIPROXY_BUILD_TIME", &build_time);
}

fn git_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_owned())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn build_time() -> String {
    env::var("SOURCE_DATE_EPOCH")
        .ok()
        .filter(|epoch| epoch.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or_else(
            || {
                SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
                    |_| "unknown".into(),
                    |time| format!("unix:{}", time.as_secs()),
                )
            },
            |epoch| format!("unix:{epoch}"),
        )
}

fn export(name: &str, value: &str) {
    let value = value.replace(['\r', '\n'], "");
    println!("cargo:rustc-env={name}={value}");
}
