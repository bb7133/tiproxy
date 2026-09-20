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

//! Shared AWS service retry settings (credential endpoint/IMDS use their own defaults).
use reqsign_core::Context;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) max_attempts: i64,
    pub(crate) adaptive: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            adaptive: false,
        }
    }
}
impl Settings {
    pub(crate) fn validate_profile(props: &BTreeMap<String, String>) -> reqsign_core::Result<()> {
        if let Some(value) = props.get("max_attempts") {
            integer(value)?;
        }
        if let Some(value) = props.get("retry_mode") {
            mode(value)?;
        }
        Ok(())
    }
    pub(crate) fn resolve(
        ctx: &Context,
        props: &BTreeMap<String, String>,
    ) -> reqsign_core::Result<Self> {
        Self::validate_profile(props)?;
        let env_max = ctx.env_var("AWS_MAX_ATTEMPTS").filter(|v| !v.is_empty());
        let env_mode = ctx.env_var("AWS_RETRY_MODE").filter(|v| !v.is_empty());
        let max = env_max
            .as_deref()
            .map(integer)
            .transpose()?
            .filter(|v| *v != 0)
            .or(props
                .get("max_attempts")
                .map(|v| integer(v))
                .transpose()?
                .filter(|v| *v != 0))
            .unwrap_or(3);
        let adaptive = env_mode
            .as_deref()
            .or(props.get("retry_mode").map(String::as_str))
            .map(mode)
            .transpose()?
            .unwrap_or(false);
        Ok(Self {
            max_attempts: max,
            adaptive,
        })
    }
}
fn integer(value: &str) -> reqsign_core::Result<i64> {
    // Go strconv.Atoi accepts an explicit sign, rejects surrounding space, and
    // uses the target's 64-bit int range. Negative means no attempt-count limit.
    value.parse().map_err(|_| invalid())
}
fn mode(value: &str) -> reqsign_core::Result<bool> {
    match value {
        "standard" => Ok(false),
        "adaptive" => Ok(true),
        _ => Err(invalid()),
    }
}
fn invalid() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("AWS retry configuration invalid")
}
