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

//! Go `credential_process` shell invocation and strict output decoding.

use reqsign_aws_v4::Credential;
use reqsign_core::{Context, time::Timestamp};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use std::fmt;

pub(crate) async fn retrieve(ctx: &Context, command: &str) -> reqsign_core::Result<Credential> {
    if command.is_empty() {
        return Err(failed());
    }
    // Go DefaultNewCommandBuilder passes the complete config value to the
    // platform shell. Splitting whitespace breaks quoted helper paths/JSON.
    let (program, flag) = if cfg!(windows) {
        ("cmd.exe", "/C")
    } else {
        ("sh", "-c")
    };
    let output = ctx.command_execute(program, &[flag, command]).await?;
    if !output.success() {
        return Err(failed());
    }
    let value: Output = serde_json::from_slice(&output.stdout).map_err(|_| failed())?;
    if value.version != 1 || value.key.is_empty() || value.secret.is_empty() {
        return Err(failed());
    }
    Ok(Credential {
        access_key_id: value.key,
        secret_access_key: value.secret,
        session_token: (!value.token.is_empty()).then_some(value.token),
        expires_in: value.expiration,
    })
}

// Go time.Time JSON accepts RFC3339, while jiff also accepts a space/lowercase
// separator. Keep these broader representations from silently becoming valid.
pub(super) fn parse_expiration(text: &str) -> reqsign_core::Result<Timestamp> {
    let bytes = text.as_bytes();
    let offset = bytes.len().checked_sub(6).map(|i| &bytes[i..]);
    if bytes.get(10) != Some(&b'T')
        || !(text.ends_with('Z')
            || offset.is_some_and(|v| matches!(v[0], b'+' | b'-') && v[3] == b':'))
    {
        return Err(failed());
    }
    text.parse().map_err(|_| failed())
}

#[derive(Default)]
struct Output {
    version: i64,
    key: String,
    secret: String,
    token: String,
    expiration: Option<Timestamp>,
}
impl<'de> Deserialize<'de> for Output {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Output;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("credential process object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Output, M::Error> {
                let mut value = Output::default();
                // Go encoding/json matches known fields case-insensitively,
                // consumes duplicates in input order and ignores null strings.
                while let Some(key) = map.next_key::<String>()? {
                    match key.to_ascii_lowercase().as_str() {
                        "version" => {
                            if let Some(version) = map.next_value::<Option<i64>>()? {
                                value.version = version;
                            }
                        }
                        "accesskeyid" | "secretaccesskey" | "sessiontoken" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                match key.to_ascii_lowercase().as_str() {
                                    "accesskeyid" => value.key = text,
                                    "secretaccesskey" => value.secret = text,
                                    _ => value.token = text,
                                }
                            }
                        }
                        "accountid" => {
                            let _ = map.next_value::<Option<String>>()?;
                        }
                        "expiration" => {
                            value.expiration = map
                                .next_value::<Option<String>>()?
                                .map(|text| {
                                    parse_expiration(&text).map_err(serde::de::Error::custom)
                                })
                                .transpose()?;
                        }
                        _ => {
                            let _ = map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(Fields)
    }
}
fn failed() -> reqsign_core::Error {
    reqsign_core::Error::credential_invalid("AWS process credential unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::{Arc, Mutex};
    #[derive(Deserialize)]
    struct Case {
        calls: usize,
        name: String,
        output: String,
        command: String,
        program: String,
        args: Option<Vec<String>>,
        error: bool,
        key: String,
        token: String,
        expiration: String,
    }
    type Calls = Arc<Mutex<Vec<(String, Vec<String>)>>>;
    #[derive(Debug, Clone)]
    struct Io {
        output: Vec<u8>,
        status: i32,
        calls: Calls,
    }
    impl reqsign_core::FileRead for Io {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            if path.ends_with("/config") {
                Ok(b"[default]\ncredential_process=fixture-command\n".to_vec())
            } else {
                Err(failed())
            }
        }
    }
    impl reqsign_core::CommandExecute for Io {
        async fn command_execute(
            &self,
            program: &str,
            args: &[&str],
        ) -> reqsign_core::Result<reqsign_core::CommandOutput> {
            self.calls
                .lock()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .push((program.into(), args.iter().map(|s| (*s).into()).collect()));
            Ok(reqsign_core::CommandOutput {
                status: self.status,
                stdout: self.output.clone(),
                stderr: b"private process stderr".to_vec(),
            })
        }
    }
    #[tokio::test]
    async fn command_and_output_match_actual_go() {
        let rows: Vec<Case> = serde_json::from_str(include_str!("../testdata/aws-process-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(rows.len(), 20);
        for row in rows {
            let io = Io {
                output: row.output.as_bytes().to_vec(),
                status: if row.name == "nonzero-exit" { 7 } else { 0 },
                calls: Arc::default(),
            };
            let ctx = Context::new().with_command_execute(io.clone());
            let result = retrieve(&ctx, &row.command).await;
            assert_eq!(result.is_err(), row.error, "{}", row.name);
            if let Ok(value) = result {
                assert_eq!(value.access_key_id, row.key, "{}", row.name);
                assert_eq!(
                    value.session_token.unwrap_or_default(),
                    row.token,
                    "{}",
                    row.name
                );
                assert_eq!(
                    value.expires_in.map(|v| v.to_string()).unwrap_or_default(),
                    row.expiration,
                    "{}",
                    row.name
                );
            }
            let calls = io.calls.lock().unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                row.calls,
                if row.command.is_empty() {
                    0
                } else if row.name == "already-expired-returned" {
                    2
                } else {
                    1
                }
            );
            if row.command.is_empty() {
                assert!(calls.is_empty());
            } else {
                assert_eq!(
                    *calls,
                    [(row.program, row.args.unwrap_or_default())],
                    "{}",
                    row.name
                );
            }
        }
    }
    #[tokio::test]
    async fn cache_uses_reported_expiration_without_discarding_freshly_returned_keys() {
        let rows: Vec<Case> = serde_json::from_str(include_str!("../testdata/aws-process-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        for row in rows.into_iter().filter(|r| {
            ["quoted-command", "temporary", "already-expired-returned"].contains(&r.name.as_str())
        }) {
            let io = Io {
                output: row.output.as_bytes().to_vec(),
                status: 0,
                calls: Arc::default(),
            };
            let ctx = Context::new()
                .with_env(reqsign_core::StaticEnv {
                    home_dir: Some("/fixture".into()),
                    envs: std::collections::HashMap::default(),
                })
                .with_file_read(io.clone())
                .with_command_execute(io.clone());
            let signer = crate::cloud_aws::AwsSigner::new(
                &control_config::AwsMeteringConfig::default(),
                "us-east-1".into(),
                None,
                ctx,
            )
            .await
            .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(
                io.calls
                    .lock()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .is_empty()
            );
            for _ in 0..2 {
                assert_eq!(
                    signer
                        .credential()
                        .await
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .access_key_id,
                    row.key
                );
            }
            assert_eq!(
                io.calls
                    .lock()
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .len(),
                row.calls,
                "{} Go cache calls",
                row.name
            );
        }
    }

    #[tokio::test]
    async fn real_bounded_shell_preserves_quoted_process_output() {
        let rows: Vec<Case> = serde_json::from_str(include_str!("../testdata/aws-process-go.json"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        let row = rows
            .into_iter()
            .find(|row| row.name == "quoted-command")
            .unwrap_or_else(|| unreachable!());
        let ctx = Context::new()
            .with_command_execute(crate::cloud_context::CloudIo(reqwest::Client::new()));
        assert_eq!(
            retrieve(&ctx, &row.command)
                .await
                .unwrap_or_else(|e| unreachable!("{e}"))
                .access_key_id,
            row.key
        );
    }
}
