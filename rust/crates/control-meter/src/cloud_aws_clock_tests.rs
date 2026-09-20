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

use super::*;
use bytes::Bytes;
use http::{Request, Response};
use serde::Deserialize;
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Clone, Deserialize)]
struct Reply {
    code: String,
    date: String,
    offset: i64,
    status: u16,
}
#[derive(Deserialize)]
struct Operation {
    responses: Vec<Reply>,
    signed: Option<Vec<i64>>,
    calls: usize,
    error: bool,
}
#[derive(Deserialize)]
struct Row {
    name: String,
    web: bool,
    new: bool,
    operations: Vec<Operation>,
}
#[derive(Default)]
struct State {
    replies: Vec<Reply>,
    signed: Vec<i64>,
    calls: usize,
}
#[derive(Clone)]
struct Io {
    base: Timestamp,
    web: bool,
    state: Arc<StdMutex<State>>,
}
impl fmt::Debug for Io {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClockIo").finish_non_exhaustive()
    }
}
impl reqsign_core::FileRead for Io {
    async fn file_read(&self, _: &str) -> reqsign_core::Result<Vec<u8>> {
        Ok(b"token".to_vec())
    }
}
impl reqsign_core::HttpSend for Io {
    async fn http_send(&self, req: Request<Bytes>) -> reqsign_core::Result<Response<Bytes>> {
        let mut state = self.state.lock().unwrap_or_else(|e| unreachable!("{e}"));
        let step = state.replies[state.calls.min(state.replies.len() - 1)].clone();
        state.calls += 1;
        if let Some(date) = req.headers().get("x-amz-date") {
            let date = date.to_str().unwrap_or_else(|e| unreachable!("{e}"));
            let at = iso_date(date);
            state.signed.push(at.as_second() - self.base.as_second());
        }
        let action = if self.web {
            "AssumeRoleWithWebIdentity"
        } else {
            "AssumeRole"
        };
        let mut status = if step.status == 0 { 200 } else { step.status };
        let body = if step.code.is_empty() {
            format!(
                "<{action}Response><{action}Result><Credentials><AccessKeyId>ASIA1234567890123456</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></{action}Result></{action}Response>"
            )
        } else {
            status = 400;
            format!(
                "<ErrorResponse><Error><Code>{}</Code></Error></ErrorResponse>",
                step.code
            )
        };
        let mut response = Response::builder().status(status);
        if step.date == "http" {
            let date = Timestamp::from_second(self.base.as_second() + step.offset)
                .unwrap_or_else(|e| unreachable!("{e}"));
            response = response.header("date", date.format_http_date());
        } else if !step.date.is_empty() {
            response = response.header("date", step.date);
        }
        response.body(Bytes::from(body)).map_err(|_| failed())
    }
}
fn iso_date(value: &str) -> Timestamp {
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &value[..4],
        &value[4..6],
        &value[6..8],
        &value[9..11],
        &value[11..13],
        &value[13..15]
    )
    .parse()
    .unwrap_or_else(|e| unreachable!("{e}"))
}
#[tokio::test(start_paused = true)]
async fn sts_clock_skew_requests_and_unsigned_web_match_actual_go() {
    #[derive(Deserialize)]
    struct Fixture {
        requests: Vec<Row>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!("../testdata/aws-sts-clock-go.json"))
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(fixture.requests.len(), 64);
    for row in fixture.requests {
        let io = Io {
            base: Timestamp::now(),
            web: row.web,
            state: Arc::default(),
        };
        let ctx = Context::new()
            .with_file_read(io.clone())
            .with_http_send(io.clone())
            .with_env(reqsign_core::StaticEnv {
                home_dir: None,
                envs: std::collections::HashMap::from([(
                    "AWS_NEW_RETRIES_2026".into(),
                    row.new.to_string(),
                )]),
            });
        let retry = crate::cloud_aws_retry::Retry::new(&ctx);
        let web = WebIdentity {
            region: "us-east-1".into(),
            arn: "arn:aws:iam::123456789012:role/test".into(),
            file: "/token".into(),
            session: Some("session".into()),
            retry: crate::cloud_aws_retry::Retry::new(&ctx),
        };
        for (index, op) in row.operations.into_iter().enumerate() {
            {
                let mut state = io.state.lock().unwrap_or_else(|e| unreachable!("{e}"));
                *state = State {
                    replies: op.responses,
                    ..Default::default()
                };
            }
            let result = if row.web {
                web.retrieve(&ctx).await
            } else {
                assume_role(
                    &ctx,
                    "us-east-1",
                    None,
                    &RoleOptions {
                        arn: "arn:aws:iam::123456789012:role/test",
                        session: "session",
                        duration: 900,
                        external_id: None,
                    },
                    Credential {
                        access_key_id: "key".into(),
                        secret_access_key: "secret".into(),
                        session_token: None,
                        expires_in: None,
                    },
                    &retry,
                )
                .await
            };
            let state = io.state.lock().unwrap_or_else(|e| unreachable!("{e}"));
            let label = format!(
                "{} new={} web={} operation={index}",
                row.name, row.new, row.web
            );
            assert_eq!(result.is_err(), op.error, "{label}");
            assert_eq!(state.calls, op.calls, "{label}");
            let expected = op.signed.unwrap_or_default();
            assert_eq!(state.signed.len(), expected.len(), "{label}");
            for (a, b) in state.signed.iter().zip(expected) {
                assert!((a - b).abs() <= 1, "{label} signature offset {a} vs Go {b}");
            }
        }
    }
}
