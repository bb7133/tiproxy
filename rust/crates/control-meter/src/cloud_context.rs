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

//! Bounded adapters for cloud credential providers. Raw SDK errors stay private.

use std::io;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use reqsign_core::{CommandExecute, CommandOutput, Context, FileRead, HttpSend, OsEnv};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_CREDENTIAL_BYTES: u64 = 4 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub(crate) struct CloudIo(pub reqwest::Client);

pub(crate) fn context(client: reqwest::Client) -> Context {
    let io = CloudIo(client);
    Context::new()
        .with_env(OsEnv)
        .with_file_read(io.clone())
        .with_command_execute(io.clone())
        .with_http_send(io)
}

fn failed() -> reqsign_core::Error {
    reqsign_core::Error::unexpected("cloud credential I/O failed")
}

async fn read_bounded(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>, io::Error> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(io::Error::other("credential input exceeds bound"));
    }
    Ok(bytes)
}

impl FileRead for CloudIo {
    async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|error| failed().with_source(error))?;
        tokio::time::timeout(DEADLINE, read_bounded(file))
            .await
            .map_err(|_| failed())?
            .map_err(|_| failed())
    }
}

impl CommandExecute for CloudIo {
    async fn command_execute(
        &self,
        program: &str,
        args: &[&str],
    ) -> reqsign_core::Result<CommandOutput> {
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| failed())?;
        let stdout = child.stdout.take().ok_or_else(failed)?;
        let stderr = child.stderr.take().ok_or_else(failed)?;
        let (stdout, stderr, status) = tokio::time::timeout(DEADLINE, async {
            tokio::try_join!(read_bounded(stdout), read_bounded(stderr), child.wait())
        })
        .await
        .map_err(|_| failed())?
        .map_err(|_| failed())?;
        Ok(CommandOutput {
            status: status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }
}

impl HttpSend for CloudIo {
    async fn http_send(
        &self,
        request: http::Request<Bytes>,
    ) -> reqsign_core::Result<http::Response<Bytes>> {
        let (parts, body) = request.into_parts();
        let mut response = self
            .0
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| failed())?;
        let mut result = http::Response::builder().status(response.status());
        if let Some(headers) = result.headers_mut() {
            *headers = response.headers().clone();
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| failed())? {
            if body.len().saturating_add(chunk.len()) as u64 > MAX_CREDENTIAL_BYTES {
                return Err(failed());
            }
            body.extend_from_slice(&chunk);
        }
        result.body(Bytes::from(body)).map_err(|_| failed())
    }
}

pub(crate) fn not_found(error: &reqsign_core::Error) -> bool {
    use std::error::Error as _;
    error
        .source()
        .and_then(|source| source.downcast_ref::<io::Error>())
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}
