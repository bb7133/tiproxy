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

//! Real binding and bounded, qualified owner-history writes.

use super::{
    Arc, ClusterResult, Duration, GenerationGate, JoinSet, MetricCapture, Mutex, PoisonError,
    Shared, SocketAddr, TcpListener, owner,
};
use control_plane::OwnerToken;
use std::io;
use std::sync::OnceLock;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub(super) struct Binding {
    pub address: SocketAddr,
    gate: GenerationGate,
    owner: OnceLock<OwnerToken>,
    writes: Mutex<()>,
}
impl Binding {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            gate: GenerationGate::new(),
            owner: OnceLock::new(),
            writes: Mutex::new(()),
        }
    }
    pub fn activate(&self, owner: OwnerToken) {
        let _ = self.owner.set(owner);
    }
    pub fn is_live(&self) -> bool {
        self.gate.is_live() && self.owner.get().is_some_and(OwnerToken::is_current)
    }
    pub fn close(&self) {
        let _guard = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        self.gate.revoke();
    }
    pub(super) fn with_live<T>(&self, write: impl FnOnce() -> T) -> Option<T> {
        let _guard = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        self.is_live().then(write)
    }
}
impl control_external::IoFence for Binding {
    fn is_live(&self) -> bool {
        self.is_live()
    }
}
struct ServingGuard(Arc<Binding>);
impl Drop for ServingGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

pub(super) async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    let _guard = ServingGuard(Arc::clone(&shared.serving));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept(), if tasks.len() < 100 => {
                let Ok((socket, _)) = result else { break; };
                let shared = Arc::clone(&shared);
                tasks.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(5), handle(socket, shared)).await;
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_some_and(|result| result.is_err()) { break; }
            }
        }
    }
    shared.serving.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

struct Response {
    capture: MetricCapture,
    binding: Arc<Binding>,
    result: Option<Arc<ClusterResult>>,
    proofs: Vec<owner::Proof>,
    bytes: Arc<[u8]>,
}
impl Response {
    fn capture(shared: &Shared, cluster: &str) -> Option<Self> {
        if !shared.serving.is_live() {
            return None;
        }
        let capture = shared.source.capture()?;
        let name = if cluster.is_empty() {
            let mut names = capture.cluster_names();
            let first = names.next().map(str::to_owned);
            if names.next().is_none() { first } else { None }
        } else {
            Some(cluster.to_owned())
        };
        let result = {
            let published = shared.lock();
            if published
                .capture
                .as_ref()
                .is_some_and(|current| current.same_generation(&capture))
            {
                name.as_ref()
                    .and_then(|name| published.clusters.get(name).cloned())
            } else {
                None
            }
        };
        let result = result.filter(|result| {
            result.gate.is_live()
                && result
                    .owner
                    .as_ref()
                    .is_none_or(|owner| owner.authority.retains_local_ownership())
                && result.backend_proofs.iter().all(owner::Proof::is_live)
        });
        let (bytes, mut proofs) = result.as_ref().map_or_else(
            || (Arc::from([]), Vec::new()),
            |result| (Arc::clone(&result.export), result.backend_proofs.clone()),
        );
        if let Some(local) = result.as_ref().and_then(|result| result.owner.as_ref())
            && !proofs.iter().any(|proof| proof.is_local(local))
        {
            proofs.push(owner::Proof::Local(Arc::clone(local)));
        }
        Some(Self {
            capture,
            binding: Arc::clone(&shared.serving),
            result,
            proofs,
            bytes,
        })
    }
    fn with_current<T>(&self, write: impl FnOnce() -> T) -> Option<T> {
        self.binding
            .with_live(|| {
                self.capture
                    .with_current(|| {
                        let proofs: Vec<_> = self.proofs.iter().collect();
                        owner::with_retained(&proofs, || {
                            if self
                                .result
                                .as_ref()
                                .is_none_or(|result| result.gate.is_live())
                            {
                                Some(write())
                            } else {
                                None
                            }
                        })
                        .flatten()
                    })
                    .flatten()
            })
            .flatten()
    }
    async fn write(self, socket: &TcpStream) -> io::Result<()> {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.bytes.len()
        );
        for bytes in [header.as_bytes(), self.bytes.as_ref()] {
            let mut sent = 0;
            while sent < bytes.len() {
                socket.writable().await?;
                let end = bytes.len().min(sent + 16 * 1024);
                let result = self
                    .with_current(|| socket.try_write(&bytes[sent..end]))
                    .ok_or_else(|| io::Error::other("retired metric response"))?;
                match result {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(count) => sent += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }
}

async fn handle(mut socket: TcpStream, shared: Arc<Shared>) -> io::Result<()> {
    let mut request = Vec::with_capacity(1024);
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 8192 {
            return write_status(&socket, &shared.serving, 431).await;
        }
        let mut byte = [0];
        socket.read_exact(&mut byte).await?;
        request.push(byte[0]);
    }
    let Some(cluster) = parse_request(&request) else {
        return write_status(&socket, &shared.serving, 400).await;
    };
    let Some(response) = Response::capture(&shared, &cluster) else {
        return write_status(&socket, &shared.serving, 503).await;
    };
    response.write(&socket).await
}
async fn write_status(socket: &TcpStream, binding: &Binding, status: u16) -> io::Result<()> {
    let bytes =
        format!("HTTP/1.1 {status} Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let mut sent = 0;
    while sent < bytes.len() {
        socket.writable().await?;
        match binding
            .with_live(|| socket.try_write(&bytes.as_bytes()[sent..]))
            .ok_or_else(|| io::Error::other("retired metric listener"))?
        {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => sent += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn parse_request(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    if first.next()? != "GET" {
        return None;
    }
    let target = first.next()?;
    if !matches!(first.next()?, "HTTP/1.1" | "HTTP/1.0") || first.next().is_some() {
        return None;
    }
    if target.len() > 8192 || target.contains('#') || !target.is_ascii() {
        return None;
    }
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return None;
        }
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/api/backend/metrics" {
        return None;
    }
    for field in query.split('&') {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        if decode_query(key)?.as_str() == "cluster" {
            return decode_query(value);
        }
    }
    Some(String::new())
}
fn decode_query(value: &str) -> Option<String> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let first = char::from(bytes.next()?).to_digit(16)?;
                let second = char::from(bytes.next()?).to_digit(16)?;
                out.push(u8::try_from(first * 16 + second).ok()?);
            }
            byte => out.push(byte),
        }
        if out.len() > 4096 {
            return None;
        }
    }
    String::from_utf8(out).ok()
}
pub(super) fn encode_query(value: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(char::from(byte));
        } else if byte == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out
}

#[cfg(test)]
mod tests;
