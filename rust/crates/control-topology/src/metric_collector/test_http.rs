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

//! Owned loopback HTTP fixture; requests, bodies and holds traverse real TCP.
use super::tests::TestError;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};

pub(crate) struct Http {
    pub address: SocketAddr,
    pub requests: mpsc::UnboundedReceiver<String>,
    pub paths: Arc<Mutex<Vec<String>>>,
    hold: Arc<AtomicBool>,
    release: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}
impl Http {
    pub async fn new(body: Arc<dyn Fn(&str) -> String + Send + Sync>) -> Result<Self, TestError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (sender, requests) = mpsc::unbounded_channel();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&paths);
        let hold = Arc::new(AtomicBool::new(false));
        let pause_gate = Arc::clone(&hold);
        let release = Arc::new(Semaphore::new(0));
        let wait = Arc::clone(&release);
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((mut socket, _)) = result else { break; };
                        let sender = sender.clone(); let body = Arc::clone(&body); let recorded = Arc::clone(&recorded);
                        let pause_gate = Arc::clone(&pause_gate); let wait = Arc::clone(&wait);
                        workers.spawn(async move {
                            let mut head = Vec::new();
                            while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                                let mut byte = [0]; if socket.read_exact(&mut byte).await.is_err() { return; } head.push(byte[0]);
                            }
                            let target = String::from_utf8_lossy(&head).lines().next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_owned();
                            let body = body(&target); let hold = pause_gate.load(Ordering::SeqCst);
                            recorded.lock().unwrap_or_else(PoisonError::into_inner).push(target.clone());
                            let _ = sender.send(target);
                            if hold { let Ok(permit) = wait.acquire().await else { return; }; permit.forget(); }
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                            let _ = socket.write_all(response.as_bytes()).await;
                        });
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {}
                }
            }
            workers.shutdown().await;
        });
        Ok(Self {
            address,
            requests,
            paths,
            hold,
            release,
            task,
        })
    }
    pub async fn next(&mut self) -> Result<String, TestError> {
        tokio::time::timeout(Duration::from_secs(3), self.requests.recv())
            .await?
            .ok_or_else(|| "HTTP fixture stopped".into())
    }
    pub fn hold(&self) {
        self.hold.store(true, Ordering::SeqCst);
    }
    pub fn release(&self) {
        self.hold.store(false, Ordering::SeqCst);
        self.release.add_permits(1000);
    }
    pub fn count(&self) -> usize {
        self.paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
