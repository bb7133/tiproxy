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

//! Pinned Go adaptive retry send-rate limiter. The retry quota remains separate.
use std::{
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

pub(crate) struct Limiter {
    base: Instant,
    epoch: f64,
    state: Mutex<State>,
}
struct State {
    enabled: bool,
    fill_rate: f64,
    last_refilled: Option<f64>,
    measured: f64,
    last_bucket: f64,
    requests: f64,
    max_rate: f64,
    last_throttle: f64,
    tokens: f64,
    capacity: f64,
}
impl Limiter {
    pub(crate) fn new() -> Self {
        Self::at(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        )
    }
    pub(crate) fn at(epoch: f64) -> Self {
        Self {
            base: Instant::now(),
            epoch,
            state: Mutex::new(State {
                enabled: false,
                fill_rate: 0.0,
                last_refilled: None,
                measured: 0.0,
                last_bucket: epoch.floor(),
                requests: 0.0,
                max_rate: 0.0,
                last_throttle: 0.0,
                tokens: 0.0,
                capacity: 0.0,
            }),
        }
    }
    fn now(&self) -> f64 {
        self.base.elapsed().as_secs_f64()
    }
    pub(crate) async fn acquire(&self) {
        loop {
            let delay = {
                let mut s = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !s.enabled {
                    return;
                }
                s.refill(self.now());
                if s.tokens >= 1.0 {
                    s.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - s.tokens) / s.fill_rate)
            };
            // Tokio timers have millisecond precision. A positive sub-tick
            // deficit must yield instead of spinning on an already-ready timer.
            tokio::time::sleep(delay.max(Duration::from_millis(1))).await;
        }
    }
    pub(crate) fn update(&self, throttled: bool) {
        let now = self.now();
        let mut s = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = ((self.epoch + now) * 2.0).floor() / 2.0;
        s.requests += 1.0;
        if bucket > s.last_bucket {
            s.measured = 0.8 * s.requests / (bucket - s.last_bucket) + (1.0 - 0.8) * s.measured;
            s.requests = 0.0;
            s.last_bucket = bucket;
        }
        let rate = if throttled {
            s.max_rate = if s.enabled {
                s.measured.min(s.fill_rate)
            } else {
                s.measured
            };
            s.last_throttle = now;
            s.enabled = true;
            0.7 * s.max_rate
        } else {
            let window = (s.max_rate * (1.0 - 0.7) / 0.4).powf(1.0 / 3.0);
            0.4 * (now - s.last_throttle - window).powi(3) + s.max_rate
        };
        let rate = rate.min(2.0 * s.measured);
        s.refill(now);
        s.fill_rate = rate.max(0.5);
        s.capacity = rate.max(1.0);
        s.tokens = s.tokens.min(s.capacity);
    }
}
impl State {
    fn refill(&mut self, now: f64) {
        if let Some(last) = self.last_refilled {
            self.tokens = (self.tokens + (now - last) * self.fill_rate).min(self.capacity);
        }
        self.last_refilled = Some(now);
    }
}
