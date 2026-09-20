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

//! Route table and middleware mirroring Go `pkg/server/api`.
//!
//! Middleware runs in the Go order: the global blocking rate limit
//! (`DefAPILimit` = 100/s, never `429`), the readiness gate (`500
//! "service not ready"` until the process marks itself ready), then the
//! handler; the access log observes the final status. Unknown paths and
//! methods answer gin's default `404 page not found`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, StatusCode};
use http_body_util::BodyExt;

use crate::health::{HealthInputs, HealthState};

/// Go `DefAPILimit`: requests per second admitted by the global limiter.
pub const DEFAULT_RATE_LIMIT_PER_SECOND: u32 = 100;
/// uber-go/ratelimit default slack: how many unused slots may accumulate.
const RATE_LIMIT_SLACK: u32 = 10;
/// Largest request body any admin handler reads (Go reads unbounded).
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// gin's default JSON content type.
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
/// gin's `c.String` content type.
const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
/// gin's built-in 404 body is written through `http.Error`-style plain text
/// without a charset parameter.
const NOT_FOUND_CONTENT_TYPE: &str = "text/plain";
/// Prometheus text exposition content type (`promhttp` with the pinned Go
/// client, which appends the escaping scheme).
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8; escaping=underscores";

/// Go `controlbridge.SnapshotStatus` projection, key order preserved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataplaneStatus {
    /// Whether a dataplane status source exists at all.
    pub enabled: bool,
    /// Latest generation the owner wants applied.
    pub desired_generation: u64,
    /// Latest generation handed to the serving side.
    pub sent_generation: u64,
    /// Latest generation applied to SQL serving.
    pub applied_generation: u64,
    /// Latest rejected generation.
    pub rejected_generation: u64,
    /// Proto enum name of the last apply outcome.
    pub last_result_code: String,
    /// Bounded detail of the last outcome (never a payload).
    pub detail: String,
    /// Age of the last successful apply in milliseconds.
    pub last_good_age_ms: i64,
}

impl DataplaneStatus {
    /// Renders the exact Go JSON: `{"enabled":false}` when disabled, otherwise
    /// gin's `H` map encoding, whose keys are emitted in sorted order.
    #[must_use]
    pub fn to_json(&self) -> String {
        if !self.enabled {
            return "{\"enabled\":false}".to_owned();
        }
        format!(
            "{{\"applied_generation\":{},\"desired_generation\":{},\"detail\":{},\"enabled\":true,\"last_good_age_ms\":{},\"last_result_code\":{},\"rejected_generation\":{},\"sent_generation\":{}}}",
            self.applied_generation,
            self.desired_generation,
            serde_json::Value::String(self.detail.clone()),
            self.last_good_age_ms,
            serde_json::Value::String(self.last_result_code.clone()),
            self.rejected_generation,
            self.sent_generation,
        )
    }
}

/// Process-state accessors supplied by the executable wiring.
#[derive(Clone)]
pub struct AdminHooks {
    /// Live health inputs for one probe.
    pub health_inputs: Arc<dyn Fn() -> HealthInputs + Send + Sync>,
    /// Prometheus text exposition of the process registry.
    pub metrics_text: Arc<dyn Fn() -> String + Send + Sync>,
    /// Current dataplane generation status.
    pub dataplane_status: Arc<dyn Fn() -> DataplaneStatus + Send + Sync>,
}

/// uber-go/ratelimit "leaky bucket with slack", the algorithm behind the Go
/// API's `ratelimit.New(DefAPILimit)`. `take` never rejects; it delays.
///
/// The port keeps uber's signed `sleepFor` accumulator: every reservation
/// adds one slot and subtracts the time elapsed since the previous
/// reservation, the accumulator is floored at minus the slack so idle time
/// cannot bank more than ten slots, and a positive accumulator becomes the
/// caller's delay while `last` moves to that future instant so later
/// callers queue behind it.
#[derive(Debug)]
pub struct RateLimiter {
    per_request_nanos: i128,
    max_slack_nanos: i128,
    state: Mutex<LimiterState>,
}

#[derive(Debug, Default)]
struct LimiterState {
    last: Option<Instant>,
    /// Signed debt (positive) or banked slack (negative) in nanoseconds.
    sleep_for_nanos: i128,
}

impl RateLimiter {
    /// Builds a limiter admitting `per_second` requests per second.
    #[must_use]
    pub fn new(per_second: u32) -> Self {
        let per_request = Duration::from_secs(1) / per_second.max(1);
        let per_request_nanos = nanos(per_request);
        Self {
            per_request_nanos,
            max_slack_nanos: per_request_nanos * i128::from(RATE_LIMIT_SLACK),
            state: Mutex::new(LimiterState::default()),
        }
    }

    /// Returns the delay the caller must observe before proceeding, updating
    /// the schedule as if the caller will do so.
    fn reserve(&self, now: Instant) -> Duration {
        let Ok(mut state) = self.state.lock() else {
            return Duration::ZERO;
        };
        let Some(last) = state.last else {
            state.last = Some(now);
            return Duration::ZERO;
        };
        // `last` may be in the future when the previous caller is still
        // sleeping; the signed difference then adds that caller's wait.
        let since_last = if now >= last {
            nanos(now - last)
        } else {
            -nanos(last - now)
        };
        state.sleep_for_nanos += self.per_request_nanos - since_last;
        if state.sleep_for_nanos < -self.max_slack_nanos {
            state.sleep_for_nanos = -self.max_slack_nanos;
        }
        if state.sleep_for_nanos > 0 {
            let sleep =
                Duration::from_nanos(u64::try_from(state.sleep_for_nanos).unwrap_or(u64::MAX));
            state.last = Some(now + sleep);
            state.sleep_for_nanos = 0;
            return sleep;
        }
        state.last = Some(now);
        Duration::ZERO
    }

    /// Waits for the caller's slot.
    pub async fn take(&self) {
        let delay = self.reserve(Instant::now());
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Signed nanoseconds of a duration (saturating; durations here are tiny).
fn nanos(duration: Duration) -> i128 {
    i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX)
}

/// Shared handler state.
pub struct AdminApp {
    hooks: AdminHooks,
    health: HealthState,
    ready: AtomicBool,
    limiter: RateLimiter,
}

impl AdminApp {
    /// Creates the app; the readiness gate starts closed like Go's `ready`.
    #[must_use]
    pub fn new(hooks: AdminHooks, health: HealthState) -> Self {
        Self {
            hooks,
            health,
            ready: AtomicBool::new(false),
            limiter: RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SECOND),
        }
    }

    /// Opens the readiness gate (Go toggles it at the end of `NewServer`).
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Returns the manual health override slot.
    #[must_use]
    pub const fn health(&self) -> &HealthState {
        &self.health
    }
}

/// Builds the complete route table served on the API listener.
pub fn full_router(app: Arc<AdminApp>) -> Router {
    let health = get(health_get).put(health_put).delete(health_delete);
    let router = Router::new()
        .route("/api/debug/health", health.clone())
        .route("/debug/health", health)
        .route("/metrics", get(metrics))
        .route("/metrics/", get(metrics))
        .route("/api/metrics", get(metrics))
        .route("/api/metrics/", get(metrics))
        .route("/api/dataplane/status", get(dataplane_status))
        .route(
            "/api/traffic/capture",
            axum::routing::post(traffic_disabled("capture")),
        )
        .route(
            "/api/traffic/replay",
            axum::routing::post(traffic_disabled("replay")),
        )
        .route(
            "/api/traffic/cancel",
            axum::routing::post(traffic_disabled("cancel")),
        )
        .route("/api/traffic/show", get(traffic_disabled("show")));
    with_middleware(router, app)
}

/// Builds the plaintext branch used when HTTP TLS is configured: only the
/// readiness probe, only `GET` (Go `server.go` cmux `HTTP1Fast` branch).
pub fn plaintext_router(app: Arc<AdminApp>) -> Router {
    let router = Router::new()
        .route("/api/debug/health", get(health_get))
        .route("/debug/health", get(health_get));
    with_middleware(router, app)
}

fn with_middleware(router: Router<Arc<AdminApp>>, app: Arc<AdminApp>) -> Router {
    router
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        // Layers run outermost-last: access log sees the final response,
        // then the readiness gate, then the rate limit admits the request.
        .layer(middleware::from_fn_with_state(Arc::clone(&app), ready_gate))
        .layer(middleware::from_fn_with_state(Arc::clone(&app), rate_limit))
        .layer(middleware::from_fn(access_log))
        .with_state(app)
}

async fn rate_limit(State(app): State<Arc<AdminApp>>, request: Request, next: Next) -> Response {
    app.limiter.take().await;
    next.run(request).await
}

async fn ready_gate(State(app): State<Arc<AdminApp>>, request: Request, next: Next) -> Response {
    if !app.ready.load(Ordering::Acquire) {
        return json(StatusCode::INTERNAL_SERVER_ERROR, "\"service not ready\"");
    }
    next.run(request).await
}

/// Payload-free access record for non-success responses only; Go logs
/// successes at debug level, which the Rust process does not emit.
async fn access_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    if status >= 400 {
        let line = serde_json::json!({
            "component": "control-admin",
            "event": "http_request",
            "method": method.as_str(),
            "path": path,
            "status": status,
            "latency_ms": started.elapsed().as_millis(),
        });
        control_plane::logging::emit_line(&line.to_string());
    }
    response
}

async fn not_found() -> Response {
    with_content_type(
        StatusCode::NOT_FOUND,
        NOT_FOUND_CONTENT_TYPE,
        "404 page not found".to_owned(),
    )
}

async fn health_get(State(app): State<Arc<AdminApp>>) -> Response {
    let inputs = (app.hooks.health_inputs)();
    let evaluated = app.health.evaluate(&inputs);
    json(
        StatusCode::from_u16(evaluated.status).unwrap_or(StatusCode::BAD_GATEWAY),
        &evaluated.body,
    )
}

async fn health_put(State(app): State<Arc<AdminApp>>, request: Request) -> Response {
    let Some(body) = read_body(request).await else {
        return json(StatusCode::BAD_REQUEST, "\"bad health override json\"");
    };
    // gin ShouldBindJSON: unknown keys ignored, missing keys zero-valued,
    // wrong types rejected.
    let Ok(serde_json::Value::Object(fields)) = serde_json::from_slice::<serde_json::Value>(&body)
    else {
        return json(StatusCode::BAD_REQUEST, "\"bad health override json\"");
    };
    let healthy = match fields.get("healthy") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => return json(StatusCode::BAD_REQUEST, "\"bad health override json\""),
    };
    let reason = match fields.get("reason") {
        None | Some(serde_json::Value::Null) => "",
        Some(serde_json::Value::String(value)) => value.as_str(),
        Some(_) => return json(StatusCode::BAD_REQUEST, "\"bad health override json\""),
    };
    app.health.set_override(healthy, reason);
    json(StatusCode::OK, "\"\"")
}

async fn health_delete(State(app): State<Arc<AdminApp>>) -> Response {
    app.health.clear_override();
    json(StatusCode::OK, "\"\"")
}

async fn metrics(State(app): State<Arc<AdminApp>>) -> Response {
    let body = (app.hooks.metrics_text)();
    with_content_type(StatusCode::OK, METRICS_CONTENT_TYPE, body)
}

async fn dataplane_status(State(app): State<Arc<AdminApp>>) -> Response {
    json(StatusCode::OK, &(app.hooks.dataplane_status)().to_json())
}

fn traffic_disabled(
    verb: &'static str,
) -> impl Fn() -> std::future::Ready<Response> + Clone + Send + 'static {
    move || {
        std::future::ready(text(
            StatusCode::BAD_REQUEST,
            &format!("traffic {verb} is disabled"),
        ))
    }
}

async fn read_body(request: Request) -> Option<Vec<u8>> {
    let limited = http_body_util::Limited::new(request.into_body(), MAX_BODY_BYTES);
    limited
        .collect()
        .await
        .ok()
        .map(|body| body.to_bytes().to_vec())
}

fn json(status: StatusCode, body: &str) -> Response {
    with_content_type(status, JSON_CONTENT_TYPE, body.to_owned())
}

fn text(status: StatusCode, body: &str) -> Response {
    with_content_type(status, TEXT_CONTENT_TYPE, body.to_owned())
}

fn with_content_type(status: StatusCode, content_type: &'static str, body: String) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

impl AdminHooks {
    /// Hooks returning fixed values, for tests and the plaintext branch.
    #[must_use]
    pub fn fixed(inputs: HealthInputs, metrics: String, status: DataplaneStatus) -> Self {
        Self {
            health_inputs: Arc::new(move || inputs.clone()),
            metrics_text: Arc::new(move || metrics.clone()),
            dataplane_status: Arc::new(move || status.clone()),
        }
    }
}

/// Convenience for in-process tests: runs one request through a router.
#[doc(hidden)]
pub async fn oneshot(router: Router, request: Request<Body>) -> (StatusCode, String, String) {
    use tower::ServiceExt;
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let status = response.status();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|body| String::from_utf8_lossy(&body.to_bytes()).into_owned())
        .unwrap_or_default();
    (status, content_type, body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn app(ready: bool) -> Arc<AdminApp> {
        let hooks = AdminHooks::fixed(
            HealthInputs {
                closing: false,
                namespaces_ready: true,
                applied_generation: 3,
                config_checksum: 42,
            },
            "# HELP x y\n".to_owned(),
            DataplaneStatus {
                enabled: true,
                desired_generation: 3,
                sent_generation: 3,
                applied_generation: 3,
                rejected_generation: 0,
                last_result_code: "ERROR_CODE_OK".to_owned(),
                detail: String::new(),
                last_good_age_ms: 1500,
            },
        );
        let app = Arc::new(AdminApp::new(hooks, HealthState::new()));
        if ready {
            app.mark_ready();
        }
        app
    }

    fn request(method: &str, path: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn readiness_gate_answers_500_json_before_ready() {
        let router = full_router(app(false));
        let (status, content_type, body) =
            oneshot(router, request("GET", "/api/debug/health", "")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(content_type, JSON_CONTENT_TYPE);
        assert_eq!(body, "\"service not ready\"");
    }

    #[tokio::test]
    async fn health_routes_and_override_match_go() {
        let app = app(true);
        let router = full_router(Arc::clone(&app));
        for path in ["/api/debug/health", "/debug/health"] {
            let (status, content_type, body) =
                oneshot(router.clone(), request("GET", path, "")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(content_type, JSON_CONTENT_TYPE);
            assert_eq!(body, "{\"config_checksum\":42}");
        }
        let (status, _, body) = oneshot(
            router.clone(),
            request(
                "PUT",
                "/api/debug/health",
                "{\"healthy\":false,\"reason\":\" down \"}",
            ),
        )
        .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "\"\""));
        let (status, _, body) = oneshot(router.clone(), request("GET", "/debug/health", "")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body,
            "{\"config_checksum\":42,\"unhealthy_reason\":\"down\"}"
        );
        let (status, _, body) = oneshot(
            router.clone(),
            request("PUT", "/api/debug/health", "{\"healthy\":\"yes\"}"),
        )
        .await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, "\"bad health override json\"")
        );
        let (status, _, body) = oneshot(
            router.clone(),
            request("PUT", "/api/debug/health", "{\"extra\":1}"),
        )
        .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "\"\""));
        let (status, _, body) = oneshot(router.clone(), request("GET", "/debug/health", "")).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_GATEWAY, "{\"config_checksum\":42}")
        );
        let (status, _, body) =
            oneshot(router.clone(), request("DELETE", "/debug/health", "")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "\"\""));
        let (status, _, _) = oneshot(router.clone(), request("GET", "/debug/health", "")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, content_type, body) =
            oneshot(router, request("POST", "/api/debug/health", "")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(content_type, NOT_FOUND_CONTENT_TYPE);
        assert_eq!(body, "404 page not found");
    }

    #[tokio::test]
    async fn metrics_status_traffic_and_unknown_paths() {
        let router = full_router(app(true));
        for path in ["/metrics", "/metrics/", "/api/metrics", "/api/metrics/"] {
            let (status, content_type, body) =
                oneshot(router.clone(), request("GET", path, "")).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(content_type, METRICS_CONTENT_TYPE);
            assert_eq!(body, "# HELP x y\n");
        }
        let (status, _, body) = oneshot(router.clone(), request("HEAD", "/metrics", "")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, ""));
        let (status, content_type, body) =
            oneshot(router.clone(), request("GET", "/api/dataplane/status", "")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, JSON_CONTENT_TYPE);
        assert_eq!(
            body,
            "{\"applied_generation\":3,\"desired_generation\":3,\"detail\":\"\",\"enabled\":true,\"last_good_age_ms\":1500,\"last_result_code\":\"ERROR_CODE_OK\",\"rejected_generation\":0,\"sent_generation\":3}"
        );
        for (method, path, verb) in [
            ("POST", "/api/traffic/capture", "capture"),
            ("POST", "/api/traffic/replay", "replay"),
            ("POST", "/api/traffic/cancel", "cancel"),
            ("GET", "/api/traffic/show", "show"),
        ] {
            let (status, content_type, body) =
                oneshot(router.clone(), request(method, path, "")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(content_type, TEXT_CONTENT_TYPE);
            assert_eq!(body, format!("traffic {verb} is disabled"));
        }
        let (status, _, body) =
            oneshot(router.clone(), request("GET", "/api/debug/pprof/heap", "")).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::NOT_FOUND, "404 page not found")
        );
        let (status, _, _) = oneshot(router, request("POST", "/metrics", "")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn plaintext_branch_serves_only_get_health() {
        let router = plaintext_router(app(true));
        let (status, _, _) = oneshot(router.clone(), request("GET", "/api/debug/health", "")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) =
            oneshot(router.clone(), request("PUT", "/api/debug/health", "{}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = oneshot(router, request("GET", "/metrics", "")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn disabled_status_is_the_exact_go_body() {
        assert_eq!(DataplaneStatus::default().to_json(), "{\"enabled\":false}");
    }

    #[test]
    fn rate_limiter_queues_same_instant_callers_and_caps_slack() {
        let limiter = RateLimiter::new(100);
        let start = Instant::now();
        // The very first reservation never waits.
        assert_eq!(limiter.reserve(start), Duration::ZERO);
        // Same instant: the second caller waits one slot, the third waits
        // behind it (uber keeps the queued debt when `last` is in the future).
        assert_eq!(limiter.reserve(start), Duration::from_millis(10));
        assert_eq!(limiter.reserve(start), Duration::from_millis(20));
        assert_eq!(limiter.reserve(start), Duration::from_millis(30));
        // A caller arriving exactly when the queue drains proceeds at once.
        assert_eq!(
            limiter.reserve(start + Duration::from_millis(40)),
            Duration::ZERO
        );
        // Idling for long banks at most the slack (ten slots): eleven
        // back-to-back callers pass, the twelfth waits one slot.
        let later = start + Duration::from_secs(5);
        for _ in 0..11 {
            assert_eq!(limiter.reserve(later), Duration::ZERO);
        }
        assert_eq!(limiter.reserve(later), Duration::from_millis(10));
    }
    /// Reviewer regression (`CodexM5`, `e30148d9`): queued debt must survive a
    /// `last` that already sits in the future.
    #[test]
    fn review_concurrent_rate_reservations_keep_future_debt() {
        let limiter = RateLimiter::new(100);
        let now = Instant::now();
        assert_eq!(limiter.reserve(now), Duration::ZERO);
        assert_eq!(limiter.reserve(now), Duration::from_millis(10));
        assert_eq!(limiter.reserve(now), Duration::from_millis(20));
    }
}
