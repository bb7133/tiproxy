# Rust management plane (CP-ADMIN #150)

`control-admin` reproduces the Go `pkg/server/api` surface inside the Rust
process so the operator-facing HTTP API, the diagnostics gRPC service and
`tiproxyctl` compatibility no longer depend on the Go helper. Delivery is
sliced; each slice lands with Go/Rust differential evidence, and this document
records the exact residual surface after every slice.

## Slice 1: listener, middleware, health, metrics, status

The Rust executable binds `--admin-addr <host:port>` before it marks itself
ready and serves the table below on that listener. During the two-process
phase Go keeps `api.addr`; the Rust admin port must be distinct from it, from
`rust-dataplane.metrics-owner-port` and from every SQL port. The final cutover
(#153) moves the Rust listener onto `api.addr`.

Middleware runs in the Go order: a global blocking rate limit (uber-go
`ratelimit` semantics, 100/s with ten slots of slack, never `429`), the
readiness gate (`500 "service not ready"` as JSON until the process is ready),
the handler, and an access log that records only method, path, status and
latency for non-2xx responses (Go logs successes at debug level, which the
Rust process does not emit). Unknown paths and unregistered methods answer
gin's `404 page not found` with `text/plain`; that includes `HEAD` on every
route, which gin never registers. Request bodies are bounded at
1 MiB; Go reads them unbounded.

TLS follows `security.server-http-tls` from the current accepted configuration
generation, read per connection so a rotated certificate applies without
rebinding. With TLS configured the first byte is sniffed like Go's `cmux`: a
TLS record reaches the full table, anything else reaches only `GET
/api/debug/health` and `GET /debug/health`. Without TLS every connection reaches
the full table over HTTP/1.1 or cleartext HTTP/2 (Go `UseH2C`). The
HTTP/1 request-head read timeout is 30 s (Go `DefConnTimeout`), and the same
30 s applies as an activity-based idle timeout to HTTP/1 and HTTP/2
connections (Go's `IdleTimeout`; hyper has no HTTP/2 equivalent, so the
listener stamps every successful read or write and closes a connection that
stays silent that long); connections are
bounded to 1024 and every connection task is tracked in a `JoinSet`, so
shutdown stops accepting, lets in-flight requests finish within 5 s, then
aborts and joins every remaining task, including peers still being sniffed,
handshaking or sending a slow body. The executable supervises the server task
like its other owners: if the listener fails, the process fails closed and
drains instead of continuing without an operator surface (Go only logs the
`Serve` error).

| Endpoint | Behaviour |
| --- | --- |
| `GET /api/debug/health`, `GET /debug/health` | `{"config_checksum":N}` with `unhealthy_reason` only when set; `502` in the Go order: manual override, closing, namespace owner not ready, no applied dataplane generation. `config_checksum` is the CRC32 of the Go-encoded TOML and is numerically identical to Go's. |
| `PUT /api/debug/health` | `{"healthy":bool,"reason":string}` decoded with `json.Decoder.Decode` semantics as gin's `ShouldBindJSON` applies them: one JSON value is read and trailing bytes are ignored, `null` is the zero value, keys match exactly or case-insensitively, unknown keys are ignored, every occurrence of a key is decoded so a wrong type anywhere is `400 "bad health override json"` and the last well-typed value wins; reason trimmed; `200 ""`. Strings in every JSON answer use Go's HTML-safe escaping (`\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`). |
| `DELETE /api/debug/health` | clears the override, `200 ""`. |
| `GET /metrics`, `/metrics/`, `/api/metrics`, `/api/metrics/` | the B0 native exposition, `text/plain; version=0.0.4; charset=utf-8; escaping=underscores`. |
| `GET /api/dataplane/status` | the Go key set in gin's sorted-map order; `desired_generation` and `sent_generation` are the latest composed generation (there is no transport hop in-process), `applied_generation`/`rejected_generation` come from SQL serving, `last_result_code` is `ERROR_CODE_INVALID_SNAPSHOT` when the latest rejection is newer than the latest apply, `ERROR_CODE_OK` after the first apply, `ERROR_CODE_UNSPECIFIED` before it. |
| `POST /api/traffic/{capture,replay,cancel}`, `GET /api/traffic/show` | `400 text/plain "traffic <verb> is disabled"`, the Go answer when `enable-traffic-replay = false`, which the Rust dataplane composition requires. |

Health inputs: `closing` is the runtime lifecycle leaving `Ready`; the
namespace-owner readiness is the config module's initial persistent view;
`applied_generation` is the SQL serving generation. Go zeroes the applied
generation while the metering consumer is unhealthy; that coupling moves to the
native metering owner (#148) when it takes ownership.

## Slice 2: namespaces and configuration

`/api/admin/namespace/*` and `/api/admin/config/` keep the Go status codes and
bodies (`namespace.go`, `config.go`) over the owner-fenced config module:

| Endpoint | Behaviour |
| --- | --- |
| `GET /api/admin/namespace/` | name-sorted JSON array of namespaces; the JSON empty string `""` when there are none (Go's nil slice). |
| `GET /api/admin/namespace/{name}` | the namespace, or `500 "can not get namespace"` (Go reports not-found through the same 500). |
| `PUT /api/admin/namespace/{name}`, `PUT /api/admin/namespace/` | body decoded with `json.Decoder` semantics against the Go `config.Namespace` field schema (one value, trailing bytes ignored, `null` = empty value, case-insensitive keys, unknown members ignored whatever their shape, `null` leaves a scalar or struct unchanged but clears a slice, duplicate struct members merge field by field, later scalars and arrays win, a known member of the wrong kind is `400 "bad namespace json"`); the path only pre-fills the name and the body's `namespace` wins and is the stored key, exactly as Go's `SetNamespace(nsc.Namespace)`; an empty name is `500 "can not update config"`; persisted below `/config/ns/<name>` through `ConfigModuleHandle::set_namespace`; `200 ""` or `500 "can not update config"`. |
| `DELETE /api/admin/namespace/{name}` | `ConfigModuleHandle::delete_namespace`; deleting an absent name succeeds like Go's B-tree; `200 ""` / `500`. |
| `POST /api/admin/namespace/commit?namespace=a&namespace=b` | query values decoded like `url.ParseQuery` (a pair with a malformed escape is dropped); every named namespace must exist (`500 "failed to get namespace"`); the call returns once the SQL serving side has applied the current CP-CFG generation, within 5 s (`500 "failed to reload namespaces"` otherwise). The barrier follows the config lineage that serving actually installed (the composer records the CP-CFG generation after each successful `reload_composed`), never the composer's own counter, which also advances on topology wakes. Namespaces reach serving through the config watch, so the commit is a barrier, not a second write. |
| `GET /api/admin/config/` | TOML (`application/toml; charset=utf-8`), or JSON with `?format=json` (case-insensitive, first value only like gin's `c.Query`) or an exact `Accept: application/json`. |
| `PUT /api/admin/config/` | Go `SetTOMLConfig` through the config owner (`ConfigModuleHandle::apply_local_toml`): the partial document is merged onto this process's file base, validated as a whole, and published only when the encoded bytes change, so the health checksum moves exactly as Go's does. The mutation is instance-scoped like the Go API (labels and other per-instance fields stay per instance) and works without etcd; the persistent `/config` overlay still applies on top. |

Namespaces therefore persist (etcd `/config/ns/*`, cluster-wide, owner-fenced)
where Go keeps them in a per-process B-tree lost on restart. That is the
intended upgrade of CP-CFG, not a compatibility slip, and it is why the
handlers never touch a second store.

### Declared divergences after slice 2

- A `PUT /api/admin/config/` that changes a restart-required field (`workdir`,
  `proxy.addr`, `proxy.advertise-addr`, `proxy.pd-addrs`, `proxy.port-range`,
  `api.*`, `log.encoder`, `log.simple`, `ha.*`, `metering.*`,
  `rust-dataplane.*`) is rejected as a whole with `500 "can not update
  config"`, even when the document also carries dynamic changes; Go accepts it
  in memory and the change silently has no effect until restart.
- Namespace JSON renders an empty instance list as `[]`; Go renders a nil
  slice as `null` and an empty slice as `[]` depending on what was PUT. The
  differential compares those bodies by decoded value with nil ≡ empty.
- Configuration TOML/JSON bodies are compared by decoded value: gin renders
  TOML through go-toml v2 (single-quoted strings) and JSON with `omitempty`
  tags; the Rust renderer emits every field with its value. Consumers that
  decode (tiproxyctl, TiDB Dashboard) see the same configuration.
- The bare `/api/admin/namespace` and `/api/admin/config` paths are served
  directly instead of gin's `301` to the slash form.

### Declared divergences after slice 1

The differential script marks each of these and fails if one stops differing:

- `/api/metrics` and `/metrics` without the trailing slash answer `200`
  directly; gin answers `301` to the slash form. Prometheus follows either.
- `/api/debug/pprof/*` answers `404`. Go serves `net/http/pprof`. Profiling of
  the Rust process is a residual CP-ADMIN item, not closed by this slice.
- `POST /api/debug/redirect` and `GET /api/backend/metrics` (slice 5) and
  `/api/dataplane/drain*` (slice 3) answer `404` until their slice lands.

### Evidence

`make controlplane-cpadmin-evidence` runs `tests/controlplane/cpadmin/run.sh`:
the production gin engine (via the api package's capture test, its unit-test
mocks and the real `ConfigManager` for namespaces and configuration) and the
Rust router over the in-memory `ConfigAdmin` (Go's per-process store
semantics) answer the same script; status, content type and body must match
exactly outside the declared list (configuration and nil-slice bodies by
decoded value), and the Go `ConfigManager`
checksum must equal the Rust `control-config` checksum for the default
configuration, a partial update, the identical update again and a
namespace-only mutation. The listener split, sniff timeout and graceful stop
are covered by the crate's own tests against real sockets and a self-signed
certificate.

## Remaining slices

- **Slice 3** — local drain/status through a dispatch query, retiring
  `drain_command`/`drain_result` (proto, catalog and Go issuer in one change),
  M9 harness on the Rust port, and the first executable runner for
  `CP-FAULT-ADMIN-DRAIN-REPLAY`.
- **Slice 4** — diagnostics gRPC (`SearchLog` over the B0 log rotation,
  `ServerInfo` with a pinned minimal host-information dependency after listing
  the Go `sysutil` fields) and `tiproxyctl` compatibility.
- **Slice 5** — `/api/backend/metrics`, `/api/debug/redirect`, retirement
  bookkeeping for `metrics_batch`, and the profiling residual.
