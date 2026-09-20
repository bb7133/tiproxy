# Diagnostics gRPC parity (CP-ADMIN slice 4b)

`make controlplane-cpdiag-evidence` runs `script.json` against the production
Go API server (`pkg/server/api.TestCPDiagCapture`: the h2c gin engine with the
`sysutil` diagnostics service, and the same server behind its cmux TLS branch
with auto certificates) and against the Rust admin listener
(`rust/crates/control-admin/examples/cpdiag_replay.rs`: plaintext and TLS),
both over a real gRPC wire, and compares:

- every `SearchLog` case packet by packet (`time`, `level`, `message`) and by
  final status code — file resolution across rotated/gzip backups, inclusive
  windows, level bitmasks (unknown levels pass every filter), all-patterns
  matching, an invalid pattern, an empty result (one empty packet), 1024-message
  batching with the trailing partial or empty packet, and a client-cancelled
  stream (the client observes `Canceled`; the server stops scanning when the
  stream ends);
- `ServerInfo` for every request type on the plaintext side and `LoadInfo`
  under TLS: identical item inventory and pair keys, byte-identical static
  values, live values in Go's exact format, `sysctl` keys in order with
  values equal outside the script's volatile list; macOS-only gaps are
  declared per Go `GOOS` in `script.json` and must still occur (the Go
  inventory itself is printed by `serverinfo-probe`);
- an HTTP/1.1 `POST` with `Content-Type: application/grpc`, which gin's
  `grpcServer` split ignores (`ProtoMajor != 2`) and answers `404`.

The fixture files are written by both sides from the same script (`generate`
entries expand to `count` lines stamped `<stamp_prefix><i/1000:02>.<i%1000:03>
-04:00`). The Go TLS branch does not advertise `h2` through ALPN, so the Go
test runs with `GRPC_ENFORCE_ALPN_ENABLED=false`.
