# TiProxy Rust Module Priority

## Priority 1 — Good PoC targets
- `pkg/proxy/net/packetio.go`
- protocol encode / decode paths
- compression / packet framing
- forwarding hot path around frontend/backend relay

## Priority 2 — Good later-phase targets
- handshake internals
- backend connection state machinery
- selected redirect/migration coordination code

## Priority 3 — Keep in Go unless evidence says otherwise
- `pkg/server/`
- `pkg/server/api/`
- `pkg/manager/infosync/`
- `pkg/manager/vip/`
- general control-plane orchestration

## Why
The highest expected Rust payoff is in the data plane where protocol correctness,
memory safety, and resource control matter most.
