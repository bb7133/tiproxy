# Native factor comparison (222-3 / 2B-1)

This implements the factor/read-window portion of frozen [v1.1](read-contract.md)
on main 91f2529e. It does not activate Rust routing. The three native factor
entry points, including their returned values and advice, are compared; actual
selector/reservation decisions and scheduler timing remain the next slice.
Producer capability metadata and successfully compared evaluation counts are
separate. `selection=false` and `scheduler=false` remain explicit.

## Capture and computation

The opt-in server installs the native namespace factory before Init. Existing
custom-policy observation constructors keep v2. The native factory binds the
concrete ClusterReader before query registration. A policy copies each actual
getter/query/clock result once into a leased arena. An unchanged query timestamp
retains Go history even if registration, publication or source identity changes.
Health's conditional failure/total reads and retained prior query results are
preserved. No capture pointer is stored in production QueryResult history.

Each of the three former time.Since sites captures one Now and uses that same
value for both the Go Sub branch and the tape. Callsite checks reject a second
Since/Now; behavioral fixtures and the single-time/shared-window equivalence
test verify the resulting history. Publication follows the actual method return
inside the same Group critical section, before reserve or unlock. The compiling
unlock fault is killed by a queued real SetConfig interleaving.

Rust consumes ordered values through the same pure score, history and advice
phases used by the existing staged factor API. Production account/source fences
stay in the existing adapter; shadow never constructs those capabilities. Scores
are computed before accepting the equal-score sort order. Reads, getter presence,
routeability, advice order, returned positions and floating values must then
match. Missing Begin, gaps, invalid/foreign owners or malformed preludes cannot
recover by later data. The lifecycle mirror independently verifies group/account
membership and observed physical/score counts before factor computation.

## Numeric domains and cross-machine replay

The v3 native owner prelude requires `go_arch`, exactly `amd64` or `arm64`, beside
the pinned Go version, origin and owner-local zero-time identity. All owners in a
process/nonce must agree. Other architectures cannot install native qualification.
A capture from architecture A uses A's semantics on every Rust replay host.

Go 1.25.12 lowers float64-to-int64 to CVTTSD2SQ on AMD64 and FCVTZSD on ARM64
(`cmd/compile/internal/ssa/_gen/{AMD64,ARM64}.rules`). AMD64 invalid, NaN and
out-of-range results use i64::MIN; ARM64 saturates, with NaN becoming zero. The
shared conversion explicitly selects these semantics for the CPU score cast and
both memory horizon casts. The existing staged Rust API keeps its prior
saturating conversion. Go uint-to-int status-port formatting preserves the full
64-bit pattern. NaN connection-ratio advice retains Go's comparison behavior.

Health generalMetric2Value converts MetricFamily values before publication.
Its real producer conversion belongs in the raw numeric oracle; replay consumes
the captured IEEE QueryResult value without converting it again. The oracle runs
all four sites on NaN, infinities, positive/negative overflow, adjacent
representable values at the signed boundary and ordinary exact integers. Note
that float64 cannot distinguish i64::MAX from 2^63; nextafter supplies the true
representable neighbors. AMD64 CI generates real AMD64 Go observations. A
Rosetta-capable ARM64 Mac additionally executes an AMD64 Go binary and replays
both architectures with its native ARM64 Rust binary. No fixture is relabeled.

Go time.Time raw equality includes Location identity and monotonic state. Add,
Sub and sample-timestamp wrapping retain their separate arithmetic domains.
Only floating scalar results use the frozen tolerance; discrete fields and
nonfinite tags must match exactly.

## Memory admission and atomic progress

Go keeps the frozen 4096-record/64MiB joint budget, 1MiB evaluation lease,
512KiB encoded body, 64 accounts, six query kinds, 4096 samples, 64 clock reads,
128 tape items, 512-byte strings and 64KiB total strings. Fixed header, copy
storage and encoding storage fit that lease. Idle arenas remain charged, may be
evicted by v2 admission, and writer-owned storage stays charged until Release.

Rust retains at most 64MiB of native metadata/history plus current staging.
Before allocating an incoming frame it charges 32 times prefix+body bytes. The
strict decoder's arrays grow within fixed limits; the charge covers input,
wire/domain overlap, vector growth and retained-query copies. Numeric strings
are canonical and no arbitrary labels/maps survive decoding. Before cloning an
existing group it additionally admits that group's complete retained charge
and 1MiB for new cache nodes/keys and temporary rows. Retained accounting includes
vector capacities, owned strings, cached queries and conservative B-tree node
charges (16 entry slots per entry, exceeding the 11-key node layout). The small
64-account temporary/cache growth fits the separate 1MiB allowance; query growth
is already included in the frame charge.

A complete evaluation runs on the admitted private clone. Only full independent
agreement commits both history and owner sequence. A failure keeps the preceding
history and compared prefix, then makes the owner invalid. Equality/+1 tests
cover the incoming charge, existing clone and stage allowance, and a fault that
mutates old history before comparison is independently detected.

## Qualification and startup diagnostics

`make controlplane-cproute-native-evidence` runs fresh real Go numeric/factor
oracles, actual mixed Group/lifecycle frames, strict codec and atomic history
checks, effect isolation, compiling faults, a finite real UDS smoke test, then
all nine balance/routing combinations with observation disabled and enabled.
Every sustained window keeps 60 seconds, two owners, two groups per owner,
eight clients, 12,000 accepted lifecycle operations, 1,200 backend
publications and 120 actual router config updates. The balance/routing combination
stays fixed while the applied connection ratio alternates. Resource/Location use actual ClusterReader registrations and
Prometheus HTTP publications; query provenance is never fixture-assigned. Final
independent counts must be zero and both admitted tails must have been compared.
The old v1/v2, read-foundation, time and other CP gates remain separate and intact.
The new CI job has a separate 45-minute budget.

The test process confirms the consumer's UDS connection on stdout before
starting the fixed workload. That coordination is outside the one-way
observation protocol. Production still does not wait for a peer after binding.
An initial failure run started traffic before the consumer connection and filled
the leased queue: its first owner record was Capacity, with no Begin and no
compared prefix. That failed run is retained in the review evidence. The startup
counterexample distinguishes it from an already connected reader that consumes
Begin and then stalls, which retains that prefix and ends with TransportLost.
Neither failure can be repaired by reconnecting, nor treated as a passing window.


The timed run uses a test-only policy decorator to record each actual native
factor call and arena seal. Its Go overlay changes only Group's concrete type
assertion to the decorator's forwarding interface and removes the unused import;
production still binds and recognizes the concrete native factor. Untimed full
windows and the finite UDS/namespace/publication-race checks use the original
factory path. Both enabled and disabled timed windows run the same decorator.
Call durations include computation plus capture, while `capture_seal` measures
only finalization, not total copy CPU time. Cycle and redirect lock-hold samples
remain separately reported. Rust reports current retained charge and the highest
admitted retained + decode + clone/stage charge, bounded by 64MiB. These are
charged conservative memory bounds, not RSS measurements.
