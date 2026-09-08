# Migration ledger and bounded simulation (#222-1)

Run `make controlplane-cproute-migration-evidence`. The dedicated migration-ledger
CI job runs the same complete entry. Existing CP, factor, resource and original
reservation gates remain required.

`MigrationSimulation` creates a fresh router incarnation and a private bounded
queue containing local `Redirect` tokens. It accepts no production Router,
command sender, transport or callback. Initial reservations go through its own
`router()`; manually selected migrations go through `prepare` and `offer`.
Neither this API nor its tests constitute the observation-only shadow in
#222-3. Factor pair selection, timed rebalance and failover scheduling are
#222-2; production wiring remains #223.

## Ownership and admission

The existing ledger owns physical `active`, initial-handshake `reserved`, and
accepted redirect `incoming`/`outgoing` counts. Connection score is
`active - outgoing + reserved + incoming`; CPU inputs still read physical
active counts. Admission checks `active + reserved + incoming + 1` for u64
overflow, including capacity needed if outgoing migrations fail. This is
arithmetic protection, not a new backend connection limit.

Only established sessions can redirect. The opaque token binds the exact
router/session incarnation, checked operation sequence, retained source/target
account identities and immutable assignments. A reservation cannot be used as
a redirect token. Preparation captures authority but makes no count change.
The actual offer revalidates C/R/H, lifecycle, physical owner, target group,
routeability and keyspace under the same router mutex; capacity and sequence
checks precede the nonblocking send. An accepted send commits infallibly before
unlocking. Immediate terminals use that same lock. A rejected send records
cooldown but consumes neither counters nor the accepted sequence.

| Event | Physical counts | Redirect counts / score |
| --- | --- | --- |
| Accepted | unchanged | source outgoing+1, target incoming+1; score transfers |
| Success | source-1, target+1 | both redirect counts released; score unchanged |
| Failure | unchanged | both released; score returns to source |
| Close while pending | current physical source-1 | both released; no target session created |
| Duplicate, foreign or late terminal | unchanged | ignored |

Failure/rejection cooldown is exactly three seconds from issuance, matching
Go's `lastRedirect` behavior. A delayed failure does not restart the clock.
Success allows immediate remigration. Revocation prevents new issuance while
accepted tokens can still settle their captured owners. Pruning checks all four
counters; source score zero while migrating does not mean the owner is idle.

## Evidence

`events.tsv` drives 21 observations from actual Go `Group.Balance`,
`OnRedirectSucceed`, `OnRedirectFail` and `OnConnClosed`, then the same Rust
ledger. Only the Go clock read is overlaid; a fixed pair/rate test policy
isolates the lifecycle from #222-2 scheduler selection. Each row compares both
backends' physical/score counts, offers, accepted operations and the last
accepted issuance timestamp. Rows include pending-repeat suppression,
success-immediate migration, delayed failure, queue rejection, cooldown just
before/at equality, removal of the physical source, close and late results.
The accepted timestamp is an observer value in Rust, not a completed scheduler.

Seven ledger regressions additionally cover initial reservations versus redirects,
max-sequence/overflow, capacity retained for failure, exact account retention,
foreign equal sequences, owner recreation and actual Connection factor scores.
Four runtime tests use real config/topology/health sources and a private bounded
queue. They test full admission/revocation/settlement, final C/R/H replacement
while waiting for the actual mutex, foreign simulations and close/result races,
and immediate success/failure between queue admission and ledger commit.
The last case parks the issuer after the real send and observes the terminal's
actual lock attempt before permitting commit.

Twelve isolated semantic mutations must compile, then fail a specifically named
regression with exit101: missing physical move; missing failure score rollback;
redirect charged as an initial reservation; terminal using the latest account;
old same-pair operation sequence ignored; success adding cooldown; cooldown starting at terminal arrival; rejected offer
consuming sequence; omitted final source validation; unlocking between offer
and commit; Connection factor using physical counts; and pruning score-zero
outgoing owners. Compile failures, missing/wrong test failures and survivors
fail the gate. The restored baseline runs again. The wrapper first performs a
normal locked observer build so cold CI caches can support offline mutations.
