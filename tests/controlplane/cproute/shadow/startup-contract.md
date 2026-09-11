# Actual router initialization and first health evidence

This preparatory path is enabled only by the private startup factory before
`ScoreBasedRouter.Init`. Production factories and installed capability bits stay
unchanged. The metadata-only and router-attempt component fixtures remain
separate; they cannot acquire initialization permission midway through an owner.

Init leases its parent and registers cleanup before Subscribe/GetConfig. It
copies the original routing-rule switch input and publishes one strict
`metadata_init { raw_rule, rule }` caller after choosing the rule and before
starting the rebalance goroutine. This frame has span 1 and no children, and is
accepted only at sequence 2 immediately after owner Begin. The string is at most
512 UTF-8 bytes in the existing caller storage. No new capacity ceiling is added.
Panic, overflow or publication failure releases the parent, invalidates evidence
and preserves the original Go behavior.

Rust derives the fixed rule from the raw input, including Go's simple lowercase
mapping U+0130 to i; it does not use expanding lowercase, trimming or generic case
folding. Public Config.Check retains its exact accepted values. Initialization
establishes empty independent state at generation 0, nil observer error, false
redirection support and absent port detector. It creates no synthetic health
refresh. Snapshot and Stage clones preserve both initialized and detector flags
under the existing layout-derived memory admission.

Only this accepted initialization permits generation-0 attempts. Repeated Next
calls before health are legal; the selector tracker validates their ordinals and
empty exclusions. Their result is no Group / exact ErrNoBackend, not an observer
error. Port visits its branch but consumes no listener while the detector is nil.
The first successful Port refresh establishes the detector even for an empty
input set; error refreshes preserve its previous presence. First Begin fences
out generation 0, and the fixed rule cannot change with subsequent configuration.
The existing complete router/Group/selector transaction still commits once or
preserves its previous prefix and retained state on a late failure.

The four actual startup streams each contain one Init, seven router attempts,
seven Next Begin/End pairs, six selector Close frames, one real Finish/Created,
five health Begin/End pairs and two generation-0 attempts. Additional actual-Go
checks cover queued health/config ordering, rule boundaries, panic, capacity,
malformed UTF-8, duplicate Init and detector/listener reads. Rust tests cover
initialization identity, simple rule derivation, old component mode, duplicate
initialization, first-Begin fencing, snapshot flags and budget equality/+1.

`make controlplane-cproute-startup-evidence` runs separately from the existing
native sustained windows. Its fixed evidence contract is 12 compiling faults,
42 execution records and four distinct streams, with pristine and restored
replay of each stream (eight successful replays). Each replay performs eight
strict decode checks, four semantic corruptions rejected at their actual frame,
and one late-Init rollback probe: 64 strict checks, 32 corruptions and eight
rollback probes across pristine/restored evidence. Exactly 12 executions must
fail at their named markers; compilation failures or timeouts never count.
Summary values are computed from completed records and replay logs, then checked
against these required counts. Artifact contents include tested commit, source
and binary hashes, original framed streams, execution logs and restoration hashes.

| Compiling fault | Intended marker |
| --- | --- |
| Omit Init publication | STARTUP_INIT_PUBLISHED |
| Consume queued health before Init publication | STARTUP_BEFORE_QUEUED_HEALTH |
| Reread configuration instead of the original switch input | STARTUP_SINGLE_CONFIG_READ |
| Reload the router's fixed rule | STARTUP_FIXED_RULE |
| Treat a nil detector as an empty detector | STARTUP_NIL_IS_NOT_EMPTY |
| Consume listener before checking detector presence | STARTUP_LISTENER_AFTER_DETECTOR |
| Permit generation 0 without initialization | STARTUP_REQUIRES_INIT |
| Permit generation 0 after first Begin, using an actual stream corruption | STARTUP_CORRUPTION_ACCEPTED 3 |
| Accept duplicate initialization | STARTUP_DUPLICATE_INIT |
| Trust the Init rule witness | STARTUP_INIT_WITNESS |
| Reset detector on an observer-error refresh | STARTUP_ERROR_DETECTOR_HISTORY |
| Lose startup flags in a staged snapshot | STARTUP_SNAPSHOT_INITIALIZED |

The queued-health fault consumes a real queued result before Init publication
so the forbidden order is deterministic; it does not rely on a scheduling sleep.
The original post-unlock errors.Is refresh effect, full SetConfig/failover caller
composition, outer router passes, production v4 dispatch and sustained complete
2B2 qualification remain outside this component.
