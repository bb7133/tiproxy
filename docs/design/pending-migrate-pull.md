# Serving the migration families from authoritative state

Status: plan under the constraints CodexM5 set while reviewing `fd36e35a`
and `62795759`. Direction is accepted; the implementation is neither written
nor reviewed, and nothing here has passed.

## Why the event-driven version cannot work

`pending_migrate` is a running +1 on an accepted offer and -1 at settlement.
Both ends travel to the exporter over a bounded, lossy channel: the recorder
drops an observation when the queue is full, by design, so that a metrics
consumer can never stall a routing settlement.

A delta over a lossy transport is permanently wrong once either end is lost.
The gauge is also clamped at zero, so a lost `Issued` is absorbed silently
while a lost `Settled` leaves the series reporting a migration that already
finished, for the life of the process.

Making the event carry an absolute value is **not** sufficient. If the final
sample — the one that returns a label set to zero — is the one dropped, and
no further migration ever uses that exact `(from, to, reason)`, nothing will
ever correct it.

A second problem is independent of loss: several namespaces, and a retained
old router alongside its successor, can be migrating between the same pair of
backends for the same reason. They share one label set, so a per-router `Set`
would have each router overwrite the others rather than contribute to a total.

## Shape

Serve the family by asking authoritative state at render time.

1. The exporter collects, from every live router incarnation, the current
   pending count per `(from, to, reason)`, and sums across routers.
2. It writes those totals into the registry as absolute values.
3. A dropped or missed update is therefore only briefly stale: the next
   scrape reconstructs the whole family from state that cannot drift.

Retirement is **not** simply "drop whatever left the routing table". A router
can be retired by configuration and still own sessions with unsettled work,
and those migrations are still pending. Enumerating `RoutePlane`'s current
routing table is therefore not sufficient. A router stops contributing only
once it has no live references and no unsettled work; until then a retained
incarnation is enumerated exactly like a current one.

## Constraints this must satisfy

- **Lock order.** The settlement path already runs router lock, then registry.
  The pull path must never invert that. It takes a read-only snapshot holding
  only the router lock, releases it, and only then takes the registry lock.
  The two locks are never held at the same time, in either direction.
- **Never block routing on a metrics consumer.** The snapshot is read-only and
  bounded; the router must not wait on the exporter.
- **Keep known series at zero.** Once a label set has been observed it keeps
  reporting `0` rather than disappearing, matching Go, where a child stays
  registered once created. This is also what makes a return to zero visible
  at all. The known set cannot be derived from the current pending set: a
  migration that starts and finishes between two scrapes would never appear,
  yet Go would have created its child. The known-label set is therefore its
  own reliable, bounded structure.
- **Bound the pull side's own series,** and bound it against *its own* table.
  Defect 4 was a capacity check that consulted a different map than the one it
  was meant to limit; the replacement must not repeat that in a new location.
- **Concurrent scrapes must not move the value backwards.** Two renders can
  overlap, and an older snapshot must never overwrite shared state that a
  newer one has already written.

## The two cumulative families

An earlier draft of this document argued that `migrate_total` and
`migrate_duration_seconds` could stay purely event-driven because a dropped
sample "only undercounts once and never corrupts later values". That is a
wrong way to describe it. An increment is not idempotent, and a lost terminal
never repairs itself: the series is permanently short by that migration, and
the fact that the error stops growing does not make the value correct. It is
the same permanence as the gauge defect, only monotonic.

So these two families also keep reliable cumulative state that the scrape
reads. The event path may continue to carry the notification, but it is not
the sole source of truth for any of the three families.

Scope is exactly these three migration families. No other SQL-path metric
chain changes.
