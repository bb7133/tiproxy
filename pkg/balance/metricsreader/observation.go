// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package metricsreader

import (
	"math"
	"sync"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
)

// QueryProvenance travels with the actual returned result. Publication and its
// registration describe when that immutable result was built; ReadRegistration
// separately describes the registration still present at the getter's lock.
// These diagnostics never key a factor cache or authorize a production action.
type QueryProvenance struct {
	// Invalid is Go-local metadata, never a v3 read item. A bound observation
	// owner is already permanently Invalid before this value can be returned.
	Invalid          observation.InvalidReason
	Cluster          uint64
	SourceGeneration uint64
	Source           int32
	Producer         uint64
	Registration     uint64
	Publication      uint64
	ReadRegistration uint64
}

// Distinct reader incarnations share a checked process-local diagnostic space.
// Exhaustion remains zero forever, making future observation unqualifiable;
// it does not prevent Go from publishing or using its real metrics.
var readerIdentities struct {
	sync.Mutex
	next uint64
}

func nextReaderIdentity() uint64 {
	readerIdentities.Lock()
	defer readerIdentities.Unlock()
	if readerIdentities.next == math.MaxUint64 {
		return 0
	}
	readerIdentities.next++
	return readerIdentities.next
}

// queryLineage is accessed only under its reader's existing mutex. No retained
// tombstone map is needed: old immutable results carry their own registration.
type queryLineage struct {
	producer   uint64
	sequence   uint64
	registered map[string]uint64
	owners     diagnosticOwners
}

func newQueryLineage() queryLineage {
	return queryLineage{producer: nextReaderIdentity(), registered: make(map[string]uint64)}
}

func (q *queryLineage) next() uint64 {
	if q.sequence == math.MaxUint64 {
		q.owners.invalidate(observation.SequenceExhausted)
		return 0
	}
	q.sequence++
	return q.sequence
}

func (q *queryLineage) add(key string) {
	if q.registered == nil {
		q.registered = make(map[string]uint64)
	}
	q.registered[key] = q.next()
}

func (q *queryLineage) publication(registration uint64) QueryProvenance {
	return QueryProvenance{Producer: q.producer, Registration: registration, Publication: q.next()}
}

func (q *queryLineage) read(key string, result QueryResult) QueryResult {
	// Missing publications still identify the reader that returned no value.
	// Existing publications retain their original identity even after removal.
	if result.Provenance.Publication == 0 {
		result.Provenance.Producer = q.producer
	}
	result.Provenance.ReadRegistration = q.registered[key]
	result.Provenance.Invalid = q.owners.failure
	if q.producer == 0 {
		result.Provenance.Invalid = observation.SequenceExhausted
	}
	return result
}

// sourceSelection is immutable after publication. One acquire load determines
// BOTH the reader to call and the generation copied onto its returned value.
type sourceSelection struct {
	kind       int32
	generation uint64
}

func (dmr *ClusterReader) sourceKind() int32 {
	if selected := dmr.source.Load(); selected != nil {
		return selected.kind
	}
	return sourceNone
}

// diagnosticOwners retains only bounded observation metadata, never a routing
// object or arbitrary callback. The caller holds the source/reader's existing
// mutex. Invalidation touches only Owner's atomic reason and nonblocking wake.
type diagnosticOwners struct {
	owners  []*observation.Owner
	failure observation.InvalidReason
}

func (d *diagnosticOwners) bind(owner *observation.Owner) {
	if !owner.Enabled() {
		return
	}
	if d.failure != observation.Valid {
		owner.Invalidate(d.failure)
		return
	}
	for _, existing := range d.owners {
		if existing == owner {
			return
		}
	}
	if len(d.owners) >= observation.MaxOwners {
		d.invalidate(observation.Capacity)
		owner.Invalidate(observation.Capacity)
		return
	}
	d.owners = append(d.owners, owner)
}

func (d *diagnosticOwners) invalidate(reason observation.InvalidReason) {
	if d.failure != observation.Valid {
		return
	}
	d.failure = reason
	for _, owner := range d.owners {
		owner.Invalidate(reason)
	}
}

// BindObservationOwner is a prerequisite for the future native factor
// constructor, before policy Init. It establishes loss notification only; it
// cannot install a recorder into a running policy or qualify missing history.
// Repeated group bindings of the same owner do not consume extra registry slots.
func (dmr *ClusterReader) BindObservationOwner(owner *observation.Owner) {
	if !owner.Enabled() {
		return
	}
	dmr.sourceMu.Lock()
	defer dmr.sourceMu.Unlock()
	if selected := dmr.source.Load(); dmr.identity == 0 || selected != nil && selected.generation == 0 {
		dmr.observationOwners.invalidate(observation.SequenceExhausted)
	}
	dmr.observationOwners.bind(owner)
	dmr.promReader.Lock()
	if dmr.promReader.lineage.producer == 0 {
		dmr.promReader.lineage.owners.invalidate(observation.SequenceExhausted)
	}
	dmr.promReader.lineage.owners.bind(owner)
	dmr.promReader.Unlock()
	dmr.backendReader.Lock()
	if dmr.backendReader.lineage.producer == 0 {
		dmr.backendReader.lineage.owners.invalidate(observation.SequenceExhausted)
	}
	dmr.backendReader.lineage.owners.bind(owner)
	dmr.backendReader.Unlock()
}
