// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/pingcap/tiproxy/pkg/balance/observation"
	"github.com/pingcap/tiproxy/pkg/balance/observer"
)

// Router metadata capture (task #90): the actual health refresh inputs and the
// actual grouping outcomes are published as header-only caller frames so a
// Rust consumer can derive the group inventory, membership, redirection gate
// and no-group/conflict/observer-error classification independently and check
// Go's outcomes as witnesses. Everything below runs under the router lock,
// copies only values the refresh already read at the site that read them, and
// changes no decision or control flow. Only the private metadata-captured
// factory enables it.
//
// Frame order per refresh: Begin (leased before the health loop, inputs
// written from inside it, published before the first Group lock), one Assign
// per backend visit published right after that visit's Group action with the
// values that visit read (an unhealthy-but-busy backend is visited twice: the
// idle decision inside the Group lock, then the ordinary group branch that
// reads its values), one Refresh per Group inside its CIDR recomputation lock
// carrying every member read and the stored result, End after the port
// conflict rebuild. Group lock sections keep their own batches in between, so
// interleaving stays real. The scratch that survives between frames is a
// bounded, charged lease taken before any producer-side allocation.

type metadataRefresh struct {
	router  *ScoreBasedRouter
	scratch *observation.MetadataScratch
	// begin is the open Begin frame between the lease and the end of the
	// health loop; nil once published or failed.
	begin  *observation.Caller
	failed bool
}

func metadataRule(matchType MatchType) observation.MetadataRule {
	switch matchType {
	case MatchClientCIDR:
		return observation.MetadataRuleClientCIDR
	case MatchProxyCIDR:
		return observation.MetadataRuleProxyCIDR
	case MatchPort:
		return observation.MetadataRulePort
	default:
		return observation.MetadataRuleAll
	}
}

// observerErrorKind keeps the exact equality class Next relies on: pointer
// equality with ErrNoBackend retries; a wrapper matching errors.Is does not.
func observerErrorKind(err error) observation.SelectorErrorClass {
	switch {
	case err == nil:
		return observation.SelectorNoError
	case err == ErrNoBackend:
		return observation.SelectorExactNoBackend
	default:
		return observation.SelectorOtherError
	}
}

// metadataIdentity gives a held backend a stable observation identity before
// it joins any Group. The first Group Account event still publishes it.
func (router *ScoreBasedRouter) metadataIdentity(backend *backendWrapper) uint64 {
	if backend.observationID == 0 && router.observation.Enabled() {
		backend.observationID = router.observation.NextIdentity()
	}
	return backend.observationID
}

// beginMetadataRefresh leases the refresh scratch and the Begin frame before
// the refresh copies or allocates anything. With an observer error the frame is
// complete at once; otherwise it stays open for the health loop's inputs. The
// caller must defer cleanup immediately. Nil means nothing is captured.
func (router *ScoreBasedRouter) beginMetadataRefresh(err error) *metadataRefresh {
	if !router.metadataCapture || router.observation == nil || !router.observation.Enabled() || !router.observation.Native() {
		return nil
	}
	router.metadataGeneration++
	scratch := router.observation.LeaseMetadataScratch(router.metadataGeneration)
	if scratch == nil {
		return nil
	}
	refresh := &metadataRefresh{router: router, scratch: scratch}
	kind := observerErrorKind(err)
	c := router.observation.BeginCaller()
	if c == nil {
		refresh.fail()
		return refresh
	}
	refresh.begin = c
	if !c.CaptureMetadataBegin(scratch.Generation, kind, metadataRule(router.matchType)) {
		refresh.fail()
		return refresh
	}
	if kind != observation.SelectorNoError {
		refresh.publishBegin()
	}
	return refresh
}

func (r *metadataRefresh) fail() {
	if r == nil {
		return
	}
	r.failed = true
	if r.begin != nil {
		r.begin.Cleanup()
		r.begin = nil
	}
}

// cleanup is the unconditional defer of the refresh: it releases an unpublished
// Begin frame and the scratch lease.
func (r *metadataRefresh) cleanup() {
	if r == nil {
		return
	}
	if r.begin != nil {
		r.begin.Cleanup()
		r.begin = nil
	}
	r.scratch.Release()
}

// dropped records a held backend the fresh list no longer contains, in the
// leased scratch; the router keeps synthesizing its unhealthy entry as before.
func (r *metadataRefresh) dropped(backend *backendWrapper) {
	if r == nil || r.failed {
		return
	}
	if !r.scratch.Dropped(r.router.metadataIdentity(backend)) {
		r.fail()
	}
}

// input copies one backend from inside the health loop. backend is nil for an
// unhealthy backend the router never held.
func (r *metadataRefresh) input(backend *backendWrapper, health *observer.BackendHealth) {
	if r == nil || r.failed || r.begin == nil {
		return
	}
	var account uint64
	if backend != nil {
		account = r.router.metadataIdentity(backend)
	}
	if !r.begin.CaptureMetadataInput(account, backend != nil, health.Healthy, health.SupportRedirection, !r.scratch.IsDropped(account)) {
		r.fail()
	}
}

// publishBegin seals the Begin frame after the health loop, before the first
// Group lock.
func (r *metadataRefresh) publishBegin() {
	if r == nil || r.failed || r.begin == nil {
		return
	}
	c := r.begin
	r.begin = nil
	if c.Seal() && r.router.observation.PublishCaller(c) {
		return
	}
	c.Cleanup()
	r.failed = true
}

// assign publishes one backend visit's actual outcome right after its Group
// action; the index follows Go's actual visit order. values is the slice the
// visit actually read, or nil with valuesRead false where Go read none.
func (r *metadataRefresh) assign(backend *backendWrapper, group *Group, removed, created, valuesRead bool, values []string) {
	if r == nil || r.failed {
		return
	}
	index, ok := r.scratch.NextIndex()
	if !ok || !r.scratch.Account(values) {
		r.failed = true
		return
	}
	if removed {
		r.scratch.Removed++
	}
	if created {
		r.scratch.Created++
	}
	var groupID uint64
	if group != nil && !removed {
		groupID = group.observationID
	}
	c := r.router.observation.BeginCaller()
	if c == nil {
		r.failed = true
		return
	}
	defer c.Cleanup()
	if c.CaptureMetadataAssign(r.scratch.Generation, index, r.router.metadataIdentity(backend), groupID, removed, created, valuesRead, values) && c.Seal() && r.router.observation.PublishCaller(c) {
		return
	}
	r.failed = true
}

// refreshObserver witnesses one Group's RefreshCidr from inside its lock: the
// frame is leased before the first member read, each Cidr() read is copied at
// the read site, and the stored result closes the frame.
type refreshObserver struct {
	r *metadataRefresh
	c *observation.Caller
}

func (r *metadataRefresh) refreshObserver() *refreshObserver {
	if r == nil || r.failed {
		return nil
	}
	return &refreshObserver{r: r}
}

// begin leases the Refresh frame; it runs inside the Group lock before any read.
func (o *refreshObserver) begin(group *Group, valuesRead bool) {
	if o == nil || o.r.failed {
		return
	}
	c := o.r.router.observation.BeginCaller()
	if c == nil || !c.CaptureMetadataRefresh(o.r.scratch.Generation, group.observationID, valuesRead) {
		c.Cleanup()
		o.r.failed = true
		return
	}
	o.c = c
}

// member copies one member's actual Cidr() read.
func (o *refreshObserver) member(account uint64, values []string) {
	if o == nil || o.c == nil {
		return
	}
	if !o.r.scratch.Account(values) || !o.c.CaptureMetadataRefreshMember(account, values) {
		o.abandon()
	}
}

// result closes and publishes the frame with the values exactly as stored.
func (o *refreshObserver) result(values []string, parsed bool) {
	if o == nil || o.c == nil {
		return
	}
	c := o.c
	o.c = nil
	defer c.Cleanup()
	if o.r.scratch.Account(values) && c.CaptureMetadataRefreshResult(values, parsed) && c.Seal() && o.r.router.observation.PublishCaller(c) {
		return
	}
	o.r.failed = true
}

func (o *refreshObserver) abandon() {
	if o.c != nil {
		o.c.Cleanup()
		o.c = nil
	}
	o.r.failed = true
}

// cleanup is the unconditional defer registered inside the Group lock right
// after begin, before the first member read: a frame still open when the
// production path unwinds (a getter or parse panic) returns its lease.
func (o *refreshObserver) cleanup() {
	if o != nil && o.c != nil {
		o.abandon()
	}
}

// end publishes the actual completion counts.
func (r *metadataRefresh) end(supportRedirection bool, refreshFailed, conflicts uint16) {
	if r == nil || r.failed || r.begin != nil {
		r.fail()
		return
	}
	c := r.router.observation.BeginCaller()
	if c == nil {
		return
	}
	defer c.Cleanup()
	if c.CaptureMetadataEnd(r.scratch.Generation, supportRedirection, uint16(len(r.router.groups)), r.scratch.Created, r.scratch.Removed, refreshFailed, conflicts) && c.Seal() {
		r.router.observation.PublishCaller(c)
	}
}
