// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

import "unicode/utf8"

// RouterMatch preserves one actual Group.Match visit, including absence of a
// String read (MatchAll or nil address). The returned bool is a witness only.
type RouterMatch struct {
	Group                          uint64
	AddressRead, Matched, Complete bool
	Address                        DataRef
}

// RouterRoute is the outer routeOnce prefix. It shares one parent and span
// with the complete GroupRoute or the router-only RouteRejected child.
type RouterRoute struct {
	ID, Generation, Session, Next uint64
	Attempt                       uint8
	Rule                          MetadataRule
	ObserverError                 SelectorErrorClass
	Groups, Excluded              [MaxCallerGroups]uint64
	GroupCount, ExcludedCount     uint16
	Reads                         [MaxCallerGroups]RouterMatch
	ReadCount                     uint16
	PortVisited, DetectorPresent  bool
	Listener                      DataRef
	StringBytes                   uint32
	Target, Backend               uint64
	Error                         SelectorErrorClass
	ResultSet                     bool
}

func (c *Caller) CaptureRouterRoute(id, generation, session, next uint64, attempt uint8, rule MetadataRule, observerError SelectorErrorClass) bool {
	if !c.writable() {
		return false
	}
	if id == 0 || generation == 0 || session == 0 || next == 0 || attempt < 1 || attempt > 2 || rule < MetadataRuleAll || rule > MetadataRulePort || !validSelectorErrorClass(observerError) || c.length != 0 || c.children != 0 || c.storage.routerRoute.ID != 0 || c.storage.route.ID != 0 || c.storage.balance.ID != 0 || c.storage.finish.ID != 0 || c.storage.selector.Kind != 0 || c.storage.pass.Kind != 0 || c.storage.metadata.Kind != 0 {
		c.Fail(Malformed)
		return false
	}
	c.storage.routerRoute = RouterRoute{ID: id, Generation: generation, Session: session, Next: next, Attempt: attempt, Rule: rule, ObserverError: observerError}
	return true
}

func (c *Caller) routerRouteWritable() bool {
	if !c.writable() {
		return false
	}
	if c.storage.routerRoute.ID == 0 || c.storage.routerRoute.ResultSet {
		c.Fail(Malformed)
		return false
	}
	return true
}

func (c *Caller) CaptureRouterIdentity(id uint64, excluded bool) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if id == 0 || r.ReadCount != 0 || r.PortVisited || c.children != 0 {
		c.Fail(Malformed)
		return false
	}
	ids, count := &r.Groups, &r.GroupCount
	if excluded {
		ids, count = &r.Excluded, &r.ExcludedCount
	}
	if *count >= MaxCallerGroups {
		c.Fail(Capacity)
		return false
	}
	for _, previous := range ids[:*count] {
		if previous == id {
			c.Fail(Malformed)
			return false
		}
	}
	ids[*count] = id
	*count++
	return true
}

func (c *Caller) BeginRouterMatch(group uint64) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if r.ObserverError != SelectorNoError || r.Rule == MetadataRulePort || r.PortVisited || r.ReadCount >= r.GroupCount || r.Groups[r.ReadCount] != group || r.ReadCount > 0 && (!r.Reads[r.ReadCount-1].Complete || r.Reads[r.ReadCount-1].Matched) {
		c.Fail(Malformed)
		return false
	}
	r.Reads[r.ReadCount] = RouterMatch{Group: group}
	r.ReadCount++
	return true
}

func (c *Caller) routerText(value string) (DataRef, bool) {
	r := &c.storage.routerRoute
	if len(value) > MaxEvaluationStringBytes || len(value) > MaxEvaluationStringsBytes-int(r.StringBytes) {
		c.Fail(Capacity)
		return DataRef{}, false
	}
	if !utf8.ValidString(value) {
		c.Fail(Malformed)
		return DataRef{}, false
	}
	ref := DataRef{Offset: uint32(c.length), Length: uint32(len(value))}
	if !c.appendBytes([]byte(value)) {
		return DataRef{}, false
	}
	r.StringBytes += uint32(len(value))
	return ref, true
}

// CaptureRouterAddress runs only after the original addr.String() read and
// before parsing its result. It never invokes an address method itself.
func (c *Caller) CaptureRouterAddress(value string) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if r.ReadCount == 0 || r.Rule != MetadataRuleClientCIDR && r.Rule != MetadataRuleProxyCIDR {
		c.Fail(Malformed)
		return false
	}
	read := &r.Reads[r.ReadCount-1]
	if read.Complete || read.AddressRead {
		c.Fail(Malformed)
		return false
	}
	ref, ok := c.routerText(value)
	if !ok {
		return false
	}
	read.Address, read.AddressRead = ref, true
	return true
}

func (c *Caller) EndRouterMatch(matched bool) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if r.ReadCount == 0 || r.Reads[r.ReadCount-1].Complete {
		c.Fail(Malformed)
		return false
	}
	r.Reads[r.ReadCount-1].Matched, r.Reads[r.ReadCount-1].Complete = matched, true
	return true
}

func (c *Caller) CaptureRouterPort(detector bool, listener string) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if r.ObserverError != SelectorNoError || r.Rule != MetadataRulePort || r.PortVisited || r.ReadCount != 0 || !detector && listener != "" {
		c.Fail(Malformed)
		return false
	}
	r.PortVisited, r.DetectorPresent = true, detector
	if detector {
		ref, ok := c.routerText(listener)
		if !ok {
			return false
		}
		r.Listener = ref
	}
	return true
}

func (c *Caller) CaptureRouterTarget(group uint64) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if group == 0 || r.Target != 0 || r.ObserverError != SelectorNoError {
		c.Fail(Malformed)
		return false
	}
	r.Target = group
	return true
}

func (c *Caller) CaptureRouterResult(backend uint64, kind SelectorErrorClass) bool {
	if !c.routerRouteWritable() {
		return false
	}
	r := &c.storage.routerRoute
	if !validSelectorErrorClass(kind) || (backend == 0) != (kind != SelectorNoError) || backend != 0 && r.Target == 0 || r.ReadCount > 0 && !r.Reads[r.ReadCount-1].Complete {
		c.Fail(Malformed)
		return false
	}
	r.Backend, r.Error, r.ResultSet = backend, kind, true
	return true
}

// RouterRouteID is available while the parent is being composed under its lock.
func (c *Caller) RouterRouteID() uint64 {
	if c == nil || c.released.Load() {
		return 0
	}
	return c.storage.routerRoute.ID
}

func (c *Caller) RouterRoute() *RouterRoute {
	if c == nil || !c.sealed || c.released.Load() || c.storage.routerRoute.ID == 0 {
		return nil
	}
	return &c.storage.routerRoute
}
