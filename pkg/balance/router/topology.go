// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import "sort"

// BackendTopology is one backend's control-plane topology projection
// (DPL-07): the stable identity, placement, and health facts a control
// snapshot may carry to the Rust dataplane.
type BackendTopology struct {
	ID          string
	Addr        string
	ClusterName string
	Keyspace    string
	Healthy     bool
	Local       bool
	CIDRs       []string
	Labels      map[string]string
}

// TopologyEnumerator is implemented by routers that can enumerate their
// current backends for the control-plane topology projection.
type TopologyEnumerator interface {
	EnumerateTopology() []BackendTopology
}

// EnumerateTopology snapshots every known backend — grouped or not — in
// a deterministic order, so equal topologies project equal snapshots.
func (router *ScoreBasedRouter) EnumerateTopology() []BackendTopology {
	router.Lock()
	defer router.Unlock()
	topology := make([]BackendTopology, 0, len(router.backends))
	for id, backend := range router.backends {
		health := backend.getHealth()
		var labels map[string]string
		if len(health.Labels) > 0 {
			labels = make(map[string]string, len(health.Labels))
			for key, value := range health.Labels {
				labels[key] = value
			}
		}
		topology = append(topology, BackendTopology{
			ID:          id,
			Addr:        backend.Addr(),
			ClusterName: health.ClusterName,
			Keyspace:    backend.Keyspace(),
			Healthy:     backend.Healthy(),
			Local:       backend.Local(),
			CIDRs:       backend.Cidr(),
			Labels:      labels,
		})
	}
	sort.Slice(topology, func(i, j int) bool { return topology[i].ID < topology[j].ID })
	return topology
}
