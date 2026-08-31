// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package controlbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"

	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
)

const (
	meteringConsumerStateVersion = 1
	maxAbsoluteMeteringSnapshots = 1024
	maxMeteringKeyBytes          = 256
)

// MeteringSink is the existing Go meter seam. A non-nil sink used with the
// DPL-06 durable consumer must also implement durableMeteringSink, so a crash
// between ingestion and ACK cannot double-count or lose a checkpoint.
type MeteringSink interface {
	IncTraffic(clusterID string, respBytes, crossAZBytes int64, fromPublicEndpoint bool)
}

// MeteringDelta is one source-attributed aggregate handed to a durable sink.
// ProducerID + sequence qualify the whole slice for idempotent ingestion.
type MeteringDelta struct {
	Keyspace           string
	BackendID          string
	PublicEndpoint     bool
	ResponseBytes      uint64
	CrossLocationBytes uint64
}

type durableMeteringSink interface {
	ApplyMeteringBatch(producerID string, sequence uint64, deltas []MeteringDelta) error
	Healthy() bool
	MeteringCheckpoint() (producerID string, sequence uint64)
}

type meteringSourceKey struct {
	ConnectionID      uint64
	ProcessGeneration uint64
	BackendGeneration uint64
}

type meteringSourceBaseline struct {
	BackendID         string
	ClusterName       string
	Keyspace          string
	Local             bool
	PublicEndpoint    bool
	InboundBytes      uint64
	OutboundBytes     uint64
	InboundWrapEpoch  uint64
	OutboundWrapEpoch uint64
}
type meteringConsumerDiskState struct {
	Version           int                       `json:"version"`
	ProducerID        string                    `json:"producer_id"`
	LastApplied       uint64                    `json:"last_applied"`
	ProcessGeneration uint64                    `json:"process_generation"`
	Sources           []persistedMeteringSource `json:"sources"`
	Totals            []persistedMeteringTotal  `json:"totals"`
	Pending           []persistedMeteringTotal  `json:"pending"`
}

type persistedMeteringSource struct {
	Key      meteringSourceKey      `json:"key"`
	Baseline meteringSourceBaseline `json:"baseline"`
}

type persistedMeteringTotal struct {
	Keyspace           string `json:"keyspace"`
	BackendID          string `json:"backend_id"`
	PublicEndpoint     bool   `json:"public_endpoint"`
	ResponseBytes      uint64 `json:"response_bytes"`
	CrossLocationBytes uint64 `json:"cross_location_bytes"`
}

// OpenMeteringConsumer loads or creates the durable Go-side dedup/baseline
// state. Existing corruption is fatal; a fresh state never accepts sequence
// greater than one.
func OpenMeteringConsumer(path string, sink MeteringSink) (*MeteringConsumer, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("metering consumer state path must be absolute")
	}
	if sink != nil {
		durable, ok := sink.(durableMeteringSink)
		if !ok {
			return nil, errors.New("metering consumer requires a durable sink")
		}
		if !durable.Healthy() {
			return nil, errors.New("metering durable sink is not ready")
		}
	}
	consumer := NewMeteringConsumer()
	consumer.statePath = path
	consumer.sink = sink
	if _, err := os.Lstat(path); err == nil {
		if err := consumer.loadState(); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat metering consumer state: %w", err)
	} else if err := consumer.persistLocked(); err != nil {
		return nil, err
	}
	if err := consumer.validateSinkCheckpointLocked(); err != nil {
		return nil, err
	}
	return consumer, nil
}

// ApplyAbsolute validates, deduplicates, derives monotonic deltas, durably
// stages them, and drains them into the Go meter. applied=false with nil error
// means a duplicate that should be re-ACKed. Gaps, producer mismatches, source
// identity mutation, wrap jumps, and persistence failures return an error and
// must not be ACKed.
func (consumer *MeteringConsumer) ApplyAbsolute(batch *controlpb.MeteringBatch) (applied bool, err error) {
	if batch == nil || !validMeteringProducerID(batch.GetProducerId()) {
		return false, errors.New("absolute metering batch requires producer id")
	}
	if len(batch.GetSnapshots()) == 0 {
		return false, errors.New("absolute metering batch requires snapshots")
	}
	if len(batch.GetSnapshots()) > maxAbsoluteMeteringSnapshots {
		return false, errors.New("absolute metering batch exceeds snapshot bound")
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if !consumer.healthy {
		return false, errors.New("metering consumer is unhealthy")
	}
	if err := consumer.validateSinkCheckpointLocked(); err != nil {
		consumer.healthy = false
		return false, err
	}
	if consumer.producerID != "" && consumer.producerID != batch.GetProducerId() {
		return false, errors.New("metering producer mismatch")
	}
	if consumer.producerID == batch.GetProducerId() && batch.GetSequence() <= consumer.lastApplied {
		if batch.GetSequence() == consumer.lastApplied {
			if err := consumer.drainPendingLocked(); err != nil {
				consumer.healthy = false
				return false, err
			}
		}
		return false, nil
	}
	if consumer.lastApplied == math.MaxUint64 || batch.GetSequence() != consumer.lastApplied+1 {
		return false, errors.New("metering sequence gap")
	}
	if consumer.producerID == "" && batch.GetSequence() != 1 {
		return false, errors.New("fresh metering consumer refuses sequence greater than one")
	}
	batchProcessGeneration := batch.GetSnapshots()[0].GetProcessGeneration()
	for _, snapshot := range batch.GetSnapshots()[1:] {
		if snapshot.GetProcessGeneration() != batchProcessGeneration {
			return false, errors.New("metering batch mixes process generations")
		}
	}
	if consumer.processGeneration != 0 && batchProcessGeneration < consumer.processGeneration {
		return false, errors.New("metering process generation regressed")
	}

	stagedSources := cloneMeteringSources(consumer.sources)
	if batchProcessGeneration > consumer.processGeneration {
		// A higher generation proves the prior Rust process is gone. Its last
		// applied absolute baselines are complete as far as that crashed
		// process can report, and must not leak forever as active sources.
		for key := range stagedSources {
			if key.ProcessGeneration < batchProcessGeneration {
				delete(stagedSources, key)
			}
		}
	}
	stagedTotals := cloneMeteringTotals(consumer.totals)
	stagedPending := cloneMeteringTotals(consumer.pending)
	seen := make(map[meteringSourceKey]struct{}, len(batch.GetSnapshots()))
	for _, snapshot := range batch.GetSnapshots() {
		if snapshot.GetConnectionId() == 0 || snapshot.GetProcessGeneration() == 0 ||
			snapshot.GetBackendGeneration() == 0 || snapshot.GetBackendId() == "" ||
			snapshot.GetKeyspace() == "" {
			return false, errors.New("metering snapshot has unknown attribution")
		}
		if len(snapshot.GetBackendId()) > maxMeteringKeyBytes ||
			len(snapshot.GetClusterName()) > maxMeteringKeyBytes ||
			len(snapshot.GetKeyspace()) > maxMeteringKeyBytes {
			return false, errors.New("metering snapshot attribution exceeds key bound")
		}
		sourceKey := meteringSourceKey{
			ConnectionID:      snapshot.GetConnectionId(),
			ProcessGeneration: snapshot.GetProcessGeneration(),
			BackendGeneration: snapshot.GetBackendGeneration(),
		}
		if _, duplicate := seen[sourceKey]; duplicate {
			return false, errors.New("metering batch has duplicate source")
		}
		seen[sourceKey] = struct{}{}
		baseline, exists := stagedSources[sourceKey]
		if exists && (baseline.BackendID != snapshot.GetBackendId() ||
			baseline.ClusterName != snapshot.GetClusterName() ||
			baseline.Keyspace != snapshot.GetKeyspace() || baseline.Local != snapshot.GetLocal() ||
			baseline.PublicEndpoint != snapshot.GetPublicEndpoint()) {
			return false, errors.New("metering source attribution mutated")
		}
		inbound, ok := absoluteCounterDelta(
			baseline.InboundBytes, baseline.InboundWrapEpoch,
			snapshot.GetBackendInboundBytes(), snapshot.GetInboundWrapEpoch(), exists,
		)
		if !ok {
			return false, errors.New("metering inbound counter regressed")
		}
		outbound, ok := absoluteCounterDelta(
			baseline.OutboundBytes, baseline.OutboundWrapEpoch,
			snapshot.GetBackendOutboundBytes(), snapshot.GetOutboundWrapEpoch(), exists,
		)
		if !ok {
			return false, errors.New("metering outbound counter regressed")
		}
		cross := uint64(0)
		if !snapshot.GetLocal() {
			cross = inbound + outbound
			if cross < inbound {
				return false, errors.New("metering cross-location counter overflow")
			}
		}
		key := meteringKey{
			keyspace:       snapshot.GetKeyspace(),
			backendID:      snapshot.GetBackendId(),
			publicEndpoint: snapshot.GetPublicEndpoint(),
		}
		addMeteringTotalsSaturating(stagedTotals, key, inbound, cross)
		if !addMeteringTotals(stagedPending, key, inbound, cross) {
			return false, errors.New("metering aggregate overflow")
		}
		stagedSources[sourceKey] = meteringSourceBaseline{
			BackendID:         snapshot.GetBackendId(),
			ClusterName:       snapshot.GetClusterName(),
			Keyspace:          snapshot.GetKeyspace(),
			Local:             snapshot.GetLocal(),
			PublicEndpoint:    snapshot.GetPublicEndpoint(),
			InboundBytes:      snapshot.GetBackendInboundBytes(),
			OutboundBytes:     snapshot.GetBackendOutboundBytes(),
			InboundWrapEpoch:  snapshot.GetInboundWrapEpoch(),
			OutboundWrapEpoch: snapshot.GetOutboundWrapEpoch(),
		}
		if snapshot.GetFinal() {
			delete(stagedSources, sourceKey)
		}
	}

	consumer.producerID = batch.GetProducerId()
	consumer.lastApplied = batch.GetSequence()
	consumer.processGeneration = batchProcessGeneration
	consumer.sources = stagedSources
	consumer.totals = stagedTotals
	consumer.pending = stagedPending
	if err := consumer.persistLocked(); err != nil {
		consumer.healthy = false
		return false, err
	}
	if err := consumer.drainPendingLocked(); err != nil {
		consumer.healthy = false
		return false, err
	}
	return true, nil
}

func (consumer *MeteringConsumer) drainPendingLocked() error {
	if len(consumer.pending) == 0 {
		return nil
	}
	if sink, ok := consumer.sink.(durableMeteringSink); ok {
		if err := sink.ApplyMeteringBatch(
			consumer.producerID,
			consumer.lastApplied,
			meteringDeltas(consumer.pending),
		); err != nil {
			return fmt.Errorf("persist metering sink batch: %w", err)
		}
		if !sink.Healthy() {
			return errors.New("metering sink is unhealthy")
		}
	} else if consumer.sink != nil {
		for key, value := range consumer.pending {
			if value.responseBytes > math.MaxInt64 || value.crossLocationBytes > math.MaxInt64 {
				return errors.New("metering sink delta exceeds int64")
			}
			consumer.sink.IncTraffic(
				key.keyspace,
				int64(value.responseBytes),
				int64(value.crossLocationBytes),
				key.publicEndpoint,
			)
		}
	}
	consumer.pending = make(map[meteringKey]*meteringTotals)
	if err := consumer.persistLocked(); err != nil {
		return err
	}
	return nil
}

func (consumer *MeteringConsumer) validateSinkCheckpointLocked() error {
	sink, ok := consumer.sink.(durableMeteringSink)
	if !ok {
		return nil
	}
	producer, sequence := sink.MeteringCheckpoint()
	if (producer == "") != (sequence == 0) {
		return errors.New("metering sink checkpoint is inconsistent")
	}
	if consumer.producerID == "" {
		if producer != "" || sequence != 0 {
			return errors.New("metering sink is ahead of fresh consumer state")
		}
		return nil
	}
	if producer != "" && producer != consumer.producerID {
		return errors.New("metering sink producer checkpoint mismatch")
	}
	if len(consumer.pending) == 0 {
		if producer != consumer.producerID || sequence != consumer.lastApplied {
			return errors.New("metering sink checkpoint does not match consumer")
		}
		return nil
	}
	// Pending is durably staged before sink ingestion, so after a crash the
	// sink may be exactly one batch behind, or already at lastApplied if the
	// consumer's pending-clear persist failed. No other skew is reachable.
	previous := consumer.lastApplied - 1
	if sequence != previous && sequence != consumer.lastApplied {
		return errors.New("metering sink checkpoint is outside pending window")
	}
	if sequence > 0 && producer != consumer.producerID {
		return errors.New("metering sink pending producer mismatch")
	}
	return nil
}

func meteringDeltas(input map[meteringKey]*meteringTotals) []MeteringDelta {
	output := make([]MeteringDelta, 0, len(input))
	for key, value := range input {
		output = append(output, MeteringDelta{
			Keyspace:           key.keyspace,
			BackendID:          key.backendID,
			PublicEndpoint:     key.publicEndpoint,
			ResponseBytes:      value.responseBytes,
			CrossLocationBytes: value.crossLocationBytes,
		})
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Keyspace != output[j].Keyspace {
			return output[i].Keyspace < output[j].Keyspace
		}
		if output[i].BackendID != output[j].BackendID {
			return output[i].BackendID < output[j].BackendID
		}
		return !output[i].PublicEndpoint && output[j].PublicEndpoint
	})
	return output
}

// Healthy reports whether every required durable state transition succeeded.
func (consumer *MeteringConsumer) Healthy() bool {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if !consumer.healthy {
		return false
	}
	if sink, ok := consumer.sink.(durableMeteringSink); ok {
		return sink.Healthy()
	}
	return true
}

// ProducerID returns the durable producer qualifier.
func (consumer *MeteringConsumer) ProducerID() string {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.producerID
}

func absoluteCounterDelta(previous, previousEpoch, current, currentEpoch uint64, exists bool) (uint64, bool) {
	if !exists {
		if currentEpoch != 0 {
			return 0, false
		}
		return current, true
	}
	if currentEpoch == previousEpoch {
		if current < previous {
			return 0, false
		}
		return current - previous, true
	}
	if currentEpoch != previousEpoch+1 || previousEpoch == math.MaxUint64 {
		return 0, false
	}
	if previous == 0 {
		return 0, false
	}
	delta := math.MaxUint64 - previous + 1
	if current > math.MaxUint64-delta {
		return 0, false
	}
	return delta + current, true
}

func addMeteringTotals(values map[meteringKey]*meteringTotals, key meteringKey, response, cross uint64) bool {
	current := values[key]
	if current == nil {
		current = &meteringTotals{}
		values[key] = current
	}
	if current.responseBytes > math.MaxUint64-response ||
		current.crossLocationBytes > math.MaxUint64-cross {
		return false
	}
	current.responseBytes += response
	current.crossLocationBytes += cross
	return true
}

func addMeteringTotalsSaturating(
	values map[meteringKey]*meteringTotals,
	key meteringKey,
	response, cross uint64,
) {
	current := values[key]
	if current == nil {
		current = &meteringTotals{}
		values[key] = current
	}
	if current.responseBytes > math.MaxUint64-response {
		current.responseBytes = math.MaxUint64
	} else {
		current.responseBytes += response
	}
	if current.crossLocationBytes > math.MaxUint64-cross {
		current.crossLocationBytes = math.MaxUint64
	} else {
		current.crossLocationBytes += cross
	}
}

func cloneMeteringSources(input map[meteringSourceKey]meteringSourceBaseline) map[meteringSourceKey]meteringSourceBaseline {
	output := make(map[meteringSourceKey]meteringSourceBaseline, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneMeteringTotals(input map[meteringKey]*meteringTotals) map[meteringKey]*meteringTotals {
	output := make(map[meteringKey]*meteringTotals, len(input))
	for key, value := range input {
		copy := *value
		output[key] = &copy
	}
	return output
}

func (consumer *MeteringConsumer) loadState() error {
	info, err := os.Lstat(consumer.statePath)
	if err != nil {
		return fmt.Errorf("stat metering consumer state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("metering consumer state must be a 0600 regular file")
	}
	content, err := os.ReadFile(consumer.statePath)
	if err != nil {
		return fmt.Errorf("read metering consumer state: %w", err)
	}
	var state meteringConsumerDiskState
	if err := json.Unmarshal(content, &state); err != nil || state.Version != meteringConsumerStateVersion {
		return errors.New("metering consumer state is corrupt or unsupported")
	}
	consumer.producerID = state.ProducerID
	consumer.lastApplied = state.LastApplied
	consumer.processGeneration = state.ProcessGeneration
	consumer.sources = make(map[meteringSourceKey]meteringSourceBaseline, len(state.Sources))
	for _, source := range state.Sources {
		if source.Key.ConnectionID == 0 || source.Key.ProcessGeneration == 0 ||
			source.Key.BackendGeneration == 0 || source.Baseline.BackendID == "" ||
			source.Baseline.Keyspace == "" || source.Key.ProcessGeneration > state.ProcessGeneration {
			return errors.New("metering consumer state has invalid source")
		}
		if len(source.Baseline.BackendID) > maxMeteringKeyBytes ||
			len(source.Baseline.ClusterName) > maxMeteringKeyBytes ||
			len(source.Baseline.Keyspace) > maxMeteringKeyBytes {
			return errors.New("metering consumer state source exceeds key bound")
		}
		if _, duplicate := consumer.sources[source.Key]; duplicate {
			return errors.New("metering consumer state has duplicate source")
		}
		consumer.sources[source.Key] = source.Baseline
	}
	if (state.ProducerID == "") != (state.LastApplied == 0) {
		return errors.New("metering consumer state has inconsistent producer sequence")
	}
	if state.ProducerID != "" && !validMeteringProducerID(state.ProducerID) {
		return errors.New("metering consumer state has invalid producer")
	}
	if (state.ProducerID == "") != (state.ProcessGeneration == 0) {
		return errors.New("metering consumer state has inconsistent process generation")
	}
	if state.ProducerID == "" &&
		(len(state.Sources) != 0 || len(state.Totals) != 0 || len(state.Pending) != 0) {
		return errors.New("metering consumer state has data without a producer")
	}
	consumer.totals, err = totalsFromDisk(state.Totals)
	if err != nil {
		return err
	}
	consumer.pending, err = totalsFromDisk(state.Pending)
	if err != nil {
		return err
	}
	consumer.healthy = true
	return nil
}

func validMeteringProducerID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range []byte(value) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func totalsFromDisk(input []persistedMeteringTotal) (map[meteringKey]*meteringTotals, error) {
	output := make(map[meteringKey]*meteringTotals, len(input))
	for _, item := range input {
		if item.Keyspace == "" || item.BackendID == "" {
			return nil, errors.New("metering consumer state has unknown total attribution")
		}
		if len(item.Keyspace) > maxMeteringKeyBytes || len(item.BackendID) > maxMeteringKeyBytes {
			return nil, errors.New("metering consumer state total exceeds key bound")
		}
		key := meteringKey{
			keyspace:       item.Keyspace,
			backendID:      item.BackendID,
			publicEndpoint: item.PublicEndpoint,
		}
		if _, duplicate := output[key]; duplicate {
			return nil, errors.New("metering consumer state has duplicate total")
		}
		output[key] = &meteringTotals{
			responseBytes:      item.ResponseBytes,
			crossLocationBytes: item.CrossLocationBytes,
		}
	}
	return output, nil
}

func (consumer *MeteringConsumer) persistLocked() error {
	state := meteringConsumerDiskState{
		Version:           meteringConsumerStateVersion,
		ProducerID:        consumer.producerID,
		LastApplied:       consumer.lastApplied,
		ProcessGeneration: consumer.processGeneration,
		Sources:           sourcesToDisk(consumer.sources),
		Totals:            totalsToDisk(consumer.totals),
		Pending:           totalsToDisk(consumer.pending),
	}
	content, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode metering consumer state: %w", err)
	}
	directory := filepath.Dir(consumer.statePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create metering consumer directory: %w", err)
	}
	temporary := fmt.Sprintf("%s.tmp-%d", consumer.statePath, os.Getpid())
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("open metering consumer temporary state: %w", err)
	}
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("secure metering consumer temporary state: %w", err)
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(content); err != nil {
		return fmt.Errorf("write metering consumer state: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync metering consumer state: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close metering consumer state: %w", err)
	}
	if err = os.Rename(temporary, consumer.statePath); err != nil {
		return fmt.Errorf("replace metering consumer state: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open metering consumer directory: %w", err)
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("sync metering consumer directory: %w", err)
	}
	failed = false
	return nil
}

func sourcesToDisk(input map[meteringSourceKey]meteringSourceBaseline) []persistedMeteringSource {
	output := make([]persistedMeteringSource, 0, len(input))
	for key, value := range input {
		output = append(output, persistedMeteringSource{Key: key, Baseline: value})
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Key.ConnectionID != output[j].Key.ConnectionID {
			return output[i].Key.ConnectionID < output[j].Key.ConnectionID
		}
		if output[i].Key.ProcessGeneration != output[j].Key.ProcessGeneration {
			return output[i].Key.ProcessGeneration < output[j].Key.ProcessGeneration
		}
		return output[i].Key.BackendGeneration < output[j].Key.BackendGeneration
	})
	return output
}

func totalsToDisk(input map[meteringKey]*meteringTotals) []persistedMeteringTotal {
	output := make([]persistedMeteringTotal, 0, len(input))
	for key, value := range input {
		output = append(output, persistedMeteringTotal{
			Keyspace:           key.keyspace,
			BackendID:          key.backendID,
			PublicEndpoint:     key.publicEndpoint,
			ResponseBytes:      value.responseBytes,
			CrossLocationBytes: value.crossLocationBytes,
		})
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Keyspace != output[j].Keyspace {
			return output[i].Keyspace < output[j].Keyspace
		}
		if output[i].BackendID != output[j].BackendID {
			return output[i].BackendID < output[j].BackendID
		}
		return !output[i].PublicEndpoint && output[j].PublicEndpoint
	})
	return output
}
