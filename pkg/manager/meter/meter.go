// Copyright 2025 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package meter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pingcap/metering_sdk/common"
	mconfig "github.com/pingcap/metering_sdk/config"
	"github.com/pingcap/metering_sdk/storage"
	sdkwriter "github.com/pingcap/metering_sdk/writer"
	meteringwriter "github.com/pingcap/metering_sdk/writer/metering"
	"github.com/pingcap/tiproxy/lib/config"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
	"github.com/pingcap/tiproxy/pkg/metrics"
	"github.com/pingcap/tiproxy/pkg/util/waitgroup"
	"go.uber.org/zap"
)

const (
	writeInterval = 60
	// The timeout can not be too long because the pod grace termination period is fixed.
	writeTimeout = 10 * time.Second
	category     = "proxy"

	crossAZKey         = "crossZone_bytes"
	publicEndpointKey  = "public_outBound_bytes"
	privateEndpointKey = "private_outBound_bytes"

	meterStateVersion = 1
	meterStateFile    = "metering-outbox.json"
)

type MeterData struct {
	publicRespBytes  uint64
	privateRespBytes uint64
	crossAZBytes     uint64
}

type meterWindow struct {
	timestamp int64
	data      map[string]MeterData
}

type meterDiskState struct {
	Version           int               `json:"version"`
	SelfID            string            `json:"self_id"`
	ProducerID        string            `json:"producer_id"`
	LastBatchSequence uint64            `json:"last_batch_sequence"`
	Data              []meterDiskRecord `json:"data"`
	Pending           *meterDiskWindow  `json:"pending,omitempty"`
}

type meterDiskWindow struct {
	Timestamp int64             `json:"timestamp"`
	Data      []meterDiskRecord `json:"data"`
}

type meterDiskRecord struct {
	ClusterID        string `json:"cluster_id"`
	PublicRespBytes  uint64 `json:"public_response_bytes"`
	PrivateRespBytes uint64 `json:"private_response_bytes"`
	CrossAZBytes     uint64 `json:"cross_az_bytes"`
}

type Meter struct {
	sync.Mutex
	data              map[string]MeterData
	pending           *meterWindow
	uuid              string
	producerID        string
	lastBatchSequence uint64
	statePath         string
	persistenceFailed bool
	writerHealthy     bool
	writer            sdkwriter.MeteringWriter
	lg                *zap.Logger
	wg                waitgroup.WaitGroup
	cancel            context.CancelFunc
}

func NewMeter(cfg *config.Config, lg *zap.Logger) (*Meter, error) {
	if len(cfg.Metering.Type) == 0 || len(cfg.Metering.Bucket) == 0 {
		return nil, nil
	}
	providerConfig := cfg.Metering.ToProviderConfig()
	provider, err := storage.NewObjectStorageProvider(providerConfig)
	if err != nil {
		lg.Error("Failed to create storage provider", zap.Error(err))
		return nil, err
	}
	meteringConfig := mconfig.DefaultConfig().WithLogger(lg.Named("metering_sdk"))
	writer := meteringwriter.NewMeteringWriterFromConfig(provider, meteringConfig, &cfg.Metering)
	meter := &Meter{
		lg:            lg,
		data:          make(map[string]MeterData),
		writer:        writer,
		uuid:          strings.ReplaceAll(uuid.New().String(), "-", "_"),
		writerHealthy: true,
	}
	if cfg.Workdir != "" {
		statePath, err := filepath.Abs(filepath.Join(cfg.Workdir, "run", meterStateFile))
		if err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("resolve metering outbox path: %w", err)
		}
		meter.statePath = statePath
		if err := meter.openStateLocked(); err != nil {
			_ = writer.Close()
			return nil, err
		}
	}
	return meter, nil
}

func (m *Meter) IncTraffic(clusterID string, respBytes, crossAZBytes int64, fromPublicEndpoint bool) {
	m.Lock()
	defer m.Unlock()
	if err := addTraffic(m.data, clusterID, respBytes, crossAZBytes, fromPublicEndpoint); err != nil {
		m.persistenceFailed = true
		m.lg.Error("Rejected invalid metering delta", zap.Error(err))
	}
}

// ApplyMeteringBatch durably and idempotently accepts one absolute-snapshot
// consumer batch. The producer/sequence checkpoint lives in the same atomic
// state file as the aggregate, closing the crash window between dedup and
// outbox ingestion.
func (m *Meter) ApplyMeteringBatch(
	producerID string,
	sequence uint64,
	deltas []controlbridge.MeteringDelta,
) error {
	m.Lock()
	defer m.Unlock()
	if m.persistenceFailed {
		return errors.New("metering outbox persistence is unhealthy")
	}
	if !validProducerID(producerID) || sequence == 0 {
		return errors.New("metering batch requires producer and sequence")
	}
	if m.producerID != "" && m.producerID != producerID {
		return errors.New("metering outbox producer mismatch")
	}
	if m.producerID == producerID && sequence <= m.lastBatchSequence {
		return nil
	}
	if m.lastBatchSequence == math.MaxUint64 || sequence != m.lastBatchSequence+1 {
		return errors.New("metering outbox sequence gap")
	}
	if m.producerID == "" && sequence != 1 {
		return errors.New("fresh metering outbox refuses sequence greater than one")
	}
	staged := cloneMeterData(m.data)
	for _, delta := range deltas {
		if delta.Keyspace == "" || delta.BackendID == "" {
			return errors.New("metering delta has unknown attribution")
		}
		if err := addTrafficUnsigned(
			staged,
			delta.Keyspace,
			delta.ResponseBytes,
			delta.CrossLocationBytes,
			delta.PublicEndpoint,
		); err != nil {
			return err
		}
	}
	m.data = staged
	m.producerID = producerID
	m.lastBatchSequence = sequence
	if err := m.persistLocked(); err != nil {
		m.persistenceFailed = true
		return err
	}
	return nil
}

// Healthy is the readiness gate for durable ingestion and export.
func (m *Meter) Healthy() bool {
	m.Lock()
	defer m.Unlock()
	return m.statePath != "" && !m.persistenceFailed && m.writerHealthy
}

// MeteringCheckpoint exposes the durable producer/sequence owned by this
// outbox. The consumer uses it at startup and before every ACK to detect loss
// or skew between its baseline file and the sink file.
func (m *Meter) MeteringCheckpoint() (string, uint64) {
	m.Lock()
	defer m.Unlock()
	return m.producerID, m.lastBatchSequence
}

func (m *Meter) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.RunWithRecover(func() {
		// A crash may leave a sealed window waiting for an idempotent retry.
		m.flush(time.Now().Unix()/writeInterval*writeInterval, writeTimeout)
		m.flushLoop(ctx)
	}, nil, m.lg)
}

func (m *Meter) flushLoop(ctx context.Context) {
	m.lg.Info("metering is started")
	// Control the writing timestamp accurately enough so that the previous round won't be overwritten by the next round.
	curTime := time.Now().Unix()
	nextTime := curTime/writeInterval*writeInterval + writeInterval
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(nextTime-curTime) * time.Second):
			m.flush(nextTime, writeTimeout)
			nextTime += writeInterval
			curTime = time.Now().Unix()
		}
	}
	// Try our best to flush the final data even after closing.
	m.flush(nextTime, writeTimeout)
}

func (m *Meter) flush(ts int64, timeout time.Duration) {
	m.Lock()
	if m.persistenceFailed {
		m.Unlock()
		return
	}
	if m.pending == nil {
		if len(m.data) == 0 {
			m.Unlock()
			return
		}
		m.pending = &meterWindow{timestamp: ts, data: m.data}
		m.data = make(map[string]MeterData, len(m.pending.data))
		if err := m.persistLocked(); err != nil {
			m.persistenceFailed = true
			m.lg.Error("Failed to seal metering outbox window", zap.Error(err))
			m.Unlock()
			return
		}
	}
	pending := cloneWindow(m.pending)
	m.Unlock()

	array := make([]map[string]any, 0, len(pending.data))
	for clusterID, d := range pending.data {
		array = append(array, map[string]any{
			"version":          "1",
			"cluster_id":       clusterID,
			"source_name":      category,
			crossAZKey:         &common.MeteringValue{Value: uint64(d.crossAZBytes), Unit: "bytes"},
			privateEndpointKey: &common.MeteringValue{Value: uint64(d.privateRespBytes), Unit: "bytes"},
			publicEndpointKey:  &common.MeteringValue{Value: uint64(d.publicRespBytes), Unit: "bytes"},
		})
	}

	meteringData := &common.MeteringData{
		SelfID:    m.uuid,
		Timestamp: pending.timestamp,
		Category:  category,
		Data:      array,
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := m.writer.Write(flushCtx, meteringData); err != nil {
		m.Lock()
		m.writerHealthy = false
		m.Unlock()
		metrics.ServerErrCounter.WithLabelValues("metering").Inc()
		m.lg.Error("Failed to write metering data", zap.Error(err))
		return
	}
	m.Lock()
	original := m.pending
	m.pending = nil
	if err := m.persistLocked(); err != nil {
		m.pending = original
		m.persistenceFailed = true
		m.lg.Error("Failed to commit metering outbox window", zap.Error(err))
		m.Unlock()
		return
	}
	m.writerHealthy = true
	m.Unlock()
	m.lg.Debug("flushed metering data", zap.Int("clusters", len(pending.data)))
}

func (m *Meter) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	var err error
	if m.writer != nil {
		err = m.writer.Close()
	}
	m.lg.Debug("meter closed")
	return err
}

func addTraffic(
	data map[string]MeterData,
	clusterID string,
	respBytes, crossAZBytes int64,
	fromPublicEndpoint bool,
) error {
	if respBytes < 0 || crossAZBytes < 0 {
		return errors.New("metering delta cannot be negative")
	}
	return addTrafficUnsigned(
		data,
		clusterID,
		uint64(respBytes),
		uint64(crossAZBytes),
		fromPublicEndpoint,
	)
}

func addTrafficUnsigned(
	data map[string]MeterData,
	clusterID string,
	response, cross uint64,
	fromPublicEndpoint bool,
) error {
	if clusterID == "" {
		return errors.New("metering cluster id cannot be empty")
	}
	original := data[clusterID]
	if original.crossAZBytes > math.MaxUint64-cross {
		return errors.New("metering cross-AZ aggregate overflow")
	}
	if fromPublicEndpoint {
		if original.publicRespBytes > math.MaxUint64-response {
			return errors.New("metering public aggregate overflow")
		}
		original.publicRespBytes += response
	} else {
		if original.privateRespBytes > math.MaxUint64-response {
			return errors.New("metering private aggregate overflow")
		}
		original.privateRespBytes += response
	}
	original.crossAZBytes += cross
	data[clusterID] = original
	return nil
}

func cloneWindow(input *meterWindow) *meterWindow {
	if input == nil {
		return nil
	}
	output := &meterWindow{timestamp: input.timestamp, data: make(map[string]MeterData, len(input.data))}
	for key, value := range input.data {
		output.data[key] = value
	}
	return output
}

func cloneMeterData(input map[string]MeterData) map[string]MeterData {
	output := make(map[string]MeterData, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func (m *Meter) openStateLocked() error {
	if _, err := os.Lstat(m.statePath); err == nil {
		return m.loadStateLocked()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat metering outbox: %w", err)
	}
	return m.persistLocked()
}

func (m *Meter) loadStateLocked() error {
	info, err := os.Lstat(m.statePath)
	if err != nil {
		return fmt.Errorf("stat metering outbox: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("metering outbox must be a 0600 regular file")
	}
	content, err := os.ReadFile(m.statePath)
	if err != nil {
		return fmt.Errorf("read metering outbox: %w", err)
	}
	var state meterDiskState
	if err := json.Unmarshal(content, &state); err != nil ||
		state.Version != meterStateVersion || state.SelfID == "" {
		return errors.New("metering outbox is corrupt or unsupported")
	}
	if (state.ProducerID == "") != (state.LastBatchSequence == 0) {
		return errors.New("metering outbox has inconsistent producer sequence")
	}
	if state.ProducerID != "" && !validProducerID(state.ProducerID) {
		return errors.New("metering outbox has invalid producer")
	}
	data, err := meterRecordsFromDisk(state.Data)
	if err != nil {
		return err
	}
	var pending *meterWindow
	if state.Pending != nil {
		pendingData, err := meterRecordsFromDisk(state.Pending.Data)
		if err != nil {
			return err
		}
		if state.Pending.Timestamp <= 0 || len(pendingData) == 0 {
			return errors.New("metering outbox has invalid pending window")
		}
		pending = &meterWindow{timestamp: state.Pending.Timestamp, data: pendingData}
	}
	m.uuid = state.SelfID
	m.producerID = state.ProducerID
	m.lastBatchSequence = state.LastBatchSequence
	m.data = data
	m.pending = pending
	return nil
}

func validProducerID(value string) bool {
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

func (m *Meter) persistLocked() error {
	if m.statePath == "" {
		return nil
	}
	state := meterDiskState{
		Version:           meterStateVersion,
		SelfID:            m.uuid,
		ProducerID:        m.producerID,
		LastBatchSequence: m.lastBatchSequence,
		Data:              meterRecordsToDisk(m.data),
	}
	if m.pending != nil {
		state.Pending = &meterDiskWindow{
			Timestamp: m.pending.timestamp,
			Data:      meterRecordsToDisk(m.pending.data),
		}
	}
	content, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode metering outbox: %w", err)
	}
	directory := filepath.Dir(m.statePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create metering outbox directory: %w", err)
	}
	temporary := fmt.Sprintf("%s.tmp-%d", m.statePath, os.Getpid())
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("open metering outbox temporary file: %w", err)
	}
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("secure metering outbox temporary file: %w", err)
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(content); err != nil {
		return fmt.Errorf("write metering outbox: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync metering outbox: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close metering outbox: %w", err)
	}
	if err = os.Rename(temporary, m.statePath); err != nil {
		return fmt.Errorf("replace metering outbox: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open metering outbox directory: %w", err)
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("sync metering outbox directory: %w", err)
	}
	failed = false
	return nil
}

func meterRecordsToDisk(data map[string]MeterData) []meterDiskRecord {
	records := make([]meterDiskRecord, 0, len(data))
	for clusterID, value := range data {
		records = append(records, meterDiskRecord{
			ClusterID:        clusterID,
			PublicRespBytes:  value.publicRespBytes,
			PrivateRespBytes: value.privateRespBytes,
			CrossAZBytes:     value.crossAZBytes,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ClusterID < records[j].ClusterID })
	return records
}

func meterRecordsFromDisk(records []meterDiskRecord) (map[string]MeterData, error) {
	data := make(map[string]MeterData, len(records))
	for _, record := range records {
		if record.ClusterID == "" {
			return nil, errors.New("metering outbox has empty cluster")
		}
		if _, duplicate := data[record.ClusterID]; duplicate {
			return nil, errors.New("metering outbox has duplicate cluster")
		}
		data[record.ClusterID] = MeterData{
			publicRespBytes:  record.PublicRespBytes,
			privateRespBytes: record.PrivateRespBytes,
			crossAZBytes:     record.CrossAZBytes,
		}
	}
	return data, nil
}
