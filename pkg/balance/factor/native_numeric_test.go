// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

import (
	"encoding/json"
	"math"
	"os"
	"runtime"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// The raw conversion inputs include unreachable-after-clamping CPU values so
// the oracle pins the compiler operation independently of score saturation.
// Health is upstream producer arithmetic; its resulting float is captured once.
func TestNativeNumericConversions(t *testing.T) {
	upper := math.Ldexp(1, 63)
	values := []float64{math.NaN(), math.Inf(1), math.Inf(-1), upper, -upper,
		math.Nextafter(upper, 0), math.Nextafter(upper, math.Inf(1)),
		math.Nextafter(-upper, 0), math.Nextafter(-upper, math.Inf(-1)),
		-2, -1, 0, 1, 2, -1.999, 1.999, math.MaxFloat64, -math.MaxFloat64}
	type row struct {
		Site       string  `json:"site"`
		Bits       uint64  `json:"bits"`
		Integer    int64   `json:"integer"`
		HealthBits *uint64 `json:"health_bits,omitempty"`
	}
	rows := make([]row, 0, len(values)*4)
	for _, value := range values {
		// Variables ensure these are runtime compiler conversions.
		rows = append(rows, row{Site: "cpu-int", Bits: math.Float64bits(value), Integer: int64(int(value))},
			row{Site: "memory-horizon-first", Bits: math.Float64bits(value), Integer: int64(time.Duration(value))},
			row{Site: "memory-horizon-second", Bits: math.Float64bits(value), Integer: int64(time.Duration(value))})
		name, kind := "type", "read"
		metric := &dto.Metric{Label: []*dto.LabelPair{{Name: &name, Value: &kind}}, Untyped: &dto.Untyped{Value: &value}}
		health := generalMetric2Value(map[string]*dto.MetricFamily{"total": {Metric: []*dto.Metric{metric}}}, "total", "")
		bits := math.Float64bits(float64(health))
		rows = append(rows, row{Site: "health-producer", Bits: math.Float64bits(value), Integer: int64(int(value)), HealthBits: &bits})
	}
	if path := os.Getenv("CP_ROUTE_NATIVE_NUMERIC"); path != "" {
		data, err := json.Marshal(struct {
			Arch string `json:"arch"`
			Rows []row  `json:"rows"`
		}{runtime.GOARCH, rows})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0600))
	}
	require.Len(t, rows, 72)
}
