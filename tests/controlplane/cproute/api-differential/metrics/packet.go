// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package metrics decodes whole external query inputs for test-only API replay.
package metrics

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/pingcap/tiproxy/pkg/balance/metricsreader"
	"github.com/prometheus/common/model"
)

// Keys names the fixed public routing query catalog.
var Keys = [...]string{"cpu", "memory", "failure_pd", "total_pd", "failure_tikv", "total_tikv"}

// Sample retains the original millisecond timestamp and IEEE value.
// Values use decimal strings so NaN, infinities and negative zero survive JSON.
type Sample struct {
	TimestampMillis int64  `json:"timestamp_ms"`
	Value           string `json:"value"`
}

// Series preserves first-match series ordering and every original label.
type Series struct {
	Labels  map[string]string `json:"labels"`
	Samples []Sample          `json:"samples"`
}

// Result contains only external values, never reader/factor provenance.
// A null update time means Go's zero time; Unix epoch zero remains distinct.
type Result struct {
	Kind         string   `json:"kind"`
	UpdatedNanos *int64   `json:"updated_nanos"`
	Series       []Series `json:"series"`
}

var number = regexp.MustCompile(`^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// Decode copies one complete packet. Failure cannot expose a partial replacement.
func Decode(packet map[string]*Result) (map[string]metricsreader.QueryResult, error) {
	if len(packet) != len(Keys) {
		return nil, fmt.Errorf("whole metrics query set required")
	}
	results := make(map[string]metricsreader.QueryResult, len(Keys))
	for _, key := range Keys {
		result, ok := packet[key]
		if !ok {
			return nil, fmt.Errorf("missing query %s", key)
		}
		decoded, err := decode(result)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", key, err)
		}
		results[key] = decoded
	}
	return results, nil
}

func decode(result *Result) (metricsreader.QueryResult, error) {
	var output metricsreader.QueryResult
	if result == nil {
		return output, nil
	}
	if result.Kind != "matrix" && result.Kind != "vector" {
		return output, fmt.Errorf("unsupported metric shape")
	}
	if result.UpdatedNanos != nil {
		output.UpdateTime = time.Unix(0, *result.UpdatedNanos)
	}
	vector, matrix := make(model.Vector, 0, len(result.Series)), make(model.Matrix, 0, len(result.Series))
	for _, series := range result.Series {
		labels := make(model.Metric, len(series.Labels))
		for key, value := range series.Labels {
			labels[model.LabelName(key)] = model.LabelValue(value)
		}
		samples := make([]model.SamplePair, 0, len(series.Samples))
		for _, sample := range series.Samples {
			value, err := strconv.ParseFloat(sample.Value, 64)
			special := sample.Value == "NaN" || sample.Value == "+Inf" || sample.Value == "-Inf"
			if err != nil || len(sample.Value) > 32 || (!special && (!number.MatchString(sample.Value) || math.IsInf(value, 0))) {
				return output, fmt.Errorf("invalid metric sample value")
			}
			samples = append(samples, model.SamplePair{Timestamp: model.Time(sample.TimestampMillis), Value: model.SampleValue(value)})
		}
		if result.Kind == "vector" {
			if len(samples) != 1 {
				return output, fmt.Errorf("vector series requires one sample")
			}
			vector = append(vector, &model.Sample{Metric: labels, Timestamp: samples[0].Timestamp, Value: samples[0].Value})
		} else {
			matrix = append(matrix, &model.SampleStream{Metric: labels, Values: samples})
		}
	}
	if result.Kind == "vector" {
		output.Value = vector
	} else {
		output.Value = matrix
	}
	return output, nil
}
