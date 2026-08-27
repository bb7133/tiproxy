// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
	controlpb "github.com/pingcap/tiproxy/pkg/controlbridge/pb"
	"github.com/stretchr/testify/require"
)

type staticDataplaneStatus struct {
	status controlbridge.SnapshotStatus
}

func (reader staticDataplaneStatus) Status() controlbridge.SnapshotStatus {
	return reader.status
}

func TestDataplaneStatusAPI(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	handler := &Server{mgr: Managers{DataplaneStatus: staticDataplaneStatus{status: controlbridge.SnapshotStatus{
		DesiredGeneration:  5,
		SentGeneration:     5,
		AppliedGeneration:  4,
		RejectedGeneration: 5,
		LastResultCode:     controlpb.ErrorCode_ERROR_CODE_INVALID_SNAPSHOT,
		Detail:             "invalid candidate",
		LastGoodAge:        1500 * time.Millisecond,
	}}}}
	handler.registerDataplane(engine.Group("/api/dataplane"))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/dataplane/status", nil)
	engine.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Equal(t, true, response["enabled"])
	require.Equal(t, float64(4), response["applied_generation"])
	require.Equal(t, float64(5), response["rejected_generation"])
	require.Equal(t, "ERROR_CODE_INVALID_SNAPSHOT", response["last_result_code"])
	require.Equal(t, float64(1500), response["last_good_age_ms"])
}

func TestDataplaneStatusAPIDisabled(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	handler := &Server{}
	handler.registerDataplane(engine.Group("/api/dataplane"))
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/dataplane/status", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.JSONEq(t, `{"enabled":false}`, recorder.Body.String())
}

type recordingDrainer struct {
	calls int
}

func (drainer *recordingDrainer) StartDrain(context.Context, controlbridge.DrainRequest) error {
	drainer.calls++
	return nil
}

func (drainer *recordingDrainer) DrainStatus(string) (*controlpb.DrainResult, bool) {
	return nil, false
}

func TestDataplaneDrainAPIRejectsInvalidBudgetsBeforeConversion(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	drainer := &recordingDrainer{}
	handler := &Server{mgr: Managers{DataplaneDrainer: drainer}}
	handler.registerDataplane(engine.Group("/api/dataplane"))

	// int64-max milliseconds would overflow the duration conversion
	// into a small "valid" budget; a negative value must be a client
	// error, never a silent clamp to zero.
	for name, body := range map[string]string{
		"negative graceful": `{"drain_id":"d","graceful_wait_ms":-1}`,
		"negative force":    `{"drain_id":"d","force_timeout_ms":-1}`,
		"overflow graceful": `{"drain_id":"d","graceful_wait_ms":9223372036854775807}`,
		"overflow force":    `{"drain_id":"d","force_timeout_ms":9223372036854775807}`,
		"over 30-day cap":   `{"drain_id":"d","graceful_wait_ms":2592000001}`,
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(
			http.MethodPost, "/api/dataplane/drain", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		engine.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusBadRequest, recorder.Code, name)
		require.Zero(t, drainer.calls, "invalid budgets never reach the bridge: %s", name)
	}

	// A boundary-valid budget passes through unclamped.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/dataplane/drain",
		strings.NewReader(`{"drain_id":"d","graceful_wait_ms":2592000000}`))
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Equal(t, 1, drainer.calls)
}
