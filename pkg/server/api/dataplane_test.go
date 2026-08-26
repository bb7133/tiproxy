// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
