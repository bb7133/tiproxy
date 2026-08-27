// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pingcap/tiproxy/pkg/controlbridge"
)

func (h *Server) registerDataplane(group *gin.RouterGroup) {
	group.GET("/status", h.DataplaneStatus)
	group.POST("/drain", h.DataplaneDrain)
	group.GET("/drain/:id", h.DataplaneDrainStatus)
}

type drainRequestBody struct {
	DrainID        string   `json:"drain_id" binding:"required"`
	ListenerNames  []string `json:"listener_names"`
	BackendIDs     []string `json:"backend_ids"`
	GracefulWaitMS int64    `json:"graceful_wait_ms"`
	ForceTimeoutMS int64    `json:"force_timeout_ms"`
}

// DataplaneDrain starts (or idempotently re-issues) one operator
// drain against the Rust dataplane. 202 on issuance; 409 when a
// different drain (or a previous incarnation's) is active; 503 when
// no control session exists.
func (h *Server) DataplaneDrain(c *gin.Context) {
	if h.mgr.DataplaneDrainer == nil {
		c.JSON(http.StatusNotFound, gin.H{"enabled": false})
		return
	}
	var body drainRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Validate the raw millisecond inputs BEFORE any conversion: a
	// negative budget is a client error (never silently clamped), and
	// bounding each value by the shared 30-day cap first means the
	// duration multiplication below can never overflow int64.
	const maxDrainBudgetMS = int64(controlbridge.MaxDrainDeadlineAhead / time.Millisecond)
	if body.GracefulWaitMS < 0 || body.ForceTimeoutMS < 0 ||
		body.GracefulWaitMS > maxDrainBudgetMS || body.ForceTimeoutMS > maxDrainBudgetMS {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"graceful_wait_ms and force_timeout_ms must be within [0, %d] (30 days)",
				maxDrainBudgetMS),
		})
		return
	}
	request := controlbridge.DrainRequest{
		DrainID: body.DrainID,
		Scope: controlbridge.DrainScope{
			ListenerNames: body.ListenerNames,
			BackendIDs:    body.BackendIDs,
		},
		GracefulWait: time.Duration(body.GracefulWaitMS) * time.Millisecond,
		ForceTimeout: time.Duration(body.ForceTimeoutMS) * time.Millisecond,
	}
	switch err := h.mgr.DataplaneDrainer.StartDrain(c.Request.Context(), request); {
	case err == nil:
		c.JSON(http.StatusAccepted, gin.H{"drain_id": body.DrainID})
	case errors.Is(err, controlbridge.ErrInvalidDrainBudget):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, controlbridge.ErrNoDataplaneSession),
		errors.Is(err, controlbridge.ErrSnapshotNotReady):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
	case errors.Is(err, controlbridge.ErrDrainInProgress),
		errors.Is(err, controlbridge.ErrForeignDrainActive):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

// DataplaneDrainStatus reports the latest observed progress/terminal
// for one drain id.
func (h *Server) DataplaneDrainStatus(c *gin.Context) {
	if h.mgr.DataplaneDrainer == nil {
		c.JSON(http.StatusNotFound, gin.H{"enabled": false})
		return
	}
	result, completed := h.mgr.DataplaneDrainer.DrainStatus(c.Param("id"))
	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{"known": false})
		return
	}
	_ = completed
	c.JSON(http.StatusOK, gin.H{
		"drain_id":           c.Param("id"),
		"active_connections": result.GetActiveConnections(),
		"gracefully_closed":  result.GetGracefullyClosed(),
		"force_closed":       result.GetForceClosed(),
		"complete":           result.GetComplete(),
		"code":               result.GetCode().String(),
		"detail":             result.GetDetail(),
	})
}

// DataplaneStatus returns the latest coherent Go-side snapshot generation
// status. The route remains stable while the feature is disabled so operators
// can distinguish "disabled" from an unavailable API server.
func (h *Server) DataplaneStatus(c *gin.Context) {
	if h.mgr.DataplaneStatus == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	status := h.mgr.DataplaneStatus.Status()
	c.JSON(http.StatusOK, gin.H{
		"enabled":             true,
		"desired_generation":  status.DesiredGeneration,
		"sent_generation":     status.SentGeneration,
		"applied_generation":  status.AppliedGeneration,
		"rejected_generation": status.RejectedGeneration,
		"last_result_code":    status.LastResultCode.String(),
		"detail":              status.Detail,
		"last_good_age_ms":    status.LastGoodAge.Milliseconds(),
	})
}
