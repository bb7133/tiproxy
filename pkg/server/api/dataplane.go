// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Server) registerDataplane(group *gin.RouterGroup) {
	group.GET("/status", h.DataplaneStatus)
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
