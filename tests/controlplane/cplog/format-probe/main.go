// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command format-probe records how the production Go logger builder treats
// `log.level`, `log.encoder` and `log.simple`: which level spellings
// `BuildLogger` accepts, which of debug/info/warn/error lines each accepted
// level lets through, and the line header each encoder writes. The output is
// the fixture `rust/crates/control-plane/testdata/log-format-go.json` that the
// Rust logger's tests compare against (CP-ADMIN slice 4a).
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/pingcap/tiproxy/lib/config"
	lg "github.com/pingcap/tiproxy/lib/util/logger"
)

type levelCase struct {
	Text     string          `json:"text"`
	Accepted bool            `json:"accepted"`
	Emitted  map[string]bool `json:"emitted"`
}

type encoderCase struct {
	Text      string `json:"text"`
	Simple    bool   `json:"simple"`
	FirstLine string `json:"first_line"`
}

type fixture struct {
	Levels   []levelCase   `json:"levels"`
	Encoders []encoderCase `json:"encoders"`
}

var (
	timestamp = regexp.MustCompile(`[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3} [+-][0-9]{2}:[0-9]{2}`)
	caller    = regexp.MustCompile(`main\.go:[0-9]+`)
)

var markers = []string{"debug", "info", "warn", "error"}

// build runs the production builder against a fresh temporary file, emits one
// line per marker level and returns whether the builder accepted the
// configuration and the normalized file lines.
func build(level, encoder string, simple bool) (bool, []string) {
	dir, err := os.MkdirTemp("", "log-format-probe-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	cfg := &config.Log{
		Encoder: encoder,
		Simple:  simple,
		LogOnline: config.LogOnline{
			Level:   level,
			LogFile: config.LogFile{Filename: filepath.Join(dir, "probe.log")},
		},
	}
	logger, syncer, _, err := lg.BuildLogger(cfg)
	if err != nil {
		return false, nil
	}
	logger.Debug("m", zap.String("marker", "marker-debug"))
	logger.Info("m", zap.String("marker", "marker-info"))
	logger.Warn("m", zap.String("marker", "marker-warn"))
	logger.Error("m", zap.String("marker", "marker-error"))
	if err := syncer.Close(); err != nil {
		panic(err)
	}
	raw, err := os.ReadFile(cfg.LogFile.Filename)
	if os.IsNotExist(err) {
		// lumberjack creates the file on the first write: a threshold above
		// every emitted line leaves no file at all.
		return true, nil
	}
	if err != nil {
		panic(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		line = timestamp.ReplaceAllString(line, "<TS>")
		line = caller.ReplaceAllString(line, "main.go:N")
		lines = append(lines, line)
	}
	return true, lines
}

func main() {
	var out fixture
	for _, level := range []string{
		"debug", "info", "", "warn", "warning", "error", "dpanic", "panic", "fatal",
		"INFO", "Warn", "ERROR", " info ", "info\n", "bogus", "information", "trace", "critical",
	} {
		accepted, lines := build(level, "tidb", false)
		emitted := map[string]bool{}
		for _, marker := range markers {
			emitted[marker] = false
			for _, line := range lines {
				if strings.Contains(line, "marker-"+marker) {
					emitted[marker] = true
				}
			}
		}
		if !accepted {
			emitted = nil
		}
		out.Levels = append(out.Levels, levelCase{Text: level, Accepted: accepted, Emitted: emitted})
	}
	for _, encoder := range []string{"tidb", "json", "console", "JSON", "Console", " json", "text", ""} {
		for _, simple := range []bool{false, true} {
			accepted, lines := build("info", encoder, simple)
			first := ""
			if accepted && len(lines) > 0 {
				first = lines[0]
			}
			out.Encoders = append(out.Encoders, encoderCase{Text: encoder, Simple: simple, FirstLine: first})
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
