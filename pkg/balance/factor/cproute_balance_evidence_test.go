// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package factor

func cpBalanceCases() []cpFactorCase {
	var cases []cpFactorCase
	add := func(name string, s cpFactorStep) {
		cases = append(cases, cpFactorCase{Name: name, Steps: []cpFactorStep{s}})
	}
	for _, mode := range []string{"no-physical", "zero-score", "incoming-only", "next-worst", "negative-equal", "inverted", "cutoff-equal", "cutoff-above", "equal-clamped"} {
		s := cpFactorBase()
		s.Policy = "connection"
		s.Backends = []cpFactorBackend{
			{ID: "a", Active: 1, Healthy: true, Local: true, Label: true},
			{ID: "b", Active: 10, Healthy: true, Local: true, Label: true},
			{ID: "c", Active: 20, Healthy: true, Local: true, Label: true},
		}
		switch mode {
		case "no-physical":
			s.Backends[2].Active = 0
			s.Backends[2].Pending = 30
		case "zero-score":
			s.Backends[2].Healthy = false
			s.Backends[2].Outgoing = 20
			s.Rates[0] = 2 // A positive configured rate makes the score guard observable.
		case "incoming-only":
			s.Backends[2].Active = 0
			s.Backends[2].Incoming = 30
		case "next-worst":
			s.Policy = "resource"
			cpFactorPut(&s, "failure_pd", 2, "1.1")
			cpFactorPut(&s, "total_pd", 2, "10")
			// Health risk 1 is worse but neutral versus best 0. Its lower
			// connection score is inverted, so the next-worst source must win.
			s.Backends[2].Active = 1
			s.Backends[0].Active = 2
		case "negative-equal":
			s.Policy = "resource"
			s.Backends = s.Backends[:2]
			s.Backends[0].Active = 1
			s.Backends[1].Active = 20
			cpFactorPut(&s, "cpu", 0, "0.5")
			cpFactorPut(&s, "cpu", 1, "0.51")
		case "inverted":
			s.Policy = "resource"
			s.Backends = s.Backends[:2]
			s.Backends[0].Local = false
			s.Backends[1].Local = true
			cpFactorPut(&s, "failure_pd", 1, "1.1")
			cpFactorPut(&s, "total_pd", 1, "10")
		case "equal-clamped":
			s.Backends = s.Backends[:2]
			s.Backends[0].Active = 65535
			s.Backends[1].Active = 1000000
		case "cutoff-equal":
			s.Rates[5] = 0.0001
		case "cutoff-above":
			s.Rates[5] = 0.00010001
		}
		add("balance-"+mode, s)
	}
	return cases
}
