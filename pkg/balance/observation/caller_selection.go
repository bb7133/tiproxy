// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

// SelectorErrorClass preserves the exact equality used by BackendSelector.Next.
// A wrapped ErrNoBackend is OtherError even if errors.Is would match it.
// The router metadata and selector codecs share these wire discriminants.
type SelectorErrorClass uint8

const (
	SelectorNoError SelectorErrorClass = iota + 1
	SelectorExactNoBackend
	SelectorOtherError
)
