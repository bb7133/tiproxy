// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package observation contains bounded diagnostic values and journal admission.
// It never owns a production router, connection, policy, callback or transport.
package observation

const (
	MaxEvents      = 4
	MaxWitnesses   = 2
	MaxOwners      = 128
	MaxRecords     = 4096
	MaxQueuedBytes = 64 << 20
	MaxFrameBytes  = 1 << 20
	// BatchCharge is a conservative bound for the fixed-size v2 JSON batch.
	// The encoder additionally checks its real size, outside production locks.
	BatchCharge = 8192
)

type Epoch struct {
	Process uint64
	Owner   uint64
	Nonce   uint64
}

type Kind uint8

const (
	Begin Kind = iota + 1
	Account
	RemoveAccount
	Open
	Reserve
	Created
	Redirect
	Redirected
	Closing
	Closed
	Rehydrate
	Rejected
	Retire
	End
	Watermark
	GroupCreated
	GroupRemoved
	SelectionDone
	RouteRejected
	Reconnect
)

// Event is a fixed-size allowlist of lifecycle values. Unused fields stay zero.
// Serialization and validation of each event's schema belong to the adapter.
type Event struct {
	Kind      Kind
	ID        uint64
	Group     uint64
	Session   uint64
	Operation uint64
	Account   uint64
	Target    uint64
	Success   bool
}

type AccountWitness struct {
	ID       uint64
	Score    int64
	Physical uint64
	Head     uint64
	Tail     uint64
}

// ConnectionState projects only state independently represented by the mirror.
// Go's factor advice, cooldown clocks and policy-specific phases are not inputs.
type ConnectionState struct {
	Present         bool
	Physical        uint64
	ScoreOwner      uint64
	RedirectPending bool
	Closing         bool
	Closed          bool
}

type Witness struct {
	AccountCount uint8
	Accounts     [MaxWitnesses]AccountWitness
	Session      uint64
	Predecessor  uint64
	Before       ConnectionState
	After        ConnectionState
}

// Batch is admitted atomically. Witnesses compare only after every event is
// independently applied; no snapshot between compound transition halves exists.
type Batch struct {
	EventCount uint8
	Events     [MaxEvents]Event
	Witness    Witness
}

type Record struct {
	Native   bool // immutable owner factory capability; v2 records still encode as v2
	Epoch    Epoch
	Sequence uint64 // sequence of Events[0]; the last is Sequence+EventCount-1
	Batch    Batch
	// An evaluation occupies one sequence. Its zero Batch is never interpreted
	// as a v2 lifecycle record; the writer uses the separate native codec.
	Evaluation *Evaluation
	// Caller retains one complete span, including every nested child lease.
	// Existing dialect encoders must reject it until the caller codec is used.
	Caller *Caller
}

type InvalidReason uint32

const (
	Valid InvalidReason = iota
	Capacity
	Malformed
	SequenceExhausted
	TransportLost
	OwnerDisappeared
	Shutdown
	Stale
	UnpairedDiscard
)

// InvalidSummary is explicitly not a lifecycle event or a comparison result.
// LastAdmitted must never advance a consumer's last successfully compared value.
type InvalidSummary struct {
	Epoch        Epoch
	Reason       InvalidReason
	LastAdmitted uint64
}
