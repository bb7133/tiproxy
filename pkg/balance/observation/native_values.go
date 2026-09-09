// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package observation

// These are diagnostic values only. In particular none holds a BackendCtx,
// QueryResult, policy, query function, or production resource capability.
const (
	MaxEvaluationAccounts     = 64
	MaxEvaluationQueries      = 6
	MaxEvaluationSamples      = 4096
	MaxEvaluationClocks       = 64
	MaxEvaluationReads        = 128
	MaxEvaluationStringBytes  = 512
	MaxEvaluationStringsBytes = 64 << 10
	MaxEvaluationFactors      = 7
	MaxEvaluationAdvice       = MaxEvaluationAccounts * MaxEvaluationFactors
)

type EntryPoint uint8

const (
	EntryConfig EntryPoint = iota + 1
	EntryRoute
	EntryRouteable
	EntryBalance
	EntryClose
)

type FactorKind uint8

const (
	FactorLabel FactorKind = iota + 1
	FactorStatus
	FactorHealth
	FactorMemory
	FactorCPU
	FactorLocation
	FactorConnection
)

type ClockSite uint8

const (
	ClockMetricCadence ClockSite = iota + 1
	ClockStatusSnapshot
	ClockHealthExpiry
	ClockHealthSnapshot
	ClockMemorySnapshot
	ClockMemoryExpiry
	ClockCPUSnapshot
	ClockCPUExpiry
	ClockRandomTicket
	ClockPreferIdleTicket
)

type QueryKind uint8

const (
	QueryHealthFailure0 QueryKind = iota + 1
	QueryHealthTotal0
	QueryHealthFailure1
	QueryHealthTotal1
	QueryMemory
	QueryCPU
)

// DataRef indexes the same leased input arena; it never aliases producer data.
type DataRef struct{ Offset, Length uint32 }

type NativeConfig struct {
	BalancePolicy, RoutingPolicy, LabelName, SelfLabel DataRef
	Rates                                              [6]uint64 // IEEE754 bits: status, health, memory, cpu, location, conn
	CountRatio                                         uint64
}

type BackendField uint16

const (
	BackendID BackendField = 1 << iota
	BackendAddr
	BackendConnCount
	BackendConnScore
	BackendHealthy
	BackendLocal
	BackendKeyspace
	BackendInfo
)

type NativeBackend struct {
	Account                                uint64
	Seen                                   BackendField
	ID, Addr, Keyspace, IP, Cluster, Label DataRef
	StatusPort                             uint
	LabelPresent                           bool
	ConnCount, ConnScore                   int64
	Healthy, Local                         bool
	Parts                                  [MaxEvaluationFactors]uint64
	Packed                                 uint64
	Routeable                              bool
	RouteabilitySeen                       bool
}

type NativeProvenance struct {
	Cluster, SourceGeneration                             uint64
	Source                                                int32
	Producer, Registration, Publication, ReadRegistration uint64
}

type ReadKind uint8

const (
	ReadClock ReadKind = iota + 1
	ReadQuery
)

type QueryValueKind uint8

const (
	ValueNil QueryValueKind = iota + 1
	ValueNone
	ValueMatrix
	ValueVector
	ValueScalar
	ValueString
)

type NativeRead struct {
	Kind            ReadKind
	Site            ClockSite
	Ordinal         uint16
	Time            GoTimeValue
	Query           QueryKind
	Provenance      NativeProvenance
	ValueKind       QueryValueKind
	TypedNil, Empty bool
	Series          DataRef // bounded JSON array, in original first-match order
}

type NativeAdvice struct {
	Factor   FactorKind
	From, To uint8 // input-array indices; never sorted-array indices
	Advice   int8
	Count    uint64 // IEEE754 bits; kept separate from recomputed inputs
}

type NativeEvaluation struct {
	Group, Policy, Config, Resource, ID uint64
	Entry                               EntryPoint
	Configuration                       NativeConfig
	BackendCount                        uint16
	Backends                            [MaxEvaluationAccounts]NativeBackend
	FactorCount                         uint8
	Factors                             [MaxEvaluationFactors]FactorKind
	Widths                              [MaxEvaluationFactors]uint8
	ReadCount, ClockCount               uint16
	Reads                               [MaxEvaluationReads]NativeRead
	SampleCount, StringBytes            uint32
	QueryKinds                          uint8
	AdviceCount                         uint16
	Advice                              [MaxEvaluationAdvice]NativeAdvice
	SortedCount, ReturnedCount          uint16
	Sorted, Returned                    [MaxEvaluationAccounts]uint8
	From, To                            int16 // -1 means absent
	BalanceCount                        uint64
	Reason                              FactorKind
}
