// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package shadow owns the temporary, observation-only local side channel.
// Router capture and domain accounting live in separate packages.
package shadow

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/pingcap/tiproxy/pkg/balance/observation"
)

var errSchema = errors.New("invalid routing shadow v2 schema")

type decimal uint64

func (d decimal) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(d), 10))
}
func (d *decimal) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) != nil {
		return errSchema
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != text {
		return errSchema
	}
	*d = decimal(n)
	return nil
}

type signed int64

func (d signed) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatInt(int64(d), 10)) }
func (d *signed) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) != nil {
		return errSchema
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != text {
		return errSchema
	}
	*d = signed(n)
	return nil
}

type header struct {
	Version       uint32  `json:"version"`
	Kind          string  `json:"kind"`
	Process       decimal `json:"process"`
	Owner         decimal `json:"owner"`
	Nonce         decimal `json:"nonce"`
	LifecycleOnly bool    `json:"lifecycle_only"`
	Factors       bool    `json:"factors"`
	Selection     bool    `json:"selection"`
	Scheduler     bool    `json:"scheduler"`
}
type wireEvent struct {
	Kind      string  `json:"kind"`
	ID        decimal `json:"id"`
	Group     decimal `json:"group"`
	Session   decimal `json:"session"`
	Operation decimal `json:"operation"`
	Account   decimal `json:"account"`
	Target    decimal `json:"target"`
	Success   bool    `json:"success"`
}
type wireAccount struct {
	ID       decimal `json:"id"`
	Score    signed  `json:"score"`
	Physical decimal `json:"physical"`
	Head     decimal `json:"head"`
	Tail     decimal `json:"tail"`
}
type wireConnection struct {
	Present         bool    `json:"present"`
	Physical        decimal `json:"physical"`
	ScoreOwner      decimal `json:"score_owner"`
	RedirectPending bool    `json:"redirect_pending"`
	Closing         bool    `json:"closing"`
	Closed          bool    `json:"closed"`
}
type wireWitness struct {
	Accounts    []wireAccount  `json:"accounts"`
	Session     decimal        `json:"session"`
	Predecessor decimal        `json:"predecessor"`
	Before      wireConnection `json:"before"`
	After       wireConnection `json:"after"`
}
type batchFrame struct {
	header
	Sequence decimal     `json:"sequence"`
	Events   []wireEvent `json:"events"`
	Witness  wireWitness `json:"witness"`
}
type invalidFrame struct {
	header
	LastAdmitted decimal `json:"last_admitted"`
	Reason       string  `json:"reason"`
}

var eventNames = [...]string{"", "begin", "account", "remove_account", "open", "reserve", "created", "redirect", "redirected", "closing", "closed", "rehydrate", "rejected", "retire", "end", "watermark", "group_created", "group_removed", "selection_done", "route_rejected", "reconnect"}
var reasonNames = [...]string{"", "capacity", "malformed", "sequence_exhausted", "transport_lost", "owner_disappeared", "shutdown", "stale", "unpaired_discard"}

func newHeader(kind string, epoch observation.Epoch) header {
	return header{Version: 2, Kind: kind, Process: decimal(epoch.Process), Owner: decimal(epoch.Owner), Nonce: decimal(epoch.Nonce), LifecycleOnly: true}
}
func connection(state observation.ConnectionState) wireConnection {
	return wireConnection{state.Present, decimal(state.Physical), decimal(state.ScoreOwner), state.RedirectPending, state.Closing, state.Closed}
}
func eventValue(e observation.Event) (wireEvent, error) {
	if e.Kind == 0 || int(e.Kind) >= len(eventNames) {
		return wireEvent{}, errSchema
	}
	expected := observation.Event{Kind: e.Kind}
	switch e.Kind {
	case observation.Account:
		expected.ID, expected.Group = e.ID, e.Group
	case observation.RemoveAccount:
		expected.Account = e.Account
	case observation.Open, observation.Closed, observation.SelectionDone:
		expected.Session = e.Session
	case observation.Reserve:
		expected.Session, expected.Operation, expected.Account = e.Session, e.Operation, e.Account
	case observation.Created:
		expected.Session, expected.Operation, expected.Success = e.Session, e.Operation, e.Success
	case observation.Redirect, observation.Rejected:
		expected.Session, expected.Operation, expected.Account, expected.Target = e.Session, e.Operation, e.Account, e.Target
	case observation.Redirected:
		expected.Session, expected.Operation, expected.Account, expected.Target, expected.Success = e.Session, e.Operation, e.Account, e.Target, e.Success
	case observation.Closing:
		expected.Session, expected.Operation = e.Session, e.Operation
	case observation.Rehydrate:
		expected.Session, expected.Account = e.Session, e.Account
	case observation.GroupCreated, observation.GroupRemoved:
		expected.Group = e.Group
	case observation.RouteRejected:
		expected.Session, expected.Group = e.Session, e.Group
	case observation.Reconnect:
		expected.Session, expected.Operation, expected.Account, expected.Success = e.Session, e.Operation, e.Account, e.Success
	}
	if expected != e {
		return wireEvent{}, errSchema
	}
	return wireEvent{eventNames[e.Kind], decimal(e.ID), decimal(e.Group), decimal(e.Session), decimal(e.Operation), decimal(e.Account), decimal(e.Target), e.Success}, nil
}

// EncodeRecord serializes fixed capture values off all production locks. Its
// complete allocation and encoded length must fit the already-retained charge.
func EncodeRecord(record observation.Record) ([]byte, error) {
	b := record.Batch
	if b.EventCount < 1 || b.EventCount > observation.MaxEvents || b.Witness.AccountCount > observation.MaxWitnesses || record.Sequence == 0 {
		return nil, errSchema
	}
	f := batchFrame{header: newHeader("batch", record.Epoch), Sequence: decimal(record.Sequence), Events: make([]wireEvent, b.EventCount)}
	for i := range f.Events {
		e, err := eventValue(b.Events[i])
		if err != nil {
			return nil, err
		}
		f.Events[i] = e
	}
	w := b.Witness
	f.Witness = wireWitness{Accounts: make([]wireAccount, w.AccountCount), Session: decimal(w.Session), Predecessor: decimal(w.Predecessor), Before: connection(w.Before), After: connection(w.After)}
	for i := range f.Witness.Accounts {
		a := w.Accounts[i]
		f.Witness.Accounts[i] = wireAccount{decimal(a.ID), signed(a.Score), decimal(a.Physical), decimal(a.Head), decimal(a.Tail)}
	}
	if record.Epoch.Process == 0 || record.Epoch.Owner == 0 || record.Epoch.Nonce == 0 {
		return nil, errSchema
	}
	return encode(f)
}

// EncodeInvalid is out of band: LastAdmitted never becomes a compared sequence.
func EncodeInvalid(summary observation.InvalidSummary) ([]byte, error) {
	if summary.Reason == 0 || int(summary.Reason) >= len(reasonNames) || summary.Epoch.Process == 0 || summary.Epoch.Owner == 0 || summary.Epoch.Nonce == 0 {
		return nil, errSchema
	}
	return encode(invalidFrame{newHeader("invalid", summary.Epoch), decimal(summary.LastAdmitted), reasonNames[summary.Reason]})
}

// EncodeCoverage identifies the stream and explicitly excludes factor/decision
// comparison. Owner zero denotes stream metadata, never a namespace epoch.
func EncodeCoverage(process, nonce uint64) ([]byte, error) {
	if process == 0 || nonce == 0 {
		return nil, errSchema
	}
	return encode(newHeader("coverage", observation.Epoch{Process: process, Nonce: nonce}))
}
func encode(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(body) > observation.MaxFrameBytes || len(body)+4 > observation.BatchCharge {
		return nil, errSchema
	}
	frame := make([]byte, 4, len(body)+4)
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	return append(frame, body...), nil
}

// ValidateFrame is the strict Go-side codec gate; the consumer independently
// decodes into Rust domain values. Missing, duplicate and unknown keys all fail.
func ValidateFrame(frame []byte) error {
	if len(frame) < 4 {
		return errSchema
	}
	size := binary.BigEndian.Uint32(frame)
	if size == 0 || size > observation.MaxFrameBytes || int(size) != len(frame)-4 {
		return errSchema
	}
	body := frame[4:]
	decoder := json.NewDecoder(bytes.NewReader(body))
	tree, err := strictValue(decoder, 0)
	if err != nil {
		return err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return errSchema
	}
	object, ok := tree.(map[string]any)
	if !ok {
		return errSchema
	}
	var target any
	switch object["kind"] {
	case "batch":
		target = &batchFrame{}
	case "invalid":
		target = &invalidFrame{}
	case "coverage":
		target = &header{}
	default:
		return errSchema
	}
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		return errSchema
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	decoded := json.NewDecoder(bytes.NewReader(canonical))
	expected, err := strictValue(decoded, 0)
	if err != nil || !sameShape(tree, expected) {
		return errSchema
	}
	var h header
	switch f := target.(type) {
	case *batchFrame:
		h = f.header
		if f.Sequence == 0 || len(f.Events) < 1 || len(f.Events) > observation.MaxEvents || len(f.Witness.Accounts) > observation.MaxWitnesses || f.Witness.Accounts == nil {
			return errSchema
		}
		for _, e := range f.Events {
			var kind observation.Kind
			for i, name := range eventNames {
				if name == e.Kind {
					kind = observation.Kind(i)
					break
				}
			}
			_, err = eventValue(observation.Event{Kind: kind, ID: uint64(e.ID), Group: uint64(e.Group), Session: uint64(e.Session), Operation: uint64(e.Operation), Account: uint64(e.Account), Target: uint64(e.Target), Success: e.Success})
			if err != nil {
				return err
			}
		}
	case *invalidFrame:
		h = f.header
		valid := false
		for _, r := range reasonNames[1:] {
			valid = valid || r == f.Reason
		}
		if !valid {
			return errSchema
		}
	case *header:
		h = *f
	}
	if h.Version != 2 || h.Process == 0 || h.Nonce == 0 || !h.LifecycleOnly || h.Factors || h.Selection || h.Scheduler || (h.Kind == "coverage") != (h.Owner == 0) {
		return errSchema
	}
	return nil
}

func strictValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, errSchema
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errSchema
	}
	switch token {
	case json.Delim('{'):
		object := map[string]any{}
		for decoder.More() {
			k, err := decoder.Token()
			if err != nil {
				return nil, errSchema
			}
			key, ok := k.(string)
			if !ok {
				return nil, errSchema
			}
			if _, exists := object[key]; exists {
				return nil, errSchema
			}
			v, err := strictValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = v
		}
		if t, err := decoder.Token(); err != nil || t != json.Delim('}') {
			return nil, errSchema
		}
		return object, nil
	case json.Delim('['):
		var array []any
		for decoder.More() {
			if len(array) >= observation.MaxEvents {
				return nil, errSchema
			}
			v, err := strictValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, v)
		}
		if t, err := decoder.Token(); err != nil || t != json.Delim(']') {
			return nil, errSchema
		}
		return array, nil
	default:
		if _, ok := token.(json.Delim); ok {
			return nil, errSchema
		}
		return token, nil
	}
}
func sameShape(actual, expected any) bool {
	switch wanted := expected.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok || len(got) != len(wanted) {
			return false
		}
		for k, v := range wanted {
			value, ok := got[k]
			if !ok || !sameShape(value, v) {
				return false
			}
		}
		return true
	case []any:
		got, ok := actual.([]any)
		if !ok || len(got) != len(wanted) {
			return false
		}
		for i, v := range wanted {
			if !sameShape(got[i], v) {
				return false
			}
		}
		return true
	case string:
		_, ok := actual.(string)
		return ok
	case bool:
		_, ok := actual.(bool)
		return ok
	case float64:
		_, ok := actual.(float64)
		return ok
	default:
		return actual == nil && expected == nil
	}
}
