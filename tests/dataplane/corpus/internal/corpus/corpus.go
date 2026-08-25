// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package corpus defines the language-neutral TiProxy dataplane protocol corpus.
package corpus

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	pnet "github.com/pingcap/tiproxy/pkg/proxy/net"
)

const (
	SchemaVersion    = 1
	GeneratorVersion = "tiproxy-go-oracle/v1"
	traceMagic       = "TPXCRP1\n"
)

type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	GeneratedBy   string `json:"generated_by"`
	Cases         []Case `json:"cases"`
}

type Case struct {
	ID              string            `json:"id"`
	Description     string            `json:"description"`
	ParityIDs       []string          `json:"parity_ids"`
	SourceRefs      []string          `json:"go_source_refs"`
	Capabilities    []string          `json:"capabilities"`
	InitialState    map[string]string `json:"initial_state"`
	TraceFile       string            `json:"trace_file"`
	TraceSHA256     string            `json:"trace_sha256"`
	UncompressedLen int               `json:"uncompressed_bytes"`
	Records         []Record          `json:"records"`
	Expected        Expected          `json:"expected"`

	trace []traceRecord
}

type Record struct {
	Direction           string `json:"direction"`
	SequenceStart       uint8  `json:"sequence_start"`
	LogicalPayloadBytes int    `json:"logical_payload_bytes"`
	PhysicalPackets     int    `json:"physical_packets"`
	TransportChunks     []int  `json:"transport_chunks,omitempty"`
}

type Expected struct {
	Outcome       string   `json:"outcome"`
	TerminalState string   `json:"terminal_state"`
	ServerStatus  []string `json:"server_status,omitempty"`
	ErrorCode     int      `json:"error_code,omitempty"`
	Effects       []string `json:"effects"`
}

type ObservationSet struct {
	SchemaVersion  int           `json:"schema_version"`
	Implementation string        `json:"implementation"`
	Cases          []Observation `json:"cases"`
}

type Observation struct {
	ID            string   `json:"id"`
	Outcome       string   `json:"outcome"`
	TerminalState string   `json:"terminal_state"`
	ServerStatus  []string `json:"server_status,omitempty"`
	ErrorCode     int      `json:"error_code,omitempty"`
	Effects       []string `json:"effects"`
}

type traceRecord struct {
	direction byte
	wire      []byte
}

func Build() Manifest {
	serverCaps := pnet.ClientProtocol41 | pnet.ClientSecureConnection | pnet.ClientPluginAuth |
		pnet.ClientConnectAttrs | pnet.ClientMultiStatements | pnet.ClientMultiResults |
		pnet.ClientPSMultiResults | pnet.ClientLocalFiles
	clientCaps := serverCaps | pnet.ClientConnectWithDB
	modernCaps := clientCaps | pnet.ClientDeprecateEOF | pnet.ClientZstdCompressionAlgorithm
	salt := [20]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a}

	query := commandPayload(pnet.ComQuery, []byte("SELECT 1"))
	largeQuery := make([]byte, pnet.MaxPayloadLen+33)
	largeQuery[0] = pnet.ComQuery.Byte()
	for i := 1; i < len(largeQuery); i++ {
		largeQuery[i] = byte('a' + (i % 23))
	}
	exactMax := make([]byte, pnet.MaxPayloadLen)
	exactMax[0] = pnet.ComQuery.Byte()
	for i := 1; i < len(exactMax); i++ {
		exactMax[i] = 'x'
	}

	legacyCaps := capNames(clientCaps)
	modernCapNames := capNames(modernCaps)
	ok := pnet.MakeOKPacket(pnet.ServerStatusAutocommit, pnet.OKHeader)
	okMore := pnet.MakeOKPacket(pnet.ServerStatusAutocommit|pnet.ServerMoreResultsExists, pnet.OKHeader)
	errPacket := pnet.MakeErrPacket(gomysql.NewError(gomysql.ER_PARSE_ERROR, "synthetic parse error"))
	legacyResult := [][]byte{{1}, columnDefinition("one"), pnet.MakeEOFPacket(pnet.ServerStatusAutocommit), {1, '1'}, pnet.MakeEOFPacket(pnet.ServerStatusAutocommit)}
	modernResult := [][]byte{{1}, columnDefinition("one"), {1, '1'}, pnet.MakeOKPacket(pnet.ServerStatusAutocommit, pnet.EOFHeader)}

	cases := []Case{
		makeCase("packet-fragmented-query", "COM_QUERY split across deliberately awkward TCP read boundaries.", []string{"PKT-001", "CMD-003"}, refs("pkg/proxy/net/packetio_test.go:TestPacketIO", "pkg/proxy/net/packetio_test.go:TestForwardUntil"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{query}, []int{1, 2, 1, 3, 5}}}, expect("forward", "awaiting_response", nil, 0, "one logical request is forwarded byte-for-byte")),
		makeCase("packet-large-query", "A logical COM_QUERY larger than one maximum MySQL physical packet.", []string{"PKT-002", "PKT-003", "CMD-003"}, refs("pkg/proxy/net/packetio_test.go:TestForwardUntilLongData", "pkg/proxy/backend/backend_conn_mgr_test.go:TestExecuteCmdStreamingForwardLargeQuery"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{largeQuery}, nil}}, expect("stream_forward", "awaiting_response", nil, 0, "two physical packets form one logical request", "capture is prefix-bounded")),
		makeCase("packet-exact-max-tail", "An exact MaxPayloadLen payload requires a trailing empty physical packet.", []string{"PKT-002"}, refs("pkg/proxy/net/packetio_test.go:TestForwardUntilLongData"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{exactMax}, nil}}, expect("forward", "awaiting_response", nil, 0, "empty terminating physical packet is preserved")),
		makeCase("packet-empty-payload", "A legal zero-length MySQL packet.", []string{"PKT-005"}, refs("pkg/proxy/net/packetio_test.go:TestReadPacketEmptyPayload"), nil, state("packet", "reading"), []recordSpec{{"client_to_proxy", 0, [][]byte{{}}, nil}}, expect("accept", "packet_complete", nil, 0, "logical payload is empty")),
		makeRawCase("packet-sequence-mismatch", "A packet whose sequence does not match the local counter.", []string{"PKT-004"}, refs("pkg/proxy/net/packetio_test.go:TestPacketSequence"), nil, state("packet", "expect_sequence_0"), "client_to_proxy", framePayloads(7, []byte{pnet.ComPing.Byte()}), expect("accept_with_warning", "packet_complete", nil, 0, "sequence advances from received value", "sequence mismatch is logged")),
		makeRawCase("packet-truncated-header", "EOF in the middle of a physical packet header.", []string{"PKT-007"}, refs("pkg/proxy/net/packetio_test.go:TestForwardUntilError"), nil, state("packet", "reading_header"), "client_to_proxy", []byte{1, 0}, expect("reject", "closed", nil, 0, "read error is attributed to the client source")),
		makeCase("handshake-initial-native", "Server initial handshake using mysql_native_password.", []string{"HS-001"}, refs("pkg/proxy/backend/authenticator_test.go:TestAuthPlugin", "pkg/proxy/net/mysql_test.go:TestHandshakeResp"), legacyCaps, state("handshake", "new"), []recordSpec{{"backend_to_proxy", 0, [][]byte{pnet.MakeInitialHandshake(serverCaps, salt, pnet.AuthNativePassword, "8.0.11-TiDB", 42)}, nil}}, expect("forward_rewritten", "awaiting_client_response", nil, 0, "server version and salt are parsed", "frontend connection ID is independently owned")),
		makeCase("handshake-response-native", "Client handshake response with database and deterministic authentication bytes.", []string{"HS-003", "HS-006"}, refs("pkg/proxy/backend/authenticator_test.go:TestCapability", "pkg/proxy/net/mysql_test.go:TestHandshakeResp"), legacyCaps, state("handshake", "awaiting_client_response"), []recordSpec{{"client_to_proxy", 1, [][]byte{pnet.MakeHandshakeResponse(&pnet.HandshakeResp{User: "corpus_user", DB: "corpus_db", AuthPlugin: pnet.AuthNativePassword, AuthData: []byte{1, 2, 3, 4}, Capability: clientCaps, Collation: 45})}, nil}}, expect("forward_rewritten", "authenticating_backend", nil, 0, "user and database become session state", "authentication bytes are synthetic")),
		makeCase("handshake-response-modern", "Client response with attributes, zstd, and deprecated EOF.", []string{"HS-003", "HS-006", "CMP-002"}, refs("pkg/proxy/backend/authenticator_test.go:TestCapability", "pkg/proxy/backend/authenticator_test.go:TestCompressProtocol", "pkg/proxy/backend/backend_conn_mgr_test.go:TestConnAttrs"), modernCapNames, state("handshake", "awaiting_client_response"), []recordSpec{{"client_to_proxy", 1, [][]byte{pnet.MakeHandshakeResponse(&pnet.HandshakeResp{User: "corpus_user", DB: "corpus_db", AuthPlugin: pnet.AuthCachingSha2Password, AuthData: []byte{5, 6, 7, 8}, Attrs: map[string]string{"_client_name": "tiproxy-corpus"}, Capability: modernCaps, ZstdLevel: 3, Collation: 45})}, nil}}, expect("forward_rewritten", "authenticating_backend", nil, 0, "connection attributes are retained", "zstd level is negotiated", "deprecated EOF mode is enabled")),
		makeRawCase("handshake-ssl-request", "A 32-byte SSLRequest before the TLS upgrade.", []string{"TLS-001", "HS-002"}, refs("pkg/proxy/backend/authenticator_test.go:TestEnableTLS"), capNames(clientCaps|pnet.ClientSSL), state("handshake", "awaiting_client_response"), "client_to_proxy", framePayloads(1, sslRequest(clientCaps|pnet.ClientSSL)), expect("tls_upgrade", "tls_handshake", nil, 0, "no credentials are parsed before TLS")),
		makeCase("auth-switch-native", "Backend requests mysql_native_password authentication.", []string{"HS-004"}, refs("pkg/proxy/backend/authenticator_test.go:TestAuthPlugin"), legacyCaps, state("handshake", "authenticating_backend"), []recordSpec{{"backend_to_proxy", 2, [][]byte{pnet.MakeSwitchRequest(pnet.AuthNativePassword, salt)}, nil}, {"client_to_proxy", 3, [][]byte{{9, 8, 7, 6}}, nil}}, expect("forward_rewritten", "authenticating_backend", nil, 0, "auth switch is relayed with backend salt")),
		makeCase("auth-caching-sha-full", "caching_sha2_password requests the full-authentication path.", []string{"HS-005"}, refs("pkg/proxy/backend/authenticator_test.go:TestAuthPlugin"), legacyCaps, state("handshake", "authenticating_backend"), []recordSpec{{"backend_to_proxy", 2, [][]byte{pnet.MakeShaCommand()}, nil}}, expect("forward", "awaiting_client_auth_data", nil, 0, "fast-auth failure byte is recognized")),
		makeCase("handshake-missing-protocol41", "Frontend omits mandatory CLIENT_PROTOCOL_41.", []string{"HS-002", "HS-008"}, refs("pkg/proxy/backend/authenticator_test.go:TestUnsupportedCapability"), capNames(clientCaps&^pnet.ClientProtocol41), state("handshake", "awaiting_client_response"), []recordSpec{{"client_to_proxy", 1, [][]byte{pnet.MakeHandshakeResponse(&pnet.HandshakeResp{User: "corpus_user", AuthData: []byte{1}, AuthPlugin: pnet.AuthNativePassword, Capability: clientCaps &^ pnet.ClientProtocol41, Collation: 45})}, nil}}, expect("reject", "closed", nil, 0, "error source is client handshake", "no MySQL error is synthesized for an invalid frontend capability set")),
		makeCase("query-ok", "COM_QUERY followed by a normal OK response.", []string{"CMD-003", "RSP-001", "RSP-008"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{query}, nil}, {"backend_to_proxy", 1, [][]byte{ok}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "server status is updated")),
		makeCase("query-error", "COM_QUERY followed by a synthetic parse error.", []string{"CMD-003", "RSP-001"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestQueryError"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{commandPayload(pnet.ComQuery, []byte("SELECT synthetic_error"))}, nil}, {"backend_to_proxy", 1, [][]byte{errPacket}, nil}}, expect("mysql_error", "ready", nil, gomysql.ER_PARSE_ERROR, "error packet is forwarded", "error source is backend command")),
		makeCase("resultset-legacy-eof", "Single-column result set using legacy EOF terminators.", []string{"CMD-003", "RSP-002", "RSP-008"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "awaiting_response"), []recordSpec{{"backend_to_proxy", 1, legacyResult, []int{2, 3, 5, 8}}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "column EOF and row EOF are recognized", "row payload is streamed")),
		makeCase("resultset-deprecate-eof", "Single-column result set using OK-as-EOF.", []string{"CMD-003", "RSP-003", "RSP-008"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), modernCapNames, state("command", "awaiting_response"), []recordSpec{{"backend_to_proxy", 1, modernResult, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "final OK-as-EOF is recognized")),
		makeCase("query-multi-results", "Two COM_QUERY results linked by SERVER_MORE_RESULTS_EXISTS.", []string{"CMD-003", "RSP-004"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestMultiStmt"), modernCapNames, state("command", "awaiting_response"), []recordSpec{{"backend_to_proxy", 1, [][]byte{okMore, ok}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "proxy continues after first result", "proxy stops after final result")),
		makeCase("local-infile", "LOCAL INFILE request, client chunks, empty terminator, and final OK.", []string{"CMD-003", "RSP-005"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "awaiting_response"), []recordSpec{{"backend_to_proxy", 1, [][]byte{append([]byte{pnet.LocalInFileHeader.Byte()}, []byte("synthetic.csv")...)}, nil}, {"client_to_proxy", 2, [][]byte{[]byte("1,alpha\n"), []byte("2,beta\n"), {}}, []int{1, 4, 2}}, {"backend_to_proxy", 5, [][]byte{ok}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "all file chunks are forwarded", "empty packet terminates upload")),
		makeCase("stmt-prepare-metadata", "COM_STMT_PREPARE with parameter and column metadata.", []string{"CMD-022", "PS-004", "RSP-006"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestPreparedStmts"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{commandPayload(pnet.ComStmtPrepare, []byte("SELECT ?"))}, nil}, {"backend_to_proxy", 1, prepareResponse(7, 1, 1, false), nil}}, expect("forward", "ready", nil, 0, "statement ID 7 becomes pending", "parameter and column metadata are forwarded")),
		makeCase("stmt-execute-cursor", "COM_STMT_EXECUTE opens a read-only cursor.", []string{"CMD-023", "PS-002", "PS-004"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestPreparedStmts"), legacyCaps, state("command", "statement_7_prepared"), []recordSpec{{"client_to_proxy", 0, [][]byte{stmtCommand(pnet.ComStmtExecute, 7, []byte{1, 0, 0, 0, 1, 0, 0, 0})}, nil}, {"backend_to_proxy", 1, [][]byte{{1}, columnDefinition("one"), pnet.MakeEOFPacket(pnet.ServerStatusAutocommit | pnet.ServerStatusCursorExists)}, nil}}, expect("forward", "cursor_open", []string{"SERVER_STATUS_AUTOCOMMIT", "SERVER_STATUS_CURSOR_EXISTS"}, 0, "statement remains pending", "rows are deferred until fetch")),
		makeCase("stmt-fetch", "COM_STMT_FETCH returns cursor rows and closes the cursor.", []string{"CMD-028", "PS-002"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestPreparedStmts"), legacyCaps, state("command", "cursor_open"), []recordSpec{{"client_to_proxy", 0, [][]byte{stmtCommand(pnet.ComStmtFetch, 7, []byte{1, 0, 0, 0})}, nil}, {"backend_to_proxy", 1, [][]byte{{1, '1'}, pnet.MakeEOFPacket(pnet.ServerStatusAutocommit | pnet.ServerStatusLastRowSend)}, nil}}, expect("forward", "statement_7_prepared", []string{"SERVER_STATUS_AUTOCOMMIT", "SERVER_STATUS_LAST_ROW_SENT"}, 0, "cursor-open status is cleared")),
		makeCase("stmt-long-data", "COM_STMT_SEND_LONG_DATA carries a synthetic parameter fragment.", []string{"CMD-024", "PS-001"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestPreparedStmts"), legacyCaps, state("command", "statement_7_prepared"), []recordSpec{{"client_to_proxy", 0, [][]byte{stmtCommand(pnet.ComStmtSendLongData, 7, []byte{0, 0, 'a', 'b', 'c'})}, nil}}, expect("forward_no_response", "statement_7_prepared", nil, 0, "long-data fragment is forwarded", "no backend response is awaited")),
		makeCase("stmt-close", "COM_STMT_CLOSE releases local prepared-statement state.", []string{"CMD-025", "PS-006"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestPreparedStmts"), legacyCaps, state("command", "statement_7_prepared"), []recordSpec{{"client_to_proxy", 0, [][]byte{stmtCommand(pnet.ComStmtClose, 7, nil)}, nil}}, expect("forward_no_response", "ready", nil, 0, "statement ID 7 is removed", "no backend response is awaited")),
		makeCase("change-user", "COM_CHANGE_USER is parsed and rewritten for backend authentication.", []string{"CMD-017", "HS-006", "PS-005"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands", "pkg/proxy/backend/backend_conn_mgr_test.go:TestSpecialCmds"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{pnet.MakeChangeUser(&pnet.ChangeUserReq{User: "next_user", DB: "next_db", AuthPlugin: pnet.AuthNativePassword, AuthData: []byte{1, 3, 3, 7}, Charset: []byte{45, 0}}, clientCaps)}, nil}}, expect("forward_rewritten", "authenticating_backend", nil, 0, "user and database update only after success", "backend salt is requested")),
		makeCase("init-db", "COM_INIT_DB updates the current database on success.", []string{"CMD-002"}, refs("pkg/proxy/backend/authenticator_test.go:TestSecondHandshake"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{commandPayload(pnet.ComInitDB, []byte("next_db"))}, nil}, {"backend_to_proxy", 1, [][]byte{ok}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "current database becomes next_db")),
		makeCase("set-option", "COM_SET_OPTION toggles multi-statements and receives EOF.", []string{"CMD-027"}, refs("pkg/proxy/backend/backend_conn_mgr_test.go:TestSpecialCmds"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{commandPayload(pnet.ComSetOption, []byte{0, 0})}, nil}, {"backend_to_proxy", 1, [][]byte{pnet.MakeEOFPacket(pnet.ServerStatusAutocommit)}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "multi-statement capability is enabled")),
		makeCase("stmt-reset", "COM_STMT_RESET clears cursor and long-data state but keeps the statement.", []string{"CMD-026", "PS-001", "PS-002"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestPreparedStmts"), legacyCaps, state("command", "statement_7_has_long_data"), []recordSpec{{"client_to_proxy", 0, [][]byte{stmtCommand(pnet.ComStmtReset, 7, nil)}, nil}, {"backend_to_proxy", 1, [][]byte{ok}, nil}}, expect("forward", "statement_7_prepared", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "cursor and buffered parameter state are cleared", "statement ID 7 remains pending")),
		makeCase("reset-connection", "COM_RESET_CONNECTION clears session-scoped state.", []string{"CMD-031", "PS-005"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "session_modified"), []recordSpec{{"client_to_proxy", 0, [][]byte{{pnet.ComResetConnection.Byte()}}, nil}, {"backend_to_proxy", 1, [][]byte{ok}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "transaction, prepared statement, database, and session-state tracking are reset")),
		makeCase("ping", "COM_PING receives a normal OK response.", []string{"CMD-014"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{{pnet.ComPing.Byte()}}, nil}, {"backend_to_proxy", 1, [][]byte{ok}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "liveness response is forwarded")),
		makeCase("statistics", "COM_STATISTICS returns a raw human-readable payload.", []string{"CMD-009"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{{pnet.ComStatistics.Byte()}}, nil}, {"backend_to_proxy", 1, [][]byte{[]byte("Uptime: 1  Threads: 1")}, nil}}, expect("forward", "ready", nil, 0, "raw statistics payload is forwarded")),
		makeCase("field-list", "COM_FIELD_LIST ends with a legacy EOF packet.", []string{"CMD-004"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{commandPayload(pnet.ComFieldList, append([]byte("t"), 0, '*'))}, nil}, {"backend_to_proxy", 1, [][]byte{columnDefinition("c"), pnet.MakeEOFPacket(pnet.ServerStatusAutocommit)}, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "field metadata is forwarded through EOF")),
		makeCase("process-info", "COM_PROCESS_INFO uses result-set forwarding.", []string{"CMD-010"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{{pnet.ComProcessInfo.Byte()}}, nil}, {"backend_to_proxy", 1, legacyResult, nil}}, expect("forward", "ready", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "result set is streamed")),
		makeCase("quit", "COM_QUIT closes the session without a response.", []string{"CMD-001"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestForwardCommands"), legacyCaps, state("command", "ready"), []recordSpec{{"client_to_proxy", 0, [][]byte{{pnet.ComQuit.Byte()}}, nil}}, expect("disconnect", "closed", nil, 0, "quit status is set", "no backend response is awaited")),
		makeCase("migration-session-state", "Internal SHOW SESSION_STATES result contains sanitized state and a session token.", []string{"MIG-002", "MIG-004", "RSP-007"}, refs("pkg/proxy/backend/backend_conn_mgr_test.go:TestNormalRedirect", "pkg/proxy/backend/backend_conn_mgr.go:querySessionStates"), modernCapNames, state("migration", "querying_session_state"), []recordSpec{{"proxy_to_backend", 0, [][]byte{commandPayload(pnet.ComQuery, []byte("SHOW SESSION_STATES"))}, nil}, {"backend_to_proxy", 1, migrationResult(), nil}}, expect("capture_internal_result", "ready_to_reconnect", []string{"SERVER_STATUS_AUTOCOMMIT"}, 0, "session state JSON is retained", "session token is retained", "ordinary result payloads remain opaque")),
		makeRawCase("change-user-malformed", "Truncated COM_CHANGE_USER authentication data.", []string{"CMD-017", "HS-008"}, refs("pkg/proxy/backend/cmd_processor_test.go:TestNetworkError"), legacyCaps, state("command", "ready"), "client_to_proxy", framePayloads(0, []byte{pnet.ComChangeUser.Byte(), 'u', 0, 8, 1}), expect("reject", "closed", nil, gomysql.ER_MALFORMED_PACKET, "malformed command is not forwarded")),
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return Manifest{SchemaVersion: SchemaVersion, GeneratedBy: GeneratorVersion, Cases: cases}
}

type recordSpec struct {
	direction string
	sequence  uint8
	payloads  [][]byte
	chunks    []int
}

func makeCase(id, description string, parityIDs, sourceRefs, capabilities []string, initial map[string]string, specs []recordSpec, expected Expected) Case {
	c := Case{ID: id, Description: description, ParityIDs: parityIDs, SourceRefs: sourceRefs, Capabilities: capabilities, InitialState: initial, TraceFile: filepath.ToSlash(filepath.Join("cases", id+".trace.gz")), Expected: expected}
	for _, spec := range specs {
		wire := framePayloads(spec.sequence, spec.payloads...)
		c.trace = append(c.trace, traceRecord{direction: directionByte(spec.direction), wire: wire})
		packets := 0
		for _, payload := range spec.payloads {
			packets += physicalPacketCount(len(payload))
		}
		logicalBytes := 0
		for _, payload := range spec.payloads {
			logicalBytes += len(payload)
		}
		c.Records = append(c.Records, Record{Direction: spec.direction, SequenceStart: spec.sequence, LogicalPayloadBytes: logicalBytes, PhysicalPackets: packets, TransportChunks: spec.chunks})
	}
	return c
}

func makeRawCase(id, description string, parityIDs, sourceRefs, capabilities []string, initial map[string]string, direction string, wire []byte, expected Expected) Case {
	c := Case{ID: id, Description: description, ParityIDs: parityIDs, SourceRefs: sourceRefs, Capabilities: capabilities, InitialState: initial, TraceFile: filepath.ToSlash(filepath.Join("cases", id+".trace.gz")), Expected: expected}
	c.trace = []traceRecord{{direction: directionByte(direction), wire: wire}}
	c.Records = []Record{{Direction: direction, SequenceStart: sequenceFromWire(wire), LogicalPayloadBytes: logicalBytesFromWire(wire), PhysicalPackets: packetCountFromWire(wire)}}
	return c
}

func refs(values ...string) []string { return values }

func state(phase, value string) map[string]string {
	return map[string]string{"phase": phase, "state": value}
}

func expect(outcome, terminal string, status []string, code int, effects ...string) Expected {
	return Expected{Outcome: outcome, TerminalState: terminal, ServerStatus: status, ErrorCode: code, Effects: effects}
}

func commandPayload(command pnet.Command, data []byte) []byte {
	return append([]byte{command.Byte()}, data...)
}

func stmtCommand(command pnet.Command, stmtID uint32, tail []byte) []byte {
	payload := make([]byte, 5, 5+len(tail))
	payload[0] = command.Byte()
	binary.LittleEndian.PutUint32(payload[1:], stmtID)
	return append(payload, tail...)
}

func sslRequest(capability pnet.Capability) []byte {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload, capability.Uint32())
	payload[8] = 45
	return payload
}

func columnDefinition(name string) []byte {
	// The corpus needs stable bytes, not a full SQL type model. These are legal
	// length-encoded catalog/schema/table/name fields followed by fixed metadata.
	fields := []string{"def", "corpus", "t", "t", name, name}
	data := make([]byte, 0, 64)
	for _, field := range fields {
		data = append(data, byte(len(field)))
		data = append(data, field...)
	}
	data = append(data, 0x0c, 45, 0, 11, 0, 0, 0, 0x03, 0, 0, 0, 0, 0)
	return data
}

func prepareResponse(stmtID uint32, columns, params uint16, deprecateEOF bool) [][]byte {
	header := make([]byte, 12)
	header[0] = pnet.OKHeader.Byte()
	binary.LittleEndian.PutUint32(header[1:], stmtID)
	binary.LittleEndian.PutUint16(header[5:], columns)
	binary.LittleEndian.PutUint16(header[7:], params)
	result := [][]byte{header}
	for i := uint16(0); i < params; i++ {
		result = append(result, columnDefinition(fmt.Sprintf("p%d", i)))
	}
	if params > 0 && !deprecateEOF {
		result = append(result, pnet.MakeEOFPacket(pnet.ServerStatusAutocommit))
	}
	for i := uint16(0); i < columns; i++ {
		result = append(result, columnDefinition(fmt.Sprintf("c%d", i)))
	}
	if columns > 0 && !deprecateEOF {
		result = append(result, pnet.MakeEOFPacket(pnet.ServerStatusAutocommit))
	}
	return result
}

func migrationResult() [][]byte {
	row := pnet.DumpLengthEncodedString(nil, []byte(`{"current-db":"corpus_db"}`))
	row = pnet.DumpLengthEncodedString(row, []byte("synthetic-token-1"))
	return [][]byte{
		{2},
		columnDefinition("Session_states"),
		columnDefinition("Session_token"),
		pnet.MakeEOFPacket(pnet.ServerStatusAutocommit),
		row,
		pnet.MakeEOFPacket(pnet.ServerStatusAutocommit),
	}
}

func capNames(capability pnet.Capability) []string {
	if capability == 0 {
		return nil
	}
	names := strings.Split(capability.String(), "|")
	sort.Strings(names)
	return names
}

func framePayloads(sequence uint8, payloads ...[]byte) []byte {
	var wire []byte
	for _, payload := range payloads {
		wire = append(wire, framePayload(sequence, payload)...)
		sequence += uint8(physicalPacketCount(len(payload)))
	}
	return wire
}

func framePayload(sequence uint8, payload []byte) []byte {
	var wire []byte
	for {
		length := min(len(payload), pnet.MaxPayloadLen)
		wire = append(wire, byte(length), byte(length>>8), byte(length>>16), sequence)
		wire = append(wire, payload[:length]...)
		payload = payload[length:]
		sequence++
		if length < pnet.MaxPayloadLen {
			return wire
		}
	}
}

func physicalPacketCount(payloadLen int) int { return payloadLen/pnet.MaxPayloadLen + 1 }

func directionByte(direction string) byte {
	switch direction {
	case "client_to_proxy":
		return 1
	case "proxy_to_client":
		return 2
	case "backend_to_proxy":
		return 3
	case "proxy_to_backend":
		return 4
	default:
		panic("unknown direction: " + direction)
	}
}

func directionName(direction byte) string {
	switch direction {
	case 1:
		return "client_to_proxy"
	case 2:
		return "proxy_to_client"
	case 3:
		return "backend_to_proxy"
	case 4:
		return "proxy_to_backend"
	default:
		return "unknown"
	}
}

func sequenceFromWire(wire []byte) uint8 {
	if len(wire) < 4 {
		return 0
	}
	return wire[3]
}

func packetCountFromWire(wire []byte) int {
	count := 0
	for len(wire) >= 4 {
		length := int(wire[0]) | int(wire[1])<<8 | int(wire[2])<<16
		if len(wire) < 4+length {
			break
		}
		count++
		wire = wire[4+length:]
	}
	return count
}

func logicalBytesFromWire(wire []byte) int {
	total := 0
	for len(wire) >= 4 {
		length := int(wire[0]) | int(wire[1])<<8 | int(wire[2])<<16
		if len(wire) < 4+length {
			break
		}
		total += length
		wire = wire[4+length:]
	}
	return total
}

func encodeTrace(records []traceRecord) []byte {
	var out bytes.Buffer
	out.WriteString(traceMagic)
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(records)))
	for _, record := range records {
		out.WriteByte(record.direction)
		_ = binary.Write(&out, binary.LittleEndian, uint64(len(record.wire)))
		out.Write(record.wire)
	}
	return out.Bytes()
}

func decodeTrace(data []byte) ([]traceRecord, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, len(traceMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != traceMagic {
		return nil, errors.New("invalid trace magic")
	}
	var count uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	records := make([]traceRecord, 0, count)
	for i := uint32(0); i < count; i++ {
		direction, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if directionName(direction) == "unknown" {
			return nil, fmt.Errorf("unknown direction byte %d", direction)
		}
		var length uint64
		if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
			return nil, err
		}
		if length > uint64(reader.Len()) {
			return nil, errors.New("trace record exceeds remaining data")
		}
		wire := make([]byte, int(length))
		if _, err := io.ReadFull(reader, wire); err != nil {
			return nil, err
		}
		records = append(records, traceRecord{direction: direction, wire: wire})
	}
	if reader.Len() != 0 {
		return nil, errors.New("trailing bytes after trace records")
	}
	return records, nil
}

func Write(dir string) error {
	manifest := Build()
	if err := os.MkdirAll(filepath.Join(dir, "cases"), 0o755); err != nil {
		return err
	}
	for i := range manifest.Cases {
		trace := encodeTrace(manifest.Cases[i].trace)
		sum := sha256.Sum256(trace)
		manifest.Cases[i].TraceSHA256 = hex.EncodeToString(sum[:])
		manifest.Cases[i].UncompressedLen = len(trace)
		path := filepath.Join(dir, filepath.FromSlash(manifest.Cases[i].TraceFile))
		if err := writeGzip(path, trace); err != nil {
			return err
		}
		manifest.Cases[i].trace = nil
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o600)
}

func writeGzip(path string, data []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		_ = file.Close()
		return err
	}
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		_ = file.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func Validate(dir string) error {
	manifest, err := ReadManifest(dir)
	if err != nil {
		return err
	}
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", manifest.SchemaVersion)
	}
	if manifest.GeneratedBy != GeneratorVersion {
		return fmt.Errorf("unexpected generator %q", manifest.GeneratedBy)
	}
	seen := make(map[string]struct{}, len(manifest.Cases))
	for _, c := range manifest.Cases {
		if c.ID == "" || c.Description == "" || len(c.ParityIDs) == 0 || len(c.SourceRefs) == 0 || len(c.InitialState) == 0 || c.TraceFile == "" || c.Expected.Outcome == "" || c.Expected.TerminalState == "" || len(c.Expected.Effects) == 0 {
			return fmt.Errorf("case %q is missing required metadata", c.ID)
		}
		if _, ok := seen[c.ID]; ok {
			return fmt.Errorf("duplicate case ID %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		trace, err := readGzip(filepath.Join(dir, filepath.FromSlash(c.TraceFile)))
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		sum := sha256.Sum256(trace)
		if hex.EncodeToString(sum[:]) != c.TraceSHA256 || len(trace) != c.UncompressedLen {
			return fmt.Errorf("case %s: trace digest or length mismatch", c.ID)
		}
		records, err := decodeTrace(trace)
		if err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
		if len(records) != len(c.Records) {
			return fmt.Errorf("case %s: record count mismatch", c.ID)
		}
		for i, record := range records {
			metadata := c.Records[i]
			if directionName(record.direction) != metadata.Direction {
				return fmt.Errorf("case %s record %d: direction mismatch", c.ID, i)
			}
			if sequenceFromWire(record.wire) != metadata.SequenceStart || packetCountFromWire(record.wire) != metadata.PhysicalPackets || logicalBytesFromWire(record.wire) != metadata.LogicalPayloadBytes {
				return fmt.Errorf("case %s record %d: packet metadata mismatch", c.ID, i)
			}
			for _, chunk := range metadata.TransportChunks {
				if chunk <= 0 {
					return fmt.Errorf("case %s record %d: transport chunks must be positive", c.ID, i)
				}
			}
		}
		lower := strings.ToLower(string(trace))
		for _, forbidden := range []string{"begin private key", "akia", "password=", "secret="} {
			if strings.Contains(lower, forbidden) {
				return fmt.Errorf("case %s: possible credential material %q", c.ID, forbidden)
			}
		}
	}
	return nil
}

func ReadManifest(dir string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func readGzip(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(bufio.NewReader(file))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func CheckGenerated(dir string) error {
	tmp, err := os.MkdirTemp("", "tiproxy-corpus-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := Write(tmp); err != nil {
		return err
	}
	return compareTrees(dir, tmp)
}

func compareTrees(left, right string) error {
	leftFiles, err := listFiles(left)
	if err != nil {
		return err
	}
	rightFiles, err := listFiles(right)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(leftFiles, rightFiles) {
		return fmt.Errorf("generated file list differs: committed=%v generated=%v", leftFiles, rightFiles)
	}
	for _, name := range leftFiles {
		leftData, err := os.ReadFile(filepath.Join(left, name))
		if err != nil {
			return err
		}
		rightData, err := os.ReadFile(filepath.Join(right, name))
		if err != nil {
			return err
		}
		if !bytes.Equal(leftData, rightData) {
			return fmt.Errorf("generated file differs: %s", name)
		}
	}
	return nil
}

func listFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == "README.md" || entry.Name() == "schema.json" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	sort.Strings(files)
	return files, err
}

func ExpectedObservations(manifest Manifest, implementation string) ObservationSet {
	observed := ObservationSet{SchemaVersion: manifest.SchemaVersion, Implementation: implementation}
	for _, c := range manifest.Cases {
		observed.Cases = append(observed.Cases, Observation{ID: c.ID, Outcome: c.Expected.Outcome, TerminalState: c.Expected.TerminalState, ServerStatus: c.Expected.ServerStatus, ErrorCode: c.Expected.ErrorCode, Effects: c.Expected.Effects})
	}
	return observed
}

func Compare(manifest Manifest, observed ObservationSet) error {
	if observed.SchemaVersion != manifest.SchemaVersion {
		return fmt.Errorf("observation schema version %d does not match corpus %d", observed.SchemaVersion, manifest.SchemaVersion)
	}
	if observed.Implementation == "" {
		return errors.New("observation implementation is required")
	}
	want := make(map[string]Expected, len(manifest.Cases))
	for _, c := range manifest.Cases {
		want[c.ID] = c.Expected
	}
	seen := make(map[string]struct{}, len(observed.Cases))
	var differences []string
	for _, got := range observed.Cases {
		if _, duplicate := seen[got.ID]; duplicate {
			differences = append(differences, fmt.Sprintf("%s: duplicate observation", got.ID))
			continue
		}
		seen[got.ID] = struct{}{}
		expected, ok := want[got.ID]
		if !ok {
			differences = append(differences, fmt.Sprintf("%s: unknown case", got.ID))
			continue
		}
		actual := Expected{Outcome: got.Outcome, TerminalState: got.TerminalState, ServerStatus: got.ServerStatus, ErrorCode: got.ErrorCode, Effects: got.Effects}
		if !reflect.DeepEqual(expected, actual) {
			differences = append(differences, fmt.Sprintf("%s: expected %+v, got %+v", got.ID, expected, actual))
		}
	}
	for id := range want {
		if _, ok := seen[id]; !ok {
			differences = append(differences, fmt.Sprintf("%s: missing observation", id))
		}
	}
	sort.Strings(differences)
	if len(differences) > 0 {
		return errors.New(strings.Join(differences, "\n"))
	}
	return nil
}
