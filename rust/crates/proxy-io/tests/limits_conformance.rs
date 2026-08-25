// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! WIRE-07 conformance: transport-owned limits stay anchored to the central
//! registry in `mysql_wire::limits` without moving their definitions.

use std::time::Duration;

use proxy_io::compression::{DEFAULT_MAX_EXPANSION_RATIO, MAX_COMPRESSED_FRAME_LEN};
use proxy_io::socket::{DIAL_ATTEMPT_TIMEOUT, DIAL_TOTAL_TIMEOUT};
use proxy_io::{
    DEFAULT_PUMP_BUFFER_SIZE, DEFAULT_STREAM_BUFFER_SIZE, DEFAULT_WRITE_HIGH_WATER,
    DuplexPumpConfig,
};

/// The Go-derived transport constants that WIRE-02/06 froze; a drift here is
/// a deliberate change that must update both sides and the review record.
#[test]
fn transport_constants_match_registered_values() {
    assert_eq!(DEFAULT_STREAM_BUFFER_SIZE, 32 * 1024);
    assert_eq!(DEFAULT_PUMP_BUFFER_SIZE, 32 * 1024);
    assert_eq!(DEFAULT_WRITE_HIGH_WATER, 64 * 1024);
    assert_eq!(DIAL_ATTEMPT_TIMEOUT, Duration::from_secs(1));
    assert_eq!(DIAL_TOTAL_TIMEOUT, Duration::from_secs(15));

    let pump = DuplexPumpConfig::default();
    assert_eq!(pump.max_flush_delay, Duration::from_millis(1));
    assert_eq!(pump.write_timeout, Duration::from_secs(30));
    assert_eq!(pump.shutdown_timeout, Duration::from_secs(1));
}

/// The compression bounds registered in the central module description.
#[test]
fn compression_bounds_match_registered_values() {
    assert_eq!(
        MAX_COMPRESSED_FRAME_LEN,
        mysql_wire::limits::MAX_PHYSICAL_PAYLOAD_LEN
    );
    assert_eq!(DEFAULT_MAX_EXPANSION_RATIO, 65_536);
}

/// The control-frame hard cap has one value across the codec and registry.
#[test]
fn control_frame_cap_matches_codec_default() {
    assert_eq!(
        usize::try_from(control_proto::DEFAULT_MAX_FRAME_BYTES).unwrap_or(0),
        mysql_wire::limits::MAX_CONTROL_FRAME_LEN
    );
}

/// The physical payload maximum has exactly one definition.
#[test]
fn physical_payload_limit_is_single_sourced() {
    assert_eq!(
        mysql_wire::limits::MAX_PHYSICAL_PAYLOAD_LEN,
        mysql_wire::MAX_PAYLOAD_LEN as usize
    );
}
