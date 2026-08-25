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

/// Control outbound-queue defaults match the ADR table and stay within the
/// registered hard maxima; control timing defaults match the ADR values.
#[test]
fn control_queue_and_timing_defaults_match_adr() {
    use control_proto::control_transport::{ClientConfig, QueueLimits};
    use mysql_wire::limits::{
        CONTROL_QUEUE_BULK_MAX, CONTROL_QUEUE_CONTROL_MAX, CONTROL_QUEUE_CRITICAL_MAX,
    };

    let queues = QueueLimits::default();
    assert_eq!(
        (queues.critical.messages, queues.critical.bytes),
        (1_024, 8 * 1024 * 1024)
    );
    assert_eq!(
        (queues.control.messages, queues.control.bytes),
        (4_096, 32 * 1024 * 1024)
    );
    assert_eq!(
        (queues.bulk.messages, queues.bulk.bytes),
        (256, 16 * 1024 * 1024)
    );
    for (lane, maxima) in [
        (
            (queues.critical.messages, queues.critical.bytes),
            CONTROL_QUEUE_CRITICAL_MAX,
        ),
        (
            (queues.control.messages, queues.control.bytes),
            CONTROL_QUEUE_CONTROL_MAX,
        ),
        (
            (queues.bulk.messages, queues.bulk.bytes),
            CONTROL_QUEUE_BULK_MAX,
        ),
    ] {
        assert!(
            lane.0 <= maxima.0 && lane.1 <= maxima.1,
            "default exceeds hard maxima"
        );
    }

    let config = ClientConfig::with_defaults(
        std::path::PathBuf::from("/tmp/conformance.sock"),
        0,
        control_proto::v1::Hello::default(),
    );
    assert_eq!(config.handshake_timeout, Duration::from_secs(5));
    assert_eq!(config.heartbeat_interval, Duration::from_secs(1));
    assert_eq!(config.peer_timeout, Duration::from_secs(3));
    assert_eq!(config.write_timeout, Duration::from_secs(5));
    assert_eq!(config.reconnect_base, Duration::from_millis(50));
    assert_eq!(config.reconnect_cap, Duration::from_secs(5));
}

/// The registry queue maxima equal `control-proto`'s enforcement constant in
/// both directions, and the real `ControlClient::new` accepts each lane and
/// dimension at `maximum - 1` and `maximum` while rejecting `maximum + 1`.
/// The reconnect cap is proven the same way at `cap` and `cap + 1 ns`.
#[test]
fn control_hard_maxima_are_bidirectionally_anchored() {
    use control_proto::CONTROL_PROTOCOL_V1;
    use control_proto::control_transport::{
        ClientConfig, ControlClient, HARD_QUEUE_MAXIMA, MAX_RECONNECT_BACKOFF, QueueLimit,
        QueueLimits,
    };
    use control_proto::v1::{Hello, Role};
    use mysql_wire::limits::{
        CONTROL_QUEUE_BULK_MAX, CONTROL_QUEUE_CONTROL_MAX, CONTROL_QUEUE_CRITICAL_MAX,
    };

    type LanePick = fn(&mut QueueLimits) -> &mut QueueLimit;

    let as_tuple = |lane: QueueLimit| (lane.messages, lane.bytes);
    assert_eq!(
        as_tuple(HARD_QUEUE_MAXIMA.critical),
        CONTROL_QUEUE_CRITICAL_MAX
    );
    assert_eq!(
        as_tuple(HARD_QUEUE_MAXIMA.control),
        CONTROL_QUEUE_CONTROL_MAX
    );
    assert_eq!(as_tuple(HARD_QUEUE_MAXIMA.bulk), CONTROL_QUEUE_BULK_MAX);

    let valid_config = || {
        ClientConfig::with_defaults(
            std::path::PathBuf::from("/tmp/conformance.sock"),
            0,
            Hello {
                role: Role::RustDataplane as i32,
                supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
                ..Hello::default()
            },
        )
    };
    assert!(ControlClient::new(valid_config()).is_ok());

    let lanes: [(LanePick, (usize, usize)); 3] = [
        (|limits| &mut limits.critical, CONTROL_QUEUE_CRITICAL_MAX),
        (|limits| &mut limits.control, CONTROL_QUEUE_CONTROL_MAX),
        (|limits| &mut limits.bulk, CONTROL_QUEUE_BULK_MAX),
    ];
    for (pick_lane, (max_messages, max_bytes)) in lanes {
        for (dimension, maximum) in [("messages", max_messages), ("bytes", max_bytes)] {
            for (configured, accepted) in
                [(maximum - 1, true), (maximum, true), (maximum + 1, false)]
            {
                let mut config = valid_config();
                let lane = pick_lane(&mut config.queue_limits);
                if dimension == "messages" {
                    lane.messages = configured;
                } else {
                    lane.bytes = configured;
                }
                assert_eq!(
                    ControlClient::new(config).is_ok(),
                    accepted,
                    "lane {dimension} at {configured} against hard maximum {maximum}"
                );
            }
        }
    }

    let mut config = valid_config();
    config.reconnect_cap = MAX_RECONNECT_BACKOFF;
    assert!(ControlClient::new(config).is_ok(), "reconnect cap at limit");
    let mut config = valid_config();
    config.reconnect_cap = MAX_RECONNECT_BACKOFF + Duration::from_nanos(1);
    assert!(
        ControlClient::new(config).is_err(),
        "reconnect cap one tick past the limit"
    );
}

/// The timing hard rules `ControlClient::new` enforces cannot drift
/// silently: each zero/ordering rule is proven at its reject and
/// minimal-accept boundary through the real constructor. The reconnect
/// cap's 5-second upper bound is proven in the maxima test above.
#[test]
fn control_timing_hard_rules_match_registered_bounds() {
    use control_proto::CONTROL_PROTOCOL_V1;
    use control_proto::control_transport::{ClientConfig, ControlClient};
    use control_proto::v1::{Hello, Role};

    type ApplyTiming = fn(&mut ClientConfig, Duration);

    let valid_config = || {
        ClientConfig::with_defaults(
            std::path::PathBuf::from("/tmp/conformance.sock"),
            0,
            Hello {
                role: Role::RustDataplane as i32,
                supported_versions: vec![u32::from(CONTROL_PROTOCOL_V1)],
                ..Hello::default()
            },
        )
    };

    let tick = Duration::from_nanos(1);
    let cases: [(&str, ApplyTiming, bool); 12] = [
        (
            "handshake zero",
            |c, _| c.handshake_timeout = Duration::ZERO,
            false,
        ),
        ("handshake one tick", |c, t| c.handshake_timeout = t, true),
        (
            "heartbeat zero",
            |c, _| c.heartbeat_interval = Duration::ZERO,
            false,
        ),
        ("heartbeat one tick", |c, t| c.heartbeat_interval = t, true),
        ("write zero", |c, _| c.write_timeout = Duration::ZERO, false),
        ("write one tick", |c, t| c.write_timeout = t, true),
        (
            "peer equal to heartbeat",
            |c, _| c.peer_timeout = c.heartbeat_interval,
            false,
        ),
        (
            "peer one tick above heartbeat",
            |c, t| c.peer_timeout = c.heartbeat_interval + t,
            true,
        ),
        (
            "reconnect base zero",
            |c, _| c.reconnect_base = Duration::ZERO,
            false,
        ),
        ("reconnect base one tick", |c, t| c.reconnect_base = t, true),
        (
            "reconnect cap below base",
            |c, t| c.reconnect_cap = c.reconnect_base - t,
            false,
        ),
        (
            "reconnect cap equal to base",
            |c, _| c.reconnect_cap = c.reconnect_base,
            true,
        ),
    ];
    for (name, mutate, accepted) in cases {
        let mut config = valid_config();
        mutate(&mut config, tick);
        assert_eq!(ControlClient::new(config).is_ok(), accepted, "{name}");
    }
}

/// The physical payload maximum has exactly one definition.
#[test]
fn physical_payload_limit_is_single_sourced() {
    assert_eq!(
        mysql_wire::limits::MAX_PHYSICAL_PAYLOAD_LEN,
        mysql_wire::MAX_PAYLOAD_LEN as usize
    );
}
