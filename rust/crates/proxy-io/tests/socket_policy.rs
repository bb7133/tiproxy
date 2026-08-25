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

//! WIRE-06 acceptance: listeners, cancellable dial/backoff, keepalive
//! switching, and the live-socket PROXY integration that closes the WIRE-05
//! adapter acceptance (disabled/fallback zero-consumption on a real TCP
//! stream).

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use proxy_io::PumpCancellation;
use proxy_io::proxy_protocol::{
    EncodeAddresses, ProxyCommand, ProxyVersion, TransportProtocol, encode_proxy_v2,
};
use proxy_io::socket::{
    DialPolicy, KeepalivePolicy, SocketError, apply_keepalive, bind_listeners, configure_stream,
    dial_with_backoff, read_keepalive, read_proxy_header_if_present,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

const PROXY_DEADLINE: Duration = Duration::from_secs(5);

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Multi-address bind reports real ephemeral ports, accepts work, and drop
/// releases the port for reuse (closing a listener releases accept).
#[tokio::test]
async fn listeners_report_actual_ports_and_release_on_drop() -> Result<(), Box<dyn Error>> {
    let bound = bind_listeners(&[loopback(0), loopback(0)]).await?;
    assert_eq!(bound.len(), 2);
    assert!(bound.iter().all(|b| b.actual_address.port() != 0));
    assert_ne!(
        bound[0].actual_address.port(),
        bound[1].actual_address.port()
    );

    let target = bound[0].actual_address;
    let client = TcpStream::connect(target).await?;
    let (accepted, _) = bound[0].listener.accept().await?;
    configure_stream(&accepted)?;
    assert!(accepted.nodelay()?);
    drop(client);
    drop(accepted);

    let port = target.port();
    drop(bound);
    // The released port is immediately rebindable.
    let rebound = bind_listeners(&[loopback(port)]).await?;
    assert_eq!(rebound[0].actual_address.port(), port);
    Ok(())
}

/// A dial inside budget succeeds; the returned stream is usable.
#[tokio::test]
async fn dial_succeeds_within_budget() -> Result<(), Box<dyn Error>> {
    let bound = bind_listeners(&[loopback(0)]).await?;
    let target = format!("127.0.0.1:{}", bound[0].actual_address.port());
    let cancel = PumpCancellation::new();
    let started = Instant::now();
    let stream = dial_with_backoff(&target, DialPolicy::default(), &cancel).await?;
    assert!(started.elapsed() < Duration::from_secs(1));
    configure_stream(&stream)?;
    Ok(())
}

/// Cancellation stops the dial immediately, including during backoff sleep.
#[tokio::test]
async fn cancellation_stops_dial_and_backoff_immediately() -> Result<(), Box<dyn Error>> {
    // A port that refuses instantly, forcing the dial into backoff sleeps.
    let refused = {
        let probe = bind_listeners(&[loopback(0)]).await?;
        let port = probe[0].actual_address.port();
        drop(probe);
        port
    };
    let target = format!("127.0.0.1:{refused}");
    let cancel = PumpCancellation::new();
    let policy = DialPolicy {
        attempt_timeout: Duration::from_millis(200),
        total_timeout: Duration::from_secs(30),
        backoff_initial: Duration::from_secs(2),
        randomization: 0.0,
        ..DialPolicy::default()
    };
    let canceller = cancel.clone();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        canceller.cancel();
    });
    let started = Instant::now();
    let result = dial_with_backoff(&target, policy, &cancel).await;
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(SocketError::Cancelled { .. })));
    assert!(
        elapsed < Duration::from_secs(1),
        "cancel took {elapsed:?}, expected immediate stop during a 2s backoff"
    );
    handle.await?;
    Ok(())
}

/// The total budget bounds a dial to an unresponsive target.
#[tokio::test]
async fn dial_budget_is_enforced() -> Result<(), Box<dyn Error>> {
    let refused = {
        let probe = bind_listeners(&[loopback(0)]).await?;
        let port = probe[0].actual_address.port();
        drop(probe);
        port
    };
    let target = format!("127.0.0.1:{refused}");
    let cancel = PumpCancellation::new();
    let policy = DialPolicy {
        attempt_timeout: Duration::from_millis(100),
        total_timeout: Duration::from_millis(400),
        backoff_initial: Duration::from_millis(50),
        randomization: 0.0,
        ..DialPolicy::default()
    };
    let started = Instant::now();
    let result = dial_with_backoff(&target, policy, &cancel).await;
    let elapsed = started.elapsed();
    assert!(result.is_err());
    assert!(
        elapsed < Duration::from_secs(2),
        "budget overrun: {elapsed:?}"
    );
    Ok(())
}

/// Healthy → unhealthy keepalive switching is observable via readback where
/// the platform exposes it; enablement is observable everywhere on Unix.
#[tokio::test]
#[cfg(unix)]
async fn keepalive_switch_is_observable() -> Result<(), Box<dyn Error>> {
    let bound = bind_listeners(&[loopback(0)]).await?;
    let client = TcpStream::connect(bound[0].actual_address).await?;
    let (server, _) = bound[0].listener.accept().await?;

    apply_keepalive(&server, KeepalivePolicy::backend_healthy_default())?;
    let healthy = read_keepalive(&server)?;
    assert!(healthy.enabled);

    apply_keepalive(&server, KeepalivePolicy::backend_unhealthy_default())?;
    let unhealthy = read_keepalive(&server)?;
    assert!(unhealthy.enabled);
    if let (Some(healthy_idle), Some(unhealthy_idle)) = (healthy.idle, unhealthy.idle) {
        assert_eq!(healthy_idle, Duration::from_secs(60));
        assert_eq!(unhealthy_idle, Duration::from_secs(10));
        assert_ne!(healthy_idle, unhealthy_idle, "switch must be observable");
    }

    // Disabled probing still applies cleanly (Go still sets the user timeout).
    apply_keepalive(
        &server,
        KeepalivePolicy {
            enabled: false,
            ..KeepalivePolicy::backend_healthy_default()
        },
    )?;
    let disabled = read_keepalive(&server)?;
    assert!(!disabled.enabled);
    drop(client);
    Ok(())
}

/// WIRE-05 adapter acceptance on a live socket: disabled mode performs zero
/// reads, and fallback mode consumes nothing for a non-PROXY client — the
/// full `MySQL` byte stream arrives untouched.
#[tokio::test]
async fn proxy_disabled_and_fallback_consume_nothing_on_live_socket() -> Result<(), Box<dyn Error>>
{
    // Disabled: not even a peek — client sends nothing and the call returns.
    let bound = bind_listeners(&[loopback(0)]).await?;
    let _client = TcpStream::connect(bound[0].actual_address).await?;
    let (mut server, _) = bound[0].listener.accept().await?;
    let header = read_proxy_header_if_present(&mut server, false, PROXY_DEADLINE).await?;
    assert!(header.is_none());

    // Enabled + plain client: peeked only, every byte still readable.
    let bound = bind_listeners(&[loopback(0)]).await?;
    let mut client = TcpStream::connect(bound[0].actual_address).await?;
    let (mut server, _) = bound[0].listener.accept().await?;
    client.write_all(b"plain mysql bytes").await?;
    client.flush().await?;
    let header = read_proxy_header_if_present(&mut server, true, PROXY_DEADLINE).await?;
    assert!(header.is_none());
    let mut received = vec![0_u8; 17];
    server.read_exact(&mut received).await?;
    assert_eq!(&received, b"plain mysql bytes");
    Ok(())
}

/// Enabled + PROXY client on a live socket: exactly the header is consumed
/// and the `MySQL` stream starts at the first payload byte.
#[tokio::test]
async fn proxy_header_is_consumed_exactly_on_live_socket() -> Result<(), Box<dyn Error>> {
    let bound = bind_listeners(&[loopback(0)]).await?;
    let mut client = TcpStream::connect(bound[0].actual_address).await?;
    let (mut server, _) = bound[0].listener.accept().await?;

    let source = (std::net::IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 4567_u16);
    let destination = (std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7)), 4000_u16);
    let mut wire = encode_proxy_v2(
        ProxyVersion::V2,
        ProxyCommand::PROXY,
        TransportProtocol::STREAM,
        EncodeAddresses::Ip {
            src: source,
            dst: destination,
        },
        &[(0x05, b"conn-id")],
    )?;
    wire.extend_from_slice(b"mysql-first-byte");
    client.write_all(&wire).await?;
    client.flush().await?;

    let header = read_proxy_header_if_present(&mut server, true, PROXY_DEADLINE)
        .await?
        .ok_or("expected a PROXY header")?;
    assert_eq!(header.command, ProxyCommand::PROXY);
    assert_eq!(
        header.source,
        Some(SocketAddr::from((Ipv4Addr::new(10, 1, 2, 3), 4567)))
    );
    assert_eq!(
        header.destination,
        Some(SocketAddr::from((Ipv4Addr::new(10, 9, 8, 7), 4000)))
    );
    assert_eq!(header.tlvs, vec![(0x05_u8, b"conn-id".to_vec())]);

    let mut rest = vec![0_u8; 16];
    server.read_exact(&mut rest).await?;
    assert_eq!(&rest, b"mysql-first-byte");
    Ok(())
}
