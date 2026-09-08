// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test harness for the exact consumer task used inside tiproxy-rs.
use control_router::shadow::Status;
use legacy_router_shadow::consumer::Task;
use std::{io, path::PathBuf, time::Duration};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args().nth(1).ok_or("socket path required")?);
    let task = Task::spawn(path);
    let diagnostics = task.diagnostics();
    // The parent supplies the completed business-operation total through the
    // test process's stdin. Nothing travels back through the observation UDS.
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let expected: u64 = line.trim().parse()?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let report = diagnostics.snapshot();
            if report
                .owners
                .values()
                .any(|p| matches!(p.status, Status::Invalid(_)))
            {
                return Err("invalid owner");
            }
            if report.operations >= expected && report.score == 0 && report.physical == 0 {
                return Ok(report);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let last_report = diagnostics.snapshot();
    task.shutdown().await;
    let report = result.map_err(|error| format!("{error}: {last_report:?}"))??;
    if report.operations != expected
        || report.owners.len() != 2
        || report.transport_errors != 0
        || report.connections != 1
    {
        return Err(format!("unexpected live report: {report:?}").into());
    }
    println!(
        "lifecycle_only=true owners={} operations={} batches={} events={} score={} physical={} invalid=0 mismatch=0 connections={} transport_errors={}",
        report.owners.len(),
        report.operations,
        report.batches,
        report.events,
        report.score,
        report.physical,
        report.connections,
        report.transport_errors
    );
    Ok(())
}
