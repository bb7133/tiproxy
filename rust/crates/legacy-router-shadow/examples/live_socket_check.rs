// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test harness for the exact consumer task used inside tiproxy-rs.
use control_router::shadow::{Epoch, Status};
use legacy_router_shadow::consumer::Task;
use std::{io, path::PathBuf, time::Duration};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args().nth(1).ok_or("socket path required")?);
    let native = std::env::args().nth(2).as_deref() == Some("native");
    let task = Task::spawn(path);
    let diagnostics = task.diagnostics();
    if native {
        tokio::time::timeout(Duration::from_secs(10), async {
            while diagnostics.snapshot().connections == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        // Test-process startup coordination; the observation UDS remains one-way.
        println!("native_consumer_connected");
    }
    // The parent supplies the completed business-operation total through the
    // test process's stdin. Nothing travels back through the observation UDS.
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let target = parse_target(&line)?;
    let expected = target.operations;
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
            let compared_tail = target.boundaries.iter().all(|(epoch, sequence)| {
                report.owners.get(epoch).is_some_and(|p| {
                    p.status == Status::Comparing && p.compared_sequence >= *sequence
                })
            });
            if compared_tail
                && report.operations >= expected
                && report.score == 0
                && report.physical == 0
            {
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
        || native
            && (report.native_owners.len() != 2
                || report.evaluations < expected / 5
                || expected == 12000 && report.native_configurations != 244
                || report.native_retained_bytes == 0
                || report.native_peak_bytes > 64 * 1024 * 1024)
    {
        return Err(format!("unexpected live report: {report:?}").into());
    }
    println!(
        "lifecycle_only={} owners={} operations={} batches={} events={} score={} physical={} invalid=0 mismatch=0 connections={} transport_errors={} compared_tail=true factors={} selection=false scheduler=false evaluations={} native_configurations={} native_retained_bytes={} native_peak_bytes={}",
        !native,
        report.owners.len(),
        report.operations,
        report.batches,
        report.events,
        report.score,
        report.physical,
        report.connections,
        report.transport_errors,
        native,
        report.evaluations,
        report.native_configurations,
        report.native_retained_bytes,
        report.native_peak_bytes
    );
    Ok(())
}

struct Target {
    operations: u64,
    boundaries: Vec<(Epoch, u64)>,
}
fn parse_target(line: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let mut fields = line.split_whitespace();
    let operations = fields.next().ok_or("operations required")?.parse()?;
    let mut boundaries = Vec::new();
    for field in fields {
        let numbers = field
            .split(':')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        let [process, owner, nonce, sequence] = numbers.as_slice() else {
            return Err("complete epoch and sequence required".into());
        };
        let epoch = Epoch {
            process: *process,
            owner: *owner,
            nonce: *nonce,
        };
        if [*process, *owner, *nonce, *sequence].contains(&0)
            || boundaries.iter().any(|(known, _)| *known == epoch)
        {
            return Err("nonzero distinct owner boundaries required".into());
        }
        boundaries.push((epoch, *sequence));
    }
    if boundaries.len() != 2 {
        return Err("two owner boundaries required".into());
    }
    Ok(Target {
        operations,
        boundaries,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_requires_complete_distinct_owner_boundaries() {
        for invalid in [
            "10",
            "10 41:1:43:9",
            "10 41:1:43:9 41:1:43:9",
            "10 41:1:43:0 41:2:43:9",
        ] {
            assert!(parse_target(invalid).is_err());
        }
        let target = parse_target("10 41:1:43:9 41:2:43:12")
            .unwrap_or_else(|error| unreachable!("target: {error}"));
        assert_eq!(target.operations, 10);
        assert_eq!(target.boundaries[1].1, 12);
    }
}
