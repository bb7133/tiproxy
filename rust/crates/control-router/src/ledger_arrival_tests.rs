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

use super::*;
use std::fmt::Write;

fn must<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
    r.unwrap_or_else(|e| unreachable!("arrival fixture: {e:?}"))
}
fn assignment(id: &str) -> RouteAssignment {
    RouteAssignment {
        backend_id: id.into(),
        keyspace: "tenant".into(),
        ..RouteAssignment::default()
    }
}

#[test]
fn shared_go_physical_arrival_order() {
    let Ok(path) = std::env::var("CPROUTE_ARRIVAL_FIXTURE") else {
        return;
    };
    let fixture = must(std::fs::read_to_string(path));
    let mut ledger = Ledger::new(8);
    let a = must(ledger.add_account());
    let b = must(ledger.add_account());
    let mut sessions = BTreeMap::new();
    let mut redirects = BTreeMap::new();
    let start = Instant::now();
    let mut output = String::new();
    for line in fixture.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let id: u64 = must(fields[2].parse());
        let owner = if fields[3] == "a" { &a } else { &b };
        let now = start + Duration::from_millis(must(fields[4].parse()));
        match fields[1] {
            "reset" => (),
            "open" => {
                let s = must(ledger.open());
                assert_eq!(s.sequence, id);
                sessions.insert(id, s);
            }
            "connect" => {
                let r = must(ledger.reserve(&sessions[&id], owner, assignment(fields[3])));
                assert_eq!(ledger.finish(&r, true), Settlement::Applied);
            }
            "admit" | "reject" => {
                let op = must(ledger.prepare_redirect(
                    &sessions[&id],
                    owner,
                    assignment(fields[3]),
                    now,
                ));
                ledger.admit_redirect(op.clone(), fields[1] == "admit", now);
                if fields[1] == "admit" {
                    redirects.insert(id, op);
                }
            }
            "success" | "failure" | "late_success" => {
                let expected = if fields[1] == "late_success" {
                    Settlement::Ignored
                } else {
                    Settlement::Applied
                };
                assert_eq!(
                    ledger.finish_redirect(&redirects[&id], fields[1] != "failure", now),
                    expected
                );
            }
            "close" => {
                assert_eq!(ledger.close(&sessions[&id]), Settlement::Applied);
            }
            _ => unreachable!("arrival action"),
        }
        let order = |owner| {
            ledger
                .physical_sessions(owner)
                .iter()
                .map(|s| s.sequence.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let a_counts = must(ledger.counts(&a).ok_or("a"));
        let b_counts = must(ledger.counts(&b).ok_or("b"));
        must(writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            fields[0],
            order(&a),
            order(&b),
            a_counts.connection_score(),
            b_counts.connection_score()
        ));
        // Counts and membership must agree after every event, including pending.
        assert_eq!(ledger.physical_sessions(&a).len() as u64, a_counts.active());
        assert_eq!(ledger.physical_sessions(&b).len() as u64, b_counts.active());
    }
    let expected = must(std::fs::read_to_string(must(std::env::var(
        "CPROUTE_ARRIVAL_EXPECTED",
    ))));
    assert_eq!(output, expected, "PHYSICAL_ARRIVAL_ORDER");
    if let Ok(path) = std::env::var("CPROUTE_ARRIVAL_OUTPUT") {
        must(std::fs::write(path, output));
    }
}
