// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Executes the shared fixtures against production group primitives.

use control_routing::group::{ClientInfo, GroupMatcher, MatchType, PortRoutes};
use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn values(value: &str) -> Vec<String> {
    if value == "-" {
        Vec::new()
    } else {
        value.split(';').map(str::to_owned).collect()
    }
}
fn address(value: &str) -> Option<&str> {
    (value != "-").then_some(value)
}
fn scalar(value: &str) -> &str {
    if value == "-" { "" } else { value }
}
fn rows(path: &Path, count: usize, mut observe: impl FnMut(&[&str]) -> Result<()>) -> Result<()> {
    for line in fs::read_to_string(path)?.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != count {
            return Err("wrong fixture column count".into());
        }
        observe(&fields)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let directory = env::args().nth(1).ok_or("missing fixture directory")?;
    let directory = Path::new(&directory);
    let mut output = io::BufWriter::new(io::stdout().lock());
    rows(&directory.join("match.tsv"), 6, |row| {
        let rule = match row[1] {
            "all" => MatchType::All,
            "client" => MatchType::ClientCidr,
            "proxy" => MatchType::ProxyCidr,
            "port" => MatchType::Port,
            _ => return Err("unknown rule".into()),
        };
        match GroupMatcher::new(rule, values(row[2])) {
            Err(_) => writeln!(output, "{}\tinvalid", row[0])?,
            Ok(group) => {
                let client = ClientInfo {
                    client_address: address(row[4]),
                    proxy_address: address(row[5]),
                };
                writeln!(
                    output,
                    "{}\tvalid\t{}\t{}\t{}",
                    row[0],
                    group.matches(client),
                    group.equal_values(&values(row[3])),
                    group.intersects(&values(row[3]))
                )?;
            }
        }
        Ok(())
    })?;
    let mut ports = PortRoutes::<String>::default();
    rows(&directory.join("port.tsv"), 5, |row| {
        let port = scalar(row[2]);
        match row[1] {
            "reset" => ports = PortRoutes::default(),
            "bind" => ports.bind(port, scalar(row[3]), row[4].to_owned()),
            "get" => {}
            _ => return Err("unknown port action".into()),
        }
        match ports.group_for(port) {
            Err(_) => writeln!(output, "{}\tconflict", row[0])?,
            Ok(None) => writeln!(output, "{}\tabsent", row[0])?,
            Ok(Some(group)) => writeln!(output, "{}\tgroup\t{group}", row[0])?,
        }
        Ok(())
    })?;
    output.flush()?;
    Ok(())
}
