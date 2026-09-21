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

//! macOS readers. The workspace forbids unsafe code, so the Mach and `IOKit`
//! calls `gopsutil` makes through cgo are not available; the values Go
//! reads through `sysctl(3)` come from the `sysctl` command, virtual memory
//! from `vm_stat` (the `gopsutil` no-cgo algorithm), mounts from `mount`,
//! interfaces from `ifconfig`, and NIC counters from the same
//! `netstat -ibdnW` invocation Go parses. CPU tick usage, disk I/O rates and
//! the Apple-silicon frequency are not produced (declared).

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    CpuInfo, CpuTimes, DiskCounters, Interface, Memory, NicCounters, Partition, Swap,
    combined_output,
};

fn sysctl_value(name: &str) -> Option<String> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", name])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn sysctl_u64(name: &str) -> Option<u64> {
    sysctl_value(name)?.parse().ok()
}

/// `vm.loadavg` prints `{ 1.23 4.56 7.89 }` with the two decimals Go's
/// `%.2f` of `ldavg/fscale` yields.
pub(super) fn load_avg() -> Option<(f64, f64, f64)> {
    let text = sysctl_value("vm.loadavg")?;
    let mut fields = text
        .trim_matches(|c| c == '{' || c == '}' || c == ' ')
        .split_whitespace();
    Some((
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    ))
}

pub(super) fn cpu_times() -> Option<CpuTimes> {
    None
}

/// gopsutil no-cgo `VirtualMemory`: `hw.memsize` and `vm_stat` free plus
/// inactive pages.
pub(super) fn virtual_memory() -> Option<Memory> {
    let total = sysctl_u64("hw.memsize")?;
    let text = combined_output("vm_stat", &[])?;
    let mut page_size = 0_u64;
    let mut free = 0_u64;
    let mut inactive = 0_u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Mach Virtual Memory Statistics: (page size of ") {
            page_size = rest.split_whitespace().next()?.parse().ok()?;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value: u64 = value.trim().trim_end_matches('.').parse().ok()?;
        match key.trim() {
            "Pages free" => free = value,
            "Pages inactive" => inactive = value,
            _ => {}
        }
    }
    if page_size == 0 {
        return None;
    }
    Some(Memory {
        total,
        available: page_size.wrapping_mul(free.wrapping_add(inactive)),
    })
}

fn swap_field(text: &str, key: &str) -> Option<u64> {
    let rest = text.split_once(&format!("{key} = "))?.1;
    let token = rest.split_whitespace().next()?;
    let (number, unit) = token.split_at(token.len().checked_sub(1)?);
    let scale: f64 = match unit {
        "K" => 1024.0,
        "M" => 1_048_576.0,
        "G" => 1_073_741_824.0,
        _ => return None,
    };
    Some((number.parse::<f64>().ok()? * scale).round() as u64)
}

/// `vm.swapusage` prints the `xsw_usage` totals in MiB.
pub(super) fn swap_memory() -> Option<Swap> {
    let text = sysctl_value("vm.swapusage")?;
    Some(Swap {
        total: swap_field(&text, "total")?,
        used: swap_field(&text, "used")?,
        free: swap_field(&text, "free")?,
    })
}

/// gopsutil `parseNetstatLine`.
fn parse_netstat_line(line: &str) -> Option<(NicCounters, bool)> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    if columns.first() == Some(&"Name") {
        return None;
    }
    let is_link = columns.get(2).is_some_and(|c| {
        c.starts_with("<Link#") && c.ends_with('>') && c[6..c.len() - 1].parse::<u64>().is_ok()
    });
    let base = usize::from(columns.len() >= 12);
    if !(11..=13).contains(&columns.len()) {
        return None;
    }
    let mut values = vec![
        columns[base + 3],
        columns[base + 4],
        columns[base + 5],
        columns[base + 6],
        columns[base + 7],
        columns[base + 8],
    ];
    if columns.len() == 12 {
        values.push(columns[base + 10]);
    }
    let mut parsed = Vec::with_capacity(7);
    for value in values {
        parsed.push(if value == "-" {
            0
        } else {
            value.parse::<u64>().ok()?
        });
    }
    let mut stat = NicCounters {
        name: columns[0].trim_matches('*').to_owned(),
        packets_recv: parsed[0],
        errin: parsed[1],
        bytes_recv: parsed[2],
        packets_sent: parsed[3],
        errout: parsed[4],
        bytes_sent: parsed[5],
        ..NicCounters::default()
    };
    if parsed.len() == 7 {
        stat.dropout = parsed[6];
    }
    Some((stat, is_link))
}

fn parse_netstat_output(output: &str) -> Option<Vec<(NicCounters, bool)>> {
    let lines: Vec<&str> = output.trim_matches('\n').split('\n').collect();
    lines
        .iter()
        .skip(1)
        .map(|line| parse_netstat_line(line))
        .collect()
}

/// gopsutil darwin `net.IOCounters(true)`: `netstat -ibdnW` link rows, with
/// the `ifconfig -l` re-query when names were truncated.
pub(super) fn nic_counters() -> Option<Vec<NicCounters>> {
    let output = combined_output("netstat", &["-ibdnW"])?;
    let rows = parse_netstat_output(&output)?;
    let mut usage: Vec<(String, usize)> = Vec::new();
    for (stat, link) in &rows {
        if *link {
            match usage.iter_mut().find(|(name, _)| *name == stat.name) {
                Some(entry) => entry.1 += 1,
                None => usage.push((stat.name.clone(), 1)),
            }
        }
    }
    let truncated = usage.iter().any(|(_, count)| *count > 1);
    if !truncated {
        return Some(
            rows.into_iter()
                .filter(|(_, link)| *link)
                .map(|(stat, _)| stat)
                .collect(),
        );
    }
    let names = combined_output("ifconfig", &["-l"])?;
    let mut result = Vec::new();
    for name in names.trim_end_matches('\n').split_whitespace() {
        if let Some((stat, _)) = rows.iter().find(|(stat, link)| *link && stat.name == name) {
            result.push(stat.clone());
            continue;
        }
        let output = combined_output("netstat", &[&format!("-ibdnWI{name}")])?;
        let rows = parse_netstat_output(&output)?;
        if let Some((stat, _)) = rows.into_iter().find(|(_, link)| *link) {
            result.push(stat);
        }
    }
    Some(result)
}

pub(super) fn disk_counters() -> Option<Vec<(String, DiskCounters)>> {
    None
}

/// `hw.cpufrequency` (absent on Apple silicon, where Go reads `IOKit`) and
/// `machdep.cpu.cache.size`.
#[allow(clippy::unnecessary_wraps)] // Shared platform reader signature.
pub(super) fn cpu_info() -> Option<CpuInfo> {
    Some(CpuInfo {
        mhz: sysctl_u64("hw.cpufrequency").map_or(0.0, |hz| hz as f64 / 1_000_000.0),
        cache_size: sysctl_u64("machdep.cpu.cache.size").unwrap_or(0) as i32,
    })
}

pub(super) fn physical_cores() -> Option<usize> {
    sysctl_u64("hw.physicalcpu").map(|v| v as usize)
}

/// Go `runtime.NumCPU` on darwin: `hw.ncpu`.
pub(super) fn logical_cores() -> usize {
    sysctl_u64("hw.ncpu").map_or(1, |v| v as usize)
}

/// gopsutil darwin `Partitions`: `getfsstat` flags rendered in Go's option
/// order; the `mount` command lists the same entries in the same order.
pub(super) fn partitions() -> Option<Vec<Partition>> {
    let text = combined_output("mount", &[])?;
    let mut parts = Vec::new();
    for line in text.lines() {
        let (device, rest) = line.split_once(" on ")?;
        let open = rest.rfind(" (")?;
        let mountpoint = &rest[..open];
        let inner = rest[open + 2..].trim_end_matches(')');
        let mut fields = inner.split(", ");
        let fstype = fields.next()?.to_owned();
        let flags: Vec<&str> = fields.collect();
        let has = |flag: &str| flags.contains(&flag);
        let mut opts = vec![if has("read-only") { "ro" } else { "rw" }.to_owned()];
        for (flag, opt) in [
            ("synchronous", "sync"),
            ("noexec", "noexec"),
            ("nosuid", "nosuid"),
            ("union", "union"),
            ("asynchronous", "async"),
            ("nobrowse", "nobrowse"),
            ("automounted", "automounted"),
            ("journaled", "journaled"),
            ("multilabel", "multilabel"),
            ("noatime", "noatime"),
            ("nodev", "nodev"),
        ] {
            if has(flag) {
                opts.push(opt.to_owned());
            }
        }
        parts.push(Partition {
            device: device.to_owned(),
            mountpoint: mountpoint.to_owned(),
            fstype,
            opts,
        });
    }
    Some(parts)
}

fn prefix_len_of_mask(mask: u32) -> String {
    if mask.leading_ones() + mask.trailing_zeros() == 32 {
        mask.leading_ones().to_string()
    } else {
        format!("{mask:08x}")
    }
}

/// Go `net.Interfaces` plus `Addrs` on darwin, from `ifconfig -a` (the
/// same `getifaddrs` order as the routing socket Go reads).
pub(super) fn interfaces() -> Option<Vec<Interface>> {
    let text = combined_output("ifconfig", &["-a"])?;
    let mut result: Vec<Interface> = Vec::new();
    for line in text.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            let (name, rest) = line.split_once(": ")?;
            let flags = rest
                .split_once("flags=")
                .and_then(|(_, f)| f.split_once('<'))
                .and_then(|(_, f)| f.split_once('>'))
                .map(|(f, _)| f.split(',').map(str::to_owned).collect::<Vec<_>>())
                .unwrap_or_default();
            let has = |flag: &str| flags.iter().any(|f| f == flag);
            result.push(Interface {
                name: name.to_owned(),
                up: has("UP"),
                broadcast: has("BROADCAST"),
                loopback: has("LOOPBACK"),
                point_to_point: has("POINTOPOINT"),
                multicast: has("MULTICAST"),
                ..Interface::default()
            });
            continue;
        }
        let Some(current) = result.last_mut() else {
            continue;
        };
        let mut words = line.split_whitespace();
        match words.next() {
            Some("ether" | "lladdr") => {
                current.hardware_addr.clear();
                current
                    .hardware_addr
                    .push_str(words.next().unwrap_or_default());
            }
            Some("inet") => {
                let ip: Ipv4Addr = words.next()?.parse().ok()?;
                let fields: Vec<&str> = words.collect();
                let mask = fields
                    .iter()
                    .position(|w| *w == "netmask")
                    .and_then(|i| fields.get(i + 1))
                    .and_then(|m| u32::from_str_radix(m.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                current
                    .addrs
                    .push(format!("{ip}/{}", prefix_len_of_mask(mask)));
            }
            Some("inet6") => {
                let raw = words.next()?;
                let ip: Ipv6Addr = raw.split('%').next()?.parse().ok()?;
                let fields: Vec<&str> = words.collect();
                let prefix = fields
                    .iter()
                    .position(|w| *w == "prefixlen")
                    .and_then(|i| fields.get(i + 1))
                    .unwrap_or(&"0");
                current.addrs.push(format!("{ip}/{prefix}"));
            }
            _ => {}
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstat_rows_follow_gopsutil() {
        let header = "Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll Drop";
        let link = "en0        1500  <Link#11>   1e:95:88:0a:60:15 55365819     0 41032126176 71183717     0 79281250964     0   0";
        let inet = "en0        1500  192.168.2/24  192.168.2.11     55365819     - 41032126176 71183717     -  79281250964     -   -";
        let rows = parse_netstat_output(&format!("{header}\n{link}\n{inet}\n"))
            .unwrap_or_else(|| unreachable!());
        assert_eq!(rows.len(), 2);
        assert!(rows[0].1 && !rows[1].1);
        assert_eq!(rows[0].0.bytes_recv, 41_032_126_176);
        assert_eq!(rows[0].0.dropout, 0, "the 12-column Drop value is read");
        assert_eq!(rows[0].0.bytes_sent, 79_281_250_964);
        assert_eq!(rows[0].0.packets_recv, 55_365_819);
        assert_eq!(rows[1].0.errin, 0, "dashes read as zero");
        assert!(
            parse_netstat_line("Name Mtu").is_none(),
            "a second header is an error"
        );
    }

    #[test]
    fn swap_fields_scale_units() {
        let text = "total = 3072.00M  used = 2575.75M  free = 496.25M  (encrypted)";
        assert_eq!(swap_field(text, "total"), Some(3_221_225_472));
        // 2575.75 MiB exactly; the kernel value is rounded to the printed
        // two decimals, which is why swap values are shape-compared.
        assert_eq!(swap_field(text, "used"), Some(2_700_869_632));
        assert_eq!(swap_field(text, "free"), Some(520_355_840));
    }

    #[test]
    fn masks_render_like_go_ipnet() {
        assert_eq!(prefix_len_of_mask(0xffff_ff00), "24");
        assert_eq!(prefix_len_of_mask(0xffff_ffff), "32");
        assert_eq!(prefix_len_of_mask(0xff00_ff00), "ff00ff00");
    }
}
