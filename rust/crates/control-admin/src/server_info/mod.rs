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

//! `Diagnostics.ServerInfo`: the Go `sysutil` item inventory (load,
//! hardware, system) with the exact item types, names, pair keys and value
//! formats. The host readers live in a platform module: Linux reads the same
//! `procfs`/`sysfs` files and netlink dumps that `gopsutil` reads; macOS uses
//! the commands `gopsutil` itself shells out to plus `sysctl`, `vm_stat`,
//! `mount` and `ifconfig` for what Go reads through Mach and `IOKit` (declared
//! in the design document); other platforms answer only the command-based
//! `system` items.

// The Go collectors convert between integer widths and floats freely; the
// casts below mirror them.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use control_external::diagnostics::{ServerInfoItem, ServerInfoPair, ServerInfoType};

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[path = "other.rs"]
mod platform;

/// Go `cpu.TimesStat` (seconds).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct CpuTimes {
    pub user: f64,
    pub system: f64,
    pub idle: f64,
    pub nice: f64,
    pub iowait: f64,
    pub irq: f64,
    pub softirq: f64,
    pub steal: f64,
    pub guest: f64,
    pub guest_nice: f64,
}

impl CpuTimes {
    /// Go `TimesStat.Total`.
    fn total(&self) -> f64 {
        self.user
            + self.system
            + self.idle
            + self.nice
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
            + self.guest
            + self.guest_nice
    }
}

/// Go `mem.VirtualMemoryStat` (the fields `sysutil` uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Memory {
    pub total: u64,
    pub available: u64,
}

/// Go `mem.SwapMemoryStat` (the fields `sysutil` uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Swap {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

/// Go `net.IOCountersStat`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NicCounters {
    pub name: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub errin: u64,
    pub errout: u64,
    pub dropin: u64,
    pub dropout: u64,
    pub fifoin: u64,
    pub fifoout: u64,
}

/// Go `disk.IOCountersStat` (the fields `sysutil` uses).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DiskCounters {
    pub read_count: u64,
    pub merged_read_count: u64,
    pub write_count: u64,
    pub merged_write_count: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// Go `cpu.InfoStat` (the fields `sysutil` uses from the first entry).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct CpuInfo {
    pub mhz: f64,
    pub cache_size: i32,
}

/// Go `disk.PartitionStat`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Partition {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub opts: Vec<String>,
}

/// Go `disk.UsageStat` (the fields `sysutil` uses).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Usage {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    pub used_percent: f64,
}

/// Go `net.InterfaceStat`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Go's five interface flags.
pub(crate) struct Interface {
    pub name: String,
    pub hardware_addr: String,
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
    pub addrs: Vec<String>,
}

/// Go `fmt.Sprintf("%.2f", v)`.
pub(crate) fn go_f2(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value.is_infinite() {
        if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        format!("{value:.2}")
    }
}

fn pair(key: &str, value: String) -> ServerInfoPair {
    ServerInfoPair {
        key: key.to_owned(),
        value,
    }
}

fn item(tp: &str, name: &str, pairs: Vec<ServerInfoPair>) -> ServerInfoItem {
    ServerInfoItem {
        tp: tp.to_owned(),
        name: name.to_owned(),
        pairs,
    }
}

/// Go `runtime.GOARCH` for this build.
pub(crate) fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "arm" => "arm",
        "powerpc64" => {
            if cfg!(target_endian = "little") {
                "ppc64le"
            } else {
                "ppc64"
            }
        }
        "mips64" => {
            if cfg!(target_endian = "little") {
                "mips64le"
            } else {
                "mips64"
            }
        }
        "mips" => {
            if cfg!(target_endian = "little") {
                "mipsle"
            } else {
                "mips"
            }
        }
        "loongarch64" => "loong64",
        other => other,
    }
}

/// Collects the answer for one `ServerInfoRequest.tp`, sorted by type and
/// name as `sysutil` sorts (unknown types answer nothing). Blocking: the
/// load collectors sleep 1s (CPU) and 0.5s (disk) like Go.
#[must_use]
pub fn collect(tp: i32) -> Vec<ServerInfoItem> {
    let mut items = match ServerInfoType::try_from(tp) {
        Ok(ServerInfoType::LoadInfo) => load_info(),
        Ok(ServerInfoType::HardwareInfo) => hardware_info(),
        Ok(ServerInfoType::SystemInfo) => system_info(),
        Ok(ServerInfoType::All) => {
            let mut all = load_info();
            all.extend(hardware_info());
            all.extend(system_info());
            all
        }
        Err(_) => Vec::new(),
    };
    // Go's sort.Slice is unstable; items sharing type and name (e.g. the
    // load and hardware `cpu/cpu` under All) keep collection order here.
    items.sort_by(|a, b| (&a.tp, &a.name).cmp(&(&b.tp, &b.name)));
    items
}

// ---------------------------------------------------------------------------
// Load

/// Go `getCpuLoad`.
fn cpu_load() -> Vec<ServerInfoItem> {
    let mut results = Vec::new();
    if let Some((load1, load5, load15)) = platform::load_avg() {
        results.push(item(
            "cpu",
            "cpu",
            vec![
                pair("load1", go_f2(load1)),
                pair("load5", go_f2(load5)),
                pair("load15", go_f2(load15)),
            ],
        ));
    }
    let Some(t1) = platform::cpu_times() else {
        return results;
    };
    sleep(Duration::from_secs(1));
    let Some(t2) = platform::cpu_times() else {
        return results;
    };
    let total = t2.total() - t1.total();
    let ratio = |a: f64, b: f64| go_f2((a - b) / total);
    results.push(item(
        "cpu",
        "usage",
        vec![
            pair("user", ratio(t2.user, t1.user)),
            pair("system", ratio(t2.system, t1.system)),
            pair("idle", ratio(t2.idle, t1.idle)),
            pair("nice", ratio(t2.nice, t1.nice)),
            pair("iowait", ratio(t2.iowait, t1.iowait)),
            pair("irq", ratio(t2.irq, t1.irq)),
            pair("softirq", ratio(t2.softirq, t1.softirq)),
            pair("steal", ratio(t2.steal, t1.steal)),
            pair("guest", ratio(t2.guest, t1.guest)),
            pair("guest_nice", ratio(t2.guest_nice, t1.guest_nice)),
        ],
    ));
    results
}

/// Go `getMemLoad`.
fn mem_load() -> Vec<ServerInfoItem> {
    let mut results = Vec::new();
    if let Some(virt) = platform::virtual_memory() {
        let used = virt.total.wrapping_sub(virt.available);
        let used_percent = used as f64 / virt.total as f64;
        results.push(item(
            "memory",
            "virtual",
            vec![
                pair("total", virt.total.to_string()),
                pair("used", used.to_string()),
                pair("free", virt.available.to_string()),
                pair("used-percent", go_f2(used_percent)),
                pair("free-percent", go_f2(1.0 - used_percent)),
            ],
        ));
    }
    if let Some(swap) = platform::swap_memory() {
        results.push(item(
            "memory",
            "swap",
            vec![
                pair("total", swap.total.to_string()),
                pair("used", swap.used.to_string()),
                pair("free", swap.free.to_string()),
                pair("used-percent", go_f2(swap.used as f64 / swap.total as f64)),
                pair("free-percent", go_f2(swap.free as f64 / swap.total as f64)),
            ],
        ));
    }
    results
}

/// Go `getNICLoad` (note Go's `bytes-ent` key).
fn nic_load() -> Vec<ServerInfoItem> {
    let Some(counters) = platform::nic_counters() else {
        return Vec::new();
    };
    counters
        .iter()
        .map(|ic| {
            item(
                "net",
                &ic.name,
                vec![
                    pair("bytes-ent", ic.bytes_sent.to_string()),
                    pair("bytes-recv", ic.bytes_recv.to_string()),
                    pair("packets-sent", ic.packets_sent.to_string()),
                    pair("packets-recv", ic.packets_recv.to_string()),
                    pair("errin", ic.errin.to_string()),
                    pair("errout", ic.errout.to_string()),
                    pair("dropin", ic.dropin.to_string()),
                    pair("dropout", ic.dropout.to_string()),
                    pair("fifoin", ic.fifoin.to_string()),
                    pair("fifoout", ic.fifoout.to_string()),
                ],
            )
        })
        .collect()
}

/// Go `getDiskLoad`: two snapshots 500ms apart, rates per second, filed
/// under type `net` as `sysutil` does.
fn disk_load() -> Vec<ServerInfoItem> {
    let Some(snapshot) = platform::disk_counters() else {
        return Vec::new();
    };
    sleep(Duration::from_millis(500));
    let Some(current) = platform::disk_counters() else {
        return Vec::new();
    };
    let rate = |p: u64, c: u64| go_f2(c.wrapping_sub(p) as f64 / 0.5);
    current
        .iter()
        .filter_map(|(name, c)| {
            let (_, p) = snapshot.iter().find(|(previous, _)| previous == name)?;
            Some(item(
                "net",
                name,
                vec![
                    pair("read_count/s", rate(p.read_count, c.read_count)),
                    pair(
                        "merged_read_count/s",
                        rate(p.merged_read_count, c.merged_read_count),
                    ),
                    pair("write_count/s", rate(p.write_count, c.write_count)),
                    pair(
                        "merged_write_count/s",
                        rate(p.merged_write_count, c.merged_write_count),
                    ),
                    pair("read_bytes/s", rate(p.read_bytes, c.read_bytes)),
                    pair("write_bytes/s", rate(p.write_bytes, c.write_bytes)),
                ],
            ))
        })
        .collect()
}

/// Go `getLoadInfo`.
fn load_info() -> Vec<ServerInfoItem> {
    let mut results = cpu_load();
    results.extend(mem_load());
    results.extend(nic_load());
    results.extend(disk_load());
    results
}

/// gopsutil `disk.Usage`: `statfs(2)` on the mount point; `used` excludes
/// the reserved blocks and the percentage is `used / (used + free)`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::cast_lossless)] // `f_bsize` is i64 on Linux and u32 on macOS.
fn usage(mountpoint: &str) -> Option<Usage> {
    let stat = rustix::fs::statfs(mountpoint).ok()?;
    let bsize = stat.f_bsize as u64;
    let total = (stat.f_blocks as u64).wrapping_mul(bsize);
    let free = (stat.f_bavail as u64).wrapping_mul(bsize);
    let used = (stat.f_blocks as u64)
        .wrapping_sub(stat.f_bfree as u64)
        .wrapping_mul(bsize);
    let used_percent = if used.wrapping_add(free) == 0 {
        0.0
    } else {
        used as f64 / (used.wrapping_add(free)) as f64 * 100.0
    };
    Some(Usage {
        total,
        free,
        used,
        used_percent,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn usage(_mountpoint: &str) -> Option<Usage> {
    None
}

// ---------------------------------------------------------------------------
// Hardware

/// Go `getHardwareInfo`.
fn hardware_info() -> Vec<ServerInfoItem> {
    let mut results = Vec::new();
    if let Some(info) = platform::cpu_info() {
        let physical = platform::physical_cores().unwrap_or(1);
        results.push(item(
            "cpu",
            "cpu",
            vec![
                pair("cpu-arch", go_arch().to_owned()),
                pair("cpu-logical-cores", platform::logical_cores().to_string()),
                pair("cpu-physical-cores", physical.to_string()),
                pair("cpu-frequency", format!("{}MHz", go_f2(info.mhz))),
                pair("cache", info.cache_size.to_string()),
            ],
        ));
    }
    if let Some(memory) = platform::virtual_memory() {
        results.push(item(
            "memory",
            "memory",
            vec![pair("capacity", memory.total.to_string())],
        ));
    }
    if let Some(parts) = platform::partitions() {
        for p in &parts {
            let Some(name) = p.device.strip_prefix("/dev/") else {
                continue;
            };
            let Some(usage) = usage(&p.mountpoint) else {
                continue;
            };
            results.push(item(
                "disk",
                name,
                vec![
                    pair("fstype", p.fstype.clone()),
                    pair("opts", p.opts.join(",")),
                    pair("path", p.mountpoint.clone()),
                    pair("total", usage.total.to_string()),
                    pair("free", usage.free.to_string()),
                    pair("used", usage.used.to_string()),
                    pair("free-percent", go_f2((100.0 - usage.used_percent) / 100.0)),
                    pair("used-percent", go_f2(usage.used_percent / 100.0)),
                ],
            ));
        }
    }
    if let Some(nics) = platform::interfaces() {
        for nic in &nics {
            let flag = |on: bool| if on { "true" } else { "false" }.to_owned();
            results.push(item(
                "net",
                &nic.name,
                vec![
                    pair("mac", nic.hardware_addr.clone()),
                    pair("is-up", flag(nic.up)),
                    pair("is-broadcast", flag(nic.broadcast)),
                    pair("is-multicast", flag(nic.multicast)),
                    pair("is-loopback", flag(nic.loopback)),
                    pair("is-point-to-point", flag(nic.point_to_point)),
                    pair("addresses", nic.addrs.join(",")),
                ],
            ));
        }
    }
    results
}

// ---------------------------------------------------------------------------
// System

/// Go `tryProcFs`: `filepath.Walk("/proc/sys/")` in lexical order, every
/// readable file as `a.b.c = trimmed content`; any directory or `lstat`
/// failure aborts the walk (Go returns the error to `Walk`), which selects
/// the `sysctl -a` fallback.
fn procfs_sysctl() -> Option<Vec<ServerInfoPair>> {
    const DIR: &str = "/proc/sys/";
    let mut pairs = Vec::new();
    let root = Path::new(DIR);
    let metadata = std::fs::symlink_metadata(root).ok()?;
    if !metadata.is_dir() {
        // Go: ReadFile fails on a non-directory root, ignored.
        return Some(pairs);
    }
    walk_dir(root, DIR, &mut pairs).ok()?;
    Some(pairs)
}

fn walk_dir(dir: &Path, prefix: &str, pairs: &mut Vec<ServerInfoPair>) -> std::io::Result<()> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()?;
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            walk_dir(&path, prefix, pairs)?;
            continue;
        }
        // Go ioutil.ReadFile: unreadable entries are ignored.
        let Ok(content) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&content);
        let key = path
            .to_string_lossy()
            .strip_prefix(prefix)
            .unwrap_or_default()
            .replace('/', ".");
        pairs.push(pair(&key, text.trim().to_owned()));
    }
    Ok(())
}

/// Go `exec.Command("sysctl", "-a").CombinedOutput()`, split on the first
/// `:` of each line (only the second segment is kept, like Go's
/// `strings.Split(line, ":")[1]`).
fn sysctl_command_pairs() -> Option<Vec<ServerInfoPair>> {
    let output = combined_output("sysctl", &["-a"])?;
    let mut pairs = Vec::with_capacity(2048);
    for line in output.split_inclusive('\n') {
        let line = line.trim_end_matches('\n');
        let mut segments = line.split(':');
        let (Some(key), Some(value)) = (segments.next(), segments.next()) else {
            continue;
        };
        pairs.push(pair(key, value.trim().to_owned()));
    }
    Some(pairs)
}

/// Go `CombinedOutput`: stdout and stderr through one pipe, in arrival
/// order; a spawn failure or non-zero exit is an error (`None`).
pub(crate) fn combined_output(program: &str, args: &[&str]) -> Option<String> {
    let (read_end, write_end) = rustix::pipe::pipe().ok()?;
    let write_for_stderr = write_end.try_clone().ok()?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(write_end))
        .stderr(Stdio::from(write_for_stderr))
        .spawn()
        .ok()?;
    let mut output = Vec::new();
    let mut reader = std::fs::File::from(read_end);
    let read = reader.read_to_end(&mut output);
    let status = child.wait().ok()?;
    read.ok()?;
    if !status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output).into_owned())
}

/// Go `getTransparentHugepageEnabled`.
fn transparent_hugepage() -> Vec<ServerInfoItem> {
    match std::fs::read("/sys/kernel/mm/transparent_hugepage/enabled") {
        Ok(content) => vec![item(
            "system",
            "kernel",
            vec![pair(
                "transparent_hugepage_enabled",
                String::from_utf8_lossy(&content).trim().to_owned(),
            )],
        )],
        Err(_) => Vec::new(),
    }
}

/// Go `getSystemInfo`.
fn system_info() -> Vec<ServerInfoItem> {
    let huge_page = transparent_hugepage();
    if let Some(pairs) = procfs_sysctl() {
        let mut results = vec![item("system", "sysctl", pairs)];
        results.extend(huge_page);
        return results;
    }
    let Some(pairs) = sysctl_command_pairs() else {
        return Vec::new();
    };
    let mut results = vec![item("system", "sysctl", pairs)];
    results.extend(huge_page);
    results
}

/// Distinct `(tp, name)` pairs, for tests and diagnostics.
#[cfg(test)]
pub(crate) fn inventory(items: &[ServerInfoItem]) -> std::collections::BTreeSet<(String, String)> {
    items
        .iter()
        .map(|item| (item.tp.clone(), item.name.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_float_formatting() {
        assert_eq!(go_f2(0.125), "0.12");
        assert_eq!(go_f2(2.675), "2.67");
        assert_eq!(go_f2(4000.0), "4000.00");
        assert_eq!(go_f2(f64::NAN), "NaN");
        assert_eq!(go_f2(f64::INFINITY), "+Inf");
        assert_eq!(go_f2(f64::NEG_INFINITY), "-Inf");
    }

    #[test]
    fn sysctl_lines_keep_only_the_second_segment() {
        // Go: strings.Split(line, ":")[1], trimmed; lines without ':' dropped.
        let text = "kern.version: Darwin Kernel Version 24.6.0: Mon Jul 14\nnocolon\nfs.file-max: 9223372036854775807\n";
        let pairs: Vec<(String, String)> = text
            .split_inclusive('\n')
            .filter_map(|line| {
                let mut segments = line.trim_end_matches('\n').split(':');
                Some((
                    segments.next()?.to_owned(),
                    segments.next()?.trim().to_owned(),
                ))
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                (
                    "kern.version".to_owned(),
                    "Darwin Kernel Version 24.6.0".to_owned()
                ),
                ("fs.file-max".to_owned(), "9223372036854775807".to_owned()),
            ]
        );
    }

    #[test]
    fn unknown_types_answer_nothing_and_items_sort_by_type_and_name() {
        assert!(collect(7).is_empty());
        let mut items = vec![
            item("net", "lo", vec![]),
            item("cpu", "usage", vec![]),
            item("cpu", "cpu", vec![]),
            item("cpu", "cpu", vec![pair("load1", "0.00".to_owned())]),
        ];
        items.sort_by(|a, b| (&a.tp, &a.name).cmp(&(&b.tp, &b.name)));
        assert_eq!(
            inventory(&items).into_iter().collect::<Vec<_>>(),
            vec![
                ("cpu".to_owned(), "cpu".to_owned()),
                ("cpu".to_owned(), "usage".to_owned()),
                ("net".to_owned(), "lo".to_owned()),
            ]
        );
        // Stable: the first cpu/cpu (no pairs) stays first.
        assert!(items[0].pairs.is_empty());
    }

    #[test]
    fn combined_output_merges_streams_and_rejects_failures() {
        let text = combined_output("sh", &["-c", "echo out; echo err 1>&2; echo out2"]);
        assert_eq!(text.as_deref(), Some("out\nerr\nout2\n"));
        assert_eq!(combined_output("sh", &["-c", "exit 3"]), None);
        assert_eq!(combined_output("/nonexistent/binary-xyz", &[]), None);
    }
}
