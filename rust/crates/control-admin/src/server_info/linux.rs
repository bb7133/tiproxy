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

//! Linux readers: the `procfs`/`sysfs` files and rtnetlink dumps that
//! `gopsutil` v3.24.5 and Go's `net.Interfaces` read, with their parsing
//! rules (including where Go silently drops or errors).

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use super::{CpuInfo, CpuTimes, DiskCounters, Interface, Memory, NicCounters, Partition, Swap};

/// Go `common.ReadLines`: the file split at `\n`, each line without its
/// leading/trailing `\n`, a final unterminated line kept.
fn read_lines(path: &Path) -> std::io::Result<Vec<String>> {
    let bytes = super::go_read_file(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(text
        .split_inclusive('\n')
        .map(|line| line.trim_matches('\n').to_owned())
        .collect())
}

fn proc(rel: &str) -> PathBuf {
    Path::new("/proc").join(rel)
}

fn sys(rel: &str) -> PathBuf {
    Path::new("/sys").join(rel)
}

/// gopsutil `load.Avg`: `/proc/loadavg`, else `sysinfo(2)`.
pub(super) fn load_avg() -> Option<(f64, f64, f64)> {
    let from_file = || -> Option<(f64, f64, f64)> {
        let content = super::go_read_file(&proc("loadavg")).ok()?;
        let text = String::from_utf8_lossy(&content);
        let mut fields = text.split_whitespace();
        let one_minute = fields.next()?.parse().ok()?;
        let five_minutes = fields.next()?.parse().ok()?;
        let fifteen_minutes = fields.next()?.parse().ok()?;
        Some((one_minute, five_minutes, fifteen_minutes))
    };
    from_file().or_else(|| {
        let info = rustix::system::sysinfo();
        let scale = f64::from(1_u32 << 16);
        Some((
            info.loads[0] as f64 / scale,
            info.loads[1] as f64 / scale,
            info.loads[2] as f64 / scale,
        ))
    })
}

fn clocks_per_sec() -> f64 {
    let ticks = rustix::param::clock_ticks_per_second();
    if ticks > 0 { ticks as f64 } else { 100.0 }
}

/// gopsutil `cpu.Times(false)`: the first `/proc/stat` line.
pub(super) fn cpu_times() -> Option<CpuTimes> {
    let lines = read_lines(&proc("stat")).ok()?;
    parse_stat_line(lines.first()?)
}

fn parse_stat_line(line: &str) -> Option<CpuTimes> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 8 || !fields[0].starts_with("cpu") {
        return None;
    }
    let tick = clocks_per_sec();
    let field = |i: usize| -> Option<f64> { fields.get(i)?.parse::<f64>().ok().map(|v| v / tick) };
    let mut times = CpuTimes {
        user: field(1)?,
        nice: field(2)?,
        system: field(3)?,
        idle: field(4)?,
        iowait: field(5)?,
        irq: field(6)?,
        softirq: field(7)?,
        ..CpuTimes::default()
    };
    if fields.len() > 8 {
        times.steal = field(8)?;
    }
    if fields.len() > 9 {
        times.guest = field(9)?;
    }
    if fields.len() > 10 {
        times.guest_nice = field(10)?;
    }
    Some(times)
}

/// The `/proc/meminfo` keys gopsutil parses (a parse failure on any of them
/// fails the whole read).
const MEMINFO_KEYS: &[&str] = &[
    "MemTotal",
    "MemFree",
    "MemAvailable",
    "Buffers",
    "Cached",
    "Active",
    "Inactive",
    "Active(anon)",
    "Inactive(anon)",
    "Active(file)",
    "Inactive(file)",
    "Unevictable",
    "Writeback",
    "WritebackTmp",
    "Dirty",
    "Shmem",
    "Slab",
    "SReclaimable",
    "SUnreclaim",
    "PageTables",
    "SwapCached",
    "CommitLimit",
    "Committed_AS",
    "HighTotal",
    "HighFree",
    "LowTotal",
    "LowFree",
    "SwapTotal",
    "SwapFree",
    "Mapped",
    "VmallocTotal",
    "VmallocUsed",
    "VmallocChunk",
    "HugePages_Total",
    "HugePages_Free",
    "HugePages_Rsvd",
    "HugePages_Surp",
    "Hugepagesize",
    "AnonHugePages",
];

/// gopsutil `mem.VirtualMemory`: `/proc/meminfo`, with the `MemAvailable`
/// fallbacks of `fillFromMeminfo`.
pub(super) fn virtual_memory() -> Option<Memory> {
    let lines = read_lines(&proc("meminfo")).unwrap_or_default();
    let mut total = 0_u64;
    let mut free = 0_u64;
    let mut available = 0_u64;
    let mut cached = 0_u64;
    let mut active_file = None;
    let mut inactive_file = None;
    let mut sreclaimable = None;
    let mut memavail = false;
    for line in &lines {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 2 {
            continue;
        }
        let key = fields[0].trim();
        if !MEMINFO_KEYS.contains(&key) {
            continue;
        }
        let value: u64 = fields[1].trim().replace(" kB", "").parse().ok()?;
        let bytes = value.wrapping_mul(1024);
        match key {
            "MemTotal" => total = bytes,
            "MemFree" => free = bytes,
            "MemAvailable" => {
                memavail = true;
                available = bytes;
            }
            "Cached" => cached = bytes,
            "Active(file)" => active_file = Some(bytes),
            "Inactive(file)" => inactive_file = Some(bytes),
            "SReclaimable" => sreclaimable = Some(bytes),
            _ => {}
        }
    }
    if !memavail {
        available = match (active_file, inactive_file, sreclaimable) {
            (Some(active), Some(inactive), Some(reclaimable)) => {
                calculate_avail_vmem(free, cached, active, inactive, reclaimable)
            }
            _ => cached.wrapping_add(free),
        };
    }
    Some(Memory { total, available })
}

/// gopsutil `calculateAvailVmem` (kernels without `MemAvailable`).
fn calculate_avail_vmem(
    free: u64,
    cached: u64,
    active: u64,
    inactive: u64,
    reclaimable: u64,
) -> u64 {
    let Ok(lines) = read_lines(&proc("zoneinfo")) else {
        return free.wrapping_add(cached);
    };
    let mut watermark_low: u64 = 0;
    for line in &lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first().is_some_and(|f| f.starts_with("low")) {
            let low = fields
                .get(1)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            watermark_low = watermark_low.wrapping_add(low);
        }
    }
    watermark_low = watermark_low.wrapping_mul(rustix::param::page_size() as u64);
    let mut avail = free.wrapping_sub(watermark_low);
    let mut page_cache = active.wrapping_add(inactive);
    page_cache =
        page_cache.wrapping_sub(((page_cache / 2) as f64).min(watermark_low as f64) as u64);
    avail = avail.wrapping_add(page_cache);
    avail.wrapping_add(
        reclaimable.wrapping_sub(((reclaimable / 2) as f64).min(watermark_low as f64) as u64),
    )
}

/// gopsutil `mem.SwapMemory`: `sysinfo(2)`.
#[allow(clippy::unnecessary_wraps)] // Shared platform reader signature.
pub(super) fn swap_memory() -> Option<Swap> {
    let info = rustix::system::sysinfo();
    let unit = u64::from(info.mem_unit);
    let total = (info.totalswap as u64).wrapping_mul(unit);
    let free = (info.freeswap as u64).wrapping_mul(unit);
    Some(Swap {
        total,
        used: total.wrapping_sub(free),
        free,
    })
}

/// gopsutil `net.IOCounters(true)`: `/proc/net/dev`.
pub(super) fn nic_counters() -> Option<Vec<NicCounters>> {
    let lines = read_lines(&proc("net/dev")).ok()?;
    let mut counters = Vec::new();
    for line in lines.iter().skip(2) {
        let Some(separator) = line.rfind(':') else {
            continue;
        };
        let name = line[..separator].trim();
        if name.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line[separator + 1..].split_whitespace().collect();
        let value = |i: usize| -> Option<u64> { fields.get(i)?.parse().ok() };
        counters.push(NicCounters {
            name: name.to_owned(),
            bytes_recv: value(0)?,
            packets_recv: value(1)?,
            errin: value(2)?,
            dropin: value(3)?,
            fifoin: value(4)?,
            bytes_sent: value(8)?,
            packets_sent: value(9)?,
            errout: value(10)?,
            dropout: value(11)?,
            fifoout: value(12)?,
        });
    }
    Some(counters)
}

/// gopsutil `disk.IOCounters()`: `/proc/diskstats`, all-zero rows dropped.
pub(super) fn disk_counters() -> Option<Vec<(String, DiskCounters)>> {
    const SECTOR_SIZE: u64 = 512;
    let lines = read_lines(&proc("diskstats")).ok()?;
    let mut counters = Vec::new();
    for line in &lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }
        let value = |i: usize| -> Option<u64> { fields[i].parse().ok() };
        let parsed: Vec<u64> = (3..14).map(value).collect::<Option<_>>()?;
        if parsed.iter().all(|v| *v == 0) {
            continue;
        }
        counters.push((
            fields[2].to_owned(),
            DiskCounters {
                read_count: parsed[0],
                merged_read_count: parsed[1],
                read_bytes: parsed[2].wrapping_mul(SECTOR_SIZE),
                write_count: parsed[4],
                merged_write_count: parsed[5],
                write_bytes: parsed[6].wrapping_mul(SECTOR_SIZE),
            },
        ));
    }
    Some(counters)
}

/// gopsutil `cpu.Info()[0]`: `/proc/cpuinfo` with `finishCPUInfo`'s
/// `cpufreq/cpuinfo_max_freq` override. Parse failures of `processor`,
/// `stepping`/`revision` and `cache size` fail the whole read like Go.
pub(super) fn cpu_info() -> Option<CpuInfo> {
    let lines = read_lines(&proc("cpuinfo")).unwrap_or_default();
    let mut first: Option<(i64, CpuInfo)> = None;
    let mut current: Option<(i64, CpuInfo)> = None;
    for line in &lines {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 2 {
            continue;
        }
        let key = fields[0].trim();
        let value = fields[1].trim();
        match key {
            "processor" | "cpu number" => {
                if first.is_none() {
                    first = current.take();
                }
                let cpu: i64 = value.parse().ok()?;
                current = Some((cpu, CpuInfo::default()));
            }
            "stepping" | "revision" | "CPU revision" => {
                let text = if key == "revision" {
                    value.split('.').next().unwrap_or_default()
                } else {
                    value
                };
                text.parse::<i64>().ok()?;
            }
            "cpu MHz" | "clock" | "cpu MHz dynamic" => {
                if let (Some((_, info)), Ok(mhz)) = (
                    current.as_mut(),
                    value.replacen("MHz", "", 1).parse::<f64>(),
                ) {
                    info.mhz = mhz;
                }
            }
            "cache size" => {
                let cache: i64 = value.replacen(" KB", "", 1).parse().ok()?;
                if let Some((_, info)) = current.as_mut() {
                    info.cache_size = cache as i32;
                }
            }
            _ => {}
        }
    }
    if first.is_none() {
        first = current;
    }
    let (cpu, mut info) = first?;
    finish_cpu_info(cpu, &mut info);
    Some(info)
}

fn finish_cpu_info(cpu: i64, info: &mut CpuInfo) {
    let path = sys(&format!(
        "devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq"
    ));
    let Ok(lines) = read_lines(&path) else {
        return;
    };
    let Some(Ok(value)) = lines.first().map(|line| line.parse::<f64>()) else {
        return;
    };
    let mut mhz = value / 1000.0;
    if mhz > 9999.0 {
        mhz /= 1000.0;
    }
    info.mhz = mhz;
}

/// gopsutil `cpu.Counts(false)`: distinct topology sibling lists, else the
/// `physical id`/`cpu cores` mapping of `/proc/cpuinfo`.
pub(super) fn physical_cores() -> Option<usize> {
    for relative in ["core_cpus_list", "thread_siblings_list"] {
        let mut lists = BTreeSet::new();
        if let Ok(entries) = std::fs::read_dir(sys("devices/system/cpu")) {
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(rest) = name.strip_prefix("cpu") else {
                    continue;
                };
                if !rest.starts_with(|c: char| c.is_ascii_digit()) {
                    continue;
                }
                let Ok(lines) = read_lines(&entry.path().join("topology").join(relative)) else {
                    continue;
                };
                if lines.len() != 1 {
                    continue;
                }
                lists.insert(lines[0].clone());
            }
        }
        if !lists.is_empty() {
            return Some(lists.len());
        }
    }
    let lines = read_lines(&proc("cpuinfo")).ok()?;
    let mut mapping: HashMap<i64, i64> = HashMap::new();
    let mut current: HashMap<String, i64> = HashMap::new();
    for line in &lines {
        let line = line.trim().to_lowercase();
        if line.is_empty() {
            if let (Some(id), Some(cores)) = (current.get("physical id"), current.get("cpu cores"))
            {
                mapping.insert(*id, *cores);
            }
            current.clear();
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 2 {
            continue;
        }
        let key = fields[0].trim();
        if (key == "physical id" || key == "cpu cores")
            && let Ok(value) = fields[1].trim().parse::<i64>()
        {
            current.insert(key.to_owned(), value);
        }
    }
    Some(mapping.values().sum::<i64>().max(0) as usize)
}

/// Go `runtime.NumCPU`: the scheduling affinity count.
pub(super) fn logical_cores() -> usize {
    rustix::process::sched_getaffinity(None)
        .map(|set| set.count() as usize)
        .unwrap_or(1)
        .max(1)
}

fn read_mount_file(root: &Path) -> Option<(Vec<String>, bool)> {
    match read_lines(&root.join("mountinfo")) {
        Ok(lines) => Some((lines, false)),
        Err(_) => Some((read_lines(&root.join("mounts")).ok()?, true)),
    }
}

/// gopsutil `disk.Partitions(true)`: `/proc/1/mountinfo` (then `mounts`,
/// then the same under `/proc/self`), with the `/dev/mapper` and
/// `/dev/root` resolutions.
pub(super) fn partitions() -> Option<Vec<Partition>> {
    let (lines, use_mounts) =
        read_mount_file(&proc("1")).or_else(|| read_mount_file(&proc("self")))?;
    let mut parts = Vec::with_capacity(lines.len());
    for line in &lines {
        if use_mounts {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }
            parts.push(Partition {
                device: fields[0].to_owned(),
                mountpoint: unescape_fstab(fields[1]),
                fstype: fields[2].to_owned(),
                // Go splits the option list on whitespace: one element.
                opts: vec![fields[3].to_owned()],
            });
            continue;
        }
        let halves: Vec<&str> = line.split(" - ").collect();
        if halves.len() != 2 {
            return None;
        }
        let fields: Vec<&str> = halves[0].split_whitespace().collect();
        let tail: Vec<&str> = halves[1].split_whitespace().collect();
        if fields.len() < 6 || tail.len() < 2 {
            return None;
        }
        let block_device_id = fields[2];
        let mut opts: Vec<String> = fields[5].split(',').map(str::to_owned).collect();
        if !fields[3].is_empty() && fields[3] != "/" {
            opts.push("bind".to_owned());
        }
        let mut device = tail[1].to_owned();
        if device.starts_with("/dev/mapper/")
            && let Ok(resolved) = std::fs::canonicalize(&device)
        {
            device = resolved.to_string_lossy().into_owned();
        }
        if device == "/dev/root"
            && let Ok(target) = std::fs::read_link(sys(&format!("dev/block/{block_device_id}")))
            && let Some(base) = target.file_name()
        {
            device = format!("/dev/{}", base.to_string_lossy());
        }
        parts.push(Partition {
            device,
            mountpoint: unescape_fstab(fields[4]),
            fstype: tail[0].to_owned(),
            opts,
        });
    }
    Some(parts)
}

/// gopsutil `unescapeFstab`: Go `strconv.Unquote("\"" + path + "\"")`, the
/// original path when that fails.
pub(crate) fn unescape_fstab(path: &str) -> String {
    go_unquote(path).unwrap_or_else(|| path.to_owned())
}

fn go_unquote(text: &str) -> Option<String> {
    if !text.contains('\\') {
        if text.contains('"') || text.contains('\n') {
            return None;
        }
        return Some(text.to_owned());
    }
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\n' => return None,
            '\\' => {
                let escape = chars.next()?;
                match escape {
                    'a' => out.push(7),
                    'b' => out.push(8),
                    'f' => out.push(12),
                    'n' => out.push(b'\n'),
                    'r' => out.push(b'\r'),
                    't' => out.push(b'\t'),
                    'v' => out.push(11),
                    '\\' => out.push(b'\\'),
                    '"' => out.push(b'"'),
                    'x' => {
                        let value = hex_digits(&mut chars, 2)?;
                        out.push(value as u8);
                    }
                    '0'..='7' => {
                        let mut value = escape.to_digit(8)?;
                        for _ in 0..2 {
                            value = value * 8 + chars.next()?.to_digit(8)?;
                        }
                        if value > 255 {
                            return None;
                        }
                        out.push(value as u8);
                    }
                    'u' | 'U' => {
                        let value = hex_digits(&mut chars, if escape == 'u' { 4 } else { 8 })?;
                        let rune = char::from_u32(value)?;
                        let mut buf = [0_u8; 4];
                        out.extend_from_slice(rune.encode_utf8(&mut buf).as_bytes());
                    }
                    _ => return None,
                }
            }
            other => {
                let mut buf = [0_u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_digits(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, count: usize) -> Option<u32> {
    let mut value = 0_u32;
    for _ in 0..count {
        value = value * 16 + chars.next()?.to_digit(16)?;
    }
    Some(value)
}

// ---------------------------------------------------------------------------
// rtnetlink, as Go's net.Interfaces / Interface.Addrs

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_POINTOPOINT: u32 = 0x10;
const IFF_MULTICAST: u32 = 0x1000;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Go `syscall.NetlinkRIB(proto, AF_UNSPEC)`: one dump request, every
/// message until `NLMSG_DONE`; an error message or a malformed buffer is a
/// failure.
fn netlink_dump(msg_type: u16) -> Option<Vec<(u16, Vec<u8>)>> {
    use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType, recv, send, socket};
    let fd = socket(AddressFamily::NETLINK, SocketType::RAW, None).ok()?;
    let mut request = [0_u8; 20];
    request[0..4].copy_from_slice(&20_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    // pid 0 (kernel), rtgenmsg family AF_UNSPEC.
    send(&fd, &request, SendFlags::empty()).ok()?;
    let mut messages = Vec::new();
    let mut buffer = vec![0_u8; 65536];
    loop {
        let received = recv(&fd, &mut buffer, RecvFlags::empty()).ok()?;
        let mut offset = 0;
        let mut done = false;
        while offset + NLMSG_HDRLEN <= received {
            let len = u32::from_ne_bytes(buffer[offset..offset + 4].try_into().ok()?) as usize;
            let kind = u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into().ok()?);
            let seq = u32::from_ne_bytes(buffer[offset + 8..offset + 12].try_into().ok()?);
            if len < NLMSG_HDRLEN || offset + len > received || seq != 1 {
                return None;
            }
            match kind {
                NLMSG_DONE => done = true,
                NLMSG_ERROR => return None,
                _ => messages.push((kind, buffer[offset + NLMSG_HDRLEN..offset + len].to_vec())),
            }
            offset += (len + 3) & !3;
        }
        if done {
            return Some(messages);
        }
    }
}

/// Go `ParseNetlinkRouteAttr`.
fn parse_attrs(mut data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut attrs = Vec::new();
    while data.len() >= 4 {
        let len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let kind = u16::from_ne_bytes([data[2], data[3]]);
        if len < 4 || len > data.len() {
            return None;
        }
        attrs.push((kind, &data[4..len]));
        let aligned = (len + 3) & !3;
        data = if aligned >= data.len() {
            &[]
        } else {
            &data[aligned..]
        };
    }
    Some(attrs)
}

/// Go `newAddr`: `IFA_LOCAL` marks a point-to-point address and hides
/// `IFA_ADDRESS`; the first remaining attribute is the address.
fn netlink_addr(family: u8, prefix_len: u8, attrs: &[(u16, &[u8])]) -> Option<String> {
    let point_to_point = attrs.iter().any(|(kind, _)| *kind == IFA_LOCAL);
    for (kind, value) in attrs {
        if point_to_point && *kind == IFA_ADDRESS {
            continue;
        }
        return match family {
            AF_INET => {
                let bytes: [u8; 4] = value.get(..4)?.try_into().ok()?;
                Some(format!("{}/{prefix_len}", Ipv4Addr::from(bytes)))
            }
            AF_INET6 => {
                let bytes: [u8; 16] = value.get(..16)?.try_into().ok()?;
                Some(format!("{}/{prefix_len}", Ipv6Addr::from(bytes)))
            }
            _ => None,
        };
    }
    None
}

/// Go `net.Interfaces()` plus `Interface.Addrs()` for each: `RTM_GETLINK`
/// then `RTM_GETADDR` dumps, addresses attached by interface index in dump
/// order.
pub(super) fn interfaces() -> Option<Vec<Interface>> {
    let links = netlink_dump(RTM_GETLINK)?;
    let mut indexes = Vec::new();
    let mut result = Vec::new();
    for (kind, data) in &links {
        if *kind != RTM_NEWLINK || data.len() < 16 {
            continue;
        }
        let index = i32::from_ne_bytes(data[4..8].try_into().ok()?);
        let flags = u32::from_ne_bytes(data[8..12].try_into().ok()?);
        let mut nic = Interface {
            up: flags & IFF_UP != 0,
            broadcast: flags & IFF_BROADCAST != 0,
            loopback: flags & IFF_LOOPBACK != 0,
            point_to_point: flags & IFF_POINTOPOINT != 0,
            multicast: flags & IFF_MULTICAST != 0,
            ..Interface::default()
        };
        for (attr, value) in parse_attrs(&data[16..])? {
            match attr {
                IFLA_ADDRESS => {
                    if value.iter().any(|b| *b != 0) {
                        nic.hardware_addr = value
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":");
                    }
                }
                IFLA_IFNAME => {
                    let name = value.strip_suffix(&[0]).unwrap_or(value);
                    nic.name = String::from_utf8_lossy(name).into_owned();
                }
                _ => {}
            }
        }
        indexes.push(index);
        result.push(nic);
    }
    let addrs = netlink_dump(RTM_GETADDR)?;
    for (kind, data) in &addrs {
        if *kind != RTM_NEWADDR || data.len() < 8 {
            continue;
        }
        let family = data[0];
        let prefix_len = data[1];
        let index = u32::from_ne_bytes(data[4..8].try_into().ok()?) as i32;
        let Some(position) = indexes.iter().position(|i| *i == index) else {
            continue;
        };
        let attrs = parse_attrs(&data[8..])?;
        if let Some(addr) = netlink_addr(family, prefix_len, &attrs) {
            result[position].addrs.push(addr);
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_line_follows_gopsutil() {
        let line = "cpu  100 200 300 400 500 600 700 800 900 1000";
        let times = parse_stat_line(line).unwrap_or_else(|| unreachable!());
        let tick = clocks_per_sec();
        let ticks = |seconds: f64| (seconds * tick).round() as u64;
        assert_eq!(ticks(times.user), 100);
        assert_eq!(ticks(times.nice), 200);
        assert_eq!(ticks(times.system), 300);
        assert_eq!(ticks(times.guest_nice), 1000);
        assert_eq!(parse_stat_line("cpu 1 2 3 4 5 6"), None);
        assert_eq!(parse_stat_line("intr 1 2 3 4 5 6 7 8"), None);
    }

    #[test]
    fn fstab_unescape_follows_strconv_unquote() {
        assert_eq!(unescape_fstab("/mnt/with\\040space"), "/mnt/with space");
        assert_eq!(unescape_fstab("/plain"), "/plain");
        assert_eq!(unescape_fstab("/bad\\q"), "/bad\\q");
        assert_eq!(unescape_fstab("/tab\\011x"), "/tab\tx");
        assert_eq!(unescape_fstab("/quote\"inside"), "/quote\"inside");
    }

    #[test]
    fn netlink_attrs_and_addresses_follow_go() {
        // Two attributes: IFA_ADDRESS 10.0.0.2 and IFA_LOCAL 10.0.0.1.
        let mut data = Vec::new();
        for (kind, ip) in [(IFA_ADDRESS, [10, 0, 0, 2]), (IFA_LOCAL, [10, 0, 0, 1])] {
            data.extend_from_slice(&8_u16.to_ne_bytes());
            data.extend_from_slice(&kind.to_ne_bytes());
            data.extend_from_slice(&ip);
        }
        let attrs = parse_attrs(&data).unwrap_or_else(|| unreachable!());
        assert_eq!(attrs.len(), 2);
        assert_eq!(
            netlink_addr(AF_INET, 32, &attrs).as_deref(),
            Some("10.0.0.1/32"),
            "point-to-point uses IFA_LOCAL"
        );
        let v6 = [(
            IFA_ADDRESS,
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        )];
        let mut data = Vec::new();
        for (kind, ip) in v6 {
            data.extend_from_slice(&20_u16.to_ne_bytes());
            data.extend_from_slice(&kind.to_ne_bytes());
            data.extend_from_slice(&ip);
        }
        let attrs = parse_attrs(&data).unwrap_or_else(|| unreachable!());
        assert_eq!(
            netlink_addr(AF_INET6, 64, &attrs).as_deref(),
            Some("fe80::1/64")
        );
        assert_eq!(
            parse_attrs(&[3, 0, 0, 0]),
            None,
            "attribute shorter than its header"
        );
    }
}
