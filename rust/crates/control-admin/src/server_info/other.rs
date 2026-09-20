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

//! Platforms without a host reader: only the command-based `system` items
//! are answered (declared in the design document).

use super::{CpuInfo, CpuTimes, DiskCounters, Interface, Memory, NicCounters, Partition, Swap};

pub(super) fn load_avg() -> Option<(f64, f64, f64)> {
    None
}
pub(super) fn cpu_times() -> Option<CpuTimes> {
    None
}
pub(super) fn virtual_memory() -> Option<Memory> {
    None
}
pub(super) fn swap_memory() -> Option<Swap> {
    None
}
pub(super) fn nic_counters() -> Option<Vec<NicCounters>> {
    None
}
pub(super) fn disk_counters() -> Option<Vec<(String, DiskCounters)>> {
    None
}
pub(super) fn cpu_info() -> Option<CpuInfo> {
    None
}
pub(super) fn physical_cores() -> Option<usize> {
    None
}
pub(super) fn logical_cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}
pub(super) fn partitions() -> Option<Vec<Partition>> {
    None
}
pub(super) fn interfaces() -> Option<Vec<Interface>> {
    None
}
