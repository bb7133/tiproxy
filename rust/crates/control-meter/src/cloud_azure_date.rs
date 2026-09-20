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

//! Acceptance rules for typed Azure RFC1123 response metadata.
//! No offset is calculated: metering only needs to know whether parsing succeeds.

pub(super) fn valid(value: &str) -> bool {
    if value.trim() != value || value.contains(['\t', '\r', '\n']) {
        return false;
    }
    let fields: Vec<_> = value.split(' ').filter(|s| !s.is_empty()).collect();
    let [weekday, day, month, year, clock, zone] = fields.as_slice() else {
        return false;
    };
    let weekday = weekday.strip_suffix(',').unwrap_or_default();
    if !["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        .iter()
        .any(|v| v.eq_ignore_ascii_case(weekday))
        || day.len() != 2
        || year.len() != 4
        || !valid_zone(zone)
    {
        return false;
    }
    let Some(month) = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|v| v.eq_ignore_ascii_case(month)) else {
        return false;
    };
    let number = |value: &str| {
        value
            .bytes()
            .all(|v| v.is_ascii_digit())
            .then(|| value.parse::<u16>().ok())
            .flatten()
    };
    let (Some(day), Some(year)) = (number(day), number(year)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > days[month] {
        return false;
    }
    let clock: Vec<_> = clock.split(':').collect();
    let [hour, minute, second] = clock.as_slice() else {
        return false;
    };
    let (second, fraction) = second
        .split_once(['.', ','])
        .map_or((*second, None), |(s, f)| (s, Some(f)));
    if !(1..=2).contains(&hour.len())
        || minute.len() != 2
        || second.len() != 2
        || fraction.is_some_and(|v| v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    matches!(
        (number(hour), number(minute), number(second)),
        (Some(0..=23), Some(0..=59), Some(0..=59))
    )
}

fn valid_zone(zone: &str) -> bool {
    // Go time.Parse accepts unknown abbreviations with offset zero. Its
    // special names and signed-hour grammar are broader than RFC7231's GMT.
    if zone.len() < 3 {
        return false;
    }
    if matches!(zone, "ChST" | "MeST" | "WITA" | "GMT") {
        return true;
    }
    let signed = zone.strip_prefix("GMT").unwrap_or(zone);
    if signed.starts_with(['+', '-']) {
        let digits = &signed[1..];
        return !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && digits.parse::<u64>().is_ok_and(|n| n <= 23);
    }
    zone.bytes().all(|b| b.is_ascii_uppercase())
        && (zone.len() == 3 || ((4..=5).contains(&zone.len()) && zone.ends_with('T')))
}
