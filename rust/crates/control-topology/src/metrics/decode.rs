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

//! Wire decoding with a pre-allocation lexical budget and typed cardinality caps.

use super::{
    BackendHistory, History, MAX_BYTES, MAX_LABELS, MAX_SAMPLES, MAX_SERIES, MAX_TOKEN,
    MetricError, MetricFamily, MetricPoint, QueryResult, Sample, Series, ValueKind, query_catalog,
};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use std::collections::BTreeMap;

/// A lexical preflight bounds allocations before serde builds any collections.
/// String contents are scanned without allocation; serde then validates syntax.
fn preflight(bytes: &[u8]) -> Result<(), MetricError> {
    if bytes.len() > MAX_BYTES {
        return Err(MetricError::Limit);
    }
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                nodes += 1;
                let start = index;
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    if bytes[index] == b'\\' {
                        index += 1;
                    }
                    index += 1;
                }
                if index - start > MAX_TOKEN * 6 {
                    return Err(MetricError::Limit);
                }
            }
            b'[' | b'{' => {
                depth += 1;
                nodes += 1;
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
            }
            b',' | b':' => {
                nodes += 1;
            }
            _ => {}
        }
        // Covers unknown fields, too. History may grow across multiple bounded
        // responses up to MAX_SAMPLES, but each individual JSON tree is capped.
        if depth > 16 || nodes > 1_000_000 {
            return Err(MetricError::Limit);
        }
        index += 1;
    }
    Ok(())
}

impl Serialize for Sample {
    #[allow(clippy::cast_precision_loss)]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut pair = serializer.serialize_seq(Some(2))?;
        // Go model.Time serializes float64(milliseconds)/1000. Keep that same
        // conversion; ordinary Unix times retain millisecond precision.
        pair.serialize_element(&(self.timestamp_ms as f64 / 1000.0))?;
        let value = if self.value.is_nan() {
            "NaN".into()
        } else if self.value == f64::INFINITY {
            "+Inf".into()
        } else if self.value == f64::NEG_INFINITY {
            "-Inf".into()
        } else {
            self.value.to_string()
        };
        pair.serialize_element(&value)?;
        pair.end()
    }
}

impl<'de> Deserialize<'de> for Sample {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let pair = <[Box<RawValue>; 2]>::deserialize(decoder)?;
        let timestamp_ms = timestamp(pair[0].get()).map_err(serde::de::Error::custom)?;
        let value: String =
            serde_json::from_str(pair[1].get()).map_err(serde::de::Error::custom)?;
        let value =
            parse_float(&value).ok_or_else(|| serde::de::Error::custom("invalid metric value"))?;
        Ok(Self {
            timestamp_ms,
            value,
        })
    }
}

// Go prometheus/common v0.65.0 model.Time parses decimal seconds by truncating
// to three fractional digits. Do not round a JSON f64 or accept exponent syntax.
fn timestamp(text: &str) -> Result<i64, MetricError> {
    let (whole, fraction) = text
        .split_once('.')
        .map_or((text, None), |(whole, fraction)| (whole, Some(fraction)));
    let millis = whole
        .parse::<i64>()
        .map_err(|_| MetricError::Invalid)?
        .checked_mul(1000)
        .ok_or(MetricError::Invalid)?;
    let Some(fraction) = fraction else {
        return Ok(millis);
    };
    if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MetricError::Invalid);
    }
    let mut digits = fraction.chars().take(3).collect::<String>();
    while digits.len() < 3 {
        digits.push('0');
    }
    let part = digits.parse::<i64>().map_err(|_| MetricError::Invalid)?;
    let result = millis.checked_add(part).ok_or(MetricError::Invalid)?;
    // Match the pinned Go decoder's historical negative-fraction behavior.
    Ok(if whole.starts_with('-') && result > 0 {
        -result
    } else {
        result
    })
}

fn parse_float(text: &str) -> Option<f64> {
    match text {
        "NaN" => Some(f64::NAN),
        "+Inf" | "Inf" | "+Infinity" | "Infinity" => Some(f64::INFINITY),
        "-Inf" | "-Infinity" => Some(f64::NEG_INFINITY),
        _ => text.parse().ok(),
    }
}

#[derive(Deserialize)]
struct PromResponse {
    status: String,
    data: Option<PromData>,
}
#[derive(Deserialize)]
struct PromData {
    #[serde(rename = "resultType")]
    kind: String,
    result: Vec<WireSeries>,
}
#[derive(Deserialize)]
struct WireSeries {
    #[serde(default)]
    metric: Option<BTreeMap<String, String>>,
    #[serde(default)]
    value: Option<Sample>,
    #[serde(default)]
    values: Option<Vec<Sample>>,
}

/// Decodes a successful Prometheus vector/matrix response and attaches the
/// producer's cluster label. Empty success remains a successful empty result.
///
/// # Errors
/// Returns `QueryFailed` for an API error, `Invalid` for malformed/unsupported
/// data, and `Limit` before an unbounded JSON tree or result is constructed.
pub fn decode_prometheus(
    bytes: &[u8],
    cluster: &str,
    updated_nanos: i64,
) -> Result<QueryResult, MetricError> {
    if cluster.trim().len() > MAX_TOKEN {
        return Err(MetricError::Limit);
    }
    preflight(bytes)?;
    let envelope: PromResponse = serde_json::from_slice(bytes).map_err(|_| MetricError::Invalid)?;
    if envelope.status != "success" {
        return Err(MetricError::QueryFailed);
    }
    let data = envelope.data.ok_or(MetricError::Invalid)?;
    let kind = match data.kind.as_str() {
        "vector" => ValueKind::Vector,
        "matrix" => ValueKind::Matrix,
        _ => return Err(MetricError::Invalid),
    };
    if data.result.len() > MAX_SERIES {
        return Err(MetricError::Limit);
    }
    let mut count = 0;
    let mut series = Vec::with_capacity(data.result.len());
    for wire in data.result {
        let labels = wire.metric.unwrap_or_default();
        check_labels(&labels)?;
        let samples = match kind {
            ValueKind::Vector => vec![wire.value.unwrap_or(Sample {
                timestamp_ms: 0,
                value: 0.0,
            })],
            ValueKind::Matrix => wire.values.unwrap_or_default(),
        };
        count += samples.len();
        if count > MAX_SAMPLES {
            return Err(MetricError::Limit);
        }
        series.push(Series { labels, samples });
    }
    let mut result = QueryResult {
        kind,
        series,
        updated_nanos,
    };
    result.attach_cluster(cluster);
    Ok(result)
}

fn check_labels(labels: &BTreeMap<String, String>) -> Result<(), MetricError> {
    if labels.len() > MAX_LABELS
        || labels
            .iter()
            .any(|(key, value)| key.len() > MAX_TOKEN || value.len() > MAX_TOKEN)
    {
        return Err(MetricError::Limit);
    }
    Ok(())
}

/// Decodes the existing owner-history endpoint. An empty body or JSON null
/// means successful empty history, as in Go. Unknown rule/backend keys survive.
///
/// # Errors
/// Rejects malformed histories and wire/cardinality limits.
pub fn decode_owner_history(bytes: &[u8]) -> Result<History, MetricError> {
    type WireHistory = BTreeMap<String, Option<BTreeMap<String, Option<BackendHistory>>>>;
    if bytes.is_empty() {
        return Ok(History::default());
    }
    preflight(bytes)?;
    let entries: Option<WireHistory> =
        serde_json::from_slice(bytes).map_err(|_| MetricError::Invalid)?;
    let history = History::from_entries(
        entries
            .unwrap_or_default()
            .into_iter()
            .map(|(key, backends)| {
                (
                    key,
                    backends
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(backend, history)| (backend, history.unwrap_or_default()))
                        .collect(),
                )
            })
            .collect(),
    )?;
    if history.entries.iter().any(|(rule, backends)| {
        rule.len() > MAX_TOKEN || backends.keys().any(|backend| backend.len() > MAX_TOKEN)
    }) {
        return Err(MetricError::Limit);
    }
    Ok(history)
}

/// Filters the fixed metric names before parsing Go's untyped exposition
/// points. HELP/TYPE comments are ignored just as by Go `filterMetrics`.
///
/// # Errors
/// Rejects malformed selected lines or explicit token/label/series limits.
pub fn decode_backend(bytes: &[u8]) -> Result<MetricFamily, MetricError> {
    if bytes.len() > MAX_BYTES {
        return Err(MetricError::Limit);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| MetricError::Invalid)?;
    let names: Vec<&str> = query_catalog()
        .iter()
        .flat_map(|spec| spec.names.iter().copied())
        .collect();
    let mut metrics: MetricFamily = BTreeMap::new();
    let mut count = 0;
    for line in text
        .lines()
        .filter(|line| names.iter().any(|name| line.starts_with(name)))
    {
        let (name, point) = parse_point(line)?;
        count += 1;
        if count > MAX_SERIES {
            return Err(MetricError::Limit);
        }
        metrics.entry(name).or_default().push(point);
    }
    Ok(metrics)
}

fn parse_point(line: &str) -> Result<(String, MetricPoint), MetricError> {
    let name_end = line
        .bytes()
        .position(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b':'))
        .unwrap_or(line.len());
    if name_end == 0 {
        return Err(MetricError::Invalid);
    }
    if name_end > MAX_TOKEN {
        return Err(MetricError::Limit);
    }
    let name = line[..name_end].to_owned();
    let mut rest = line[name_end..].trim_start();
    let mut labels = BTreeMap::new();
    if let Some(body) = rest.strip_prefix('{') {
        rest = body.trim_start();
        while !rest.starts_with('}') {
            if !rest
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            {
                return Err(MetricError::Invalid);
            }
            let end = rest
                .bytes()
                .position(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
                .unwrap_or(rest.len());
            if end == 0 {
                return Err(MetricError::Invalid);
            }
            let key = rest[..end].to_owned();
            rest = rest[end..]
                .trim_start()
                .strip_prefix('=')
                .ok_or(MetricError::Invalid)?
                .trim_start();
            let (value, remaining) = label_value(rest)?;
            if labels.insert(key, value).is_some() {
                return Err(MetricError::Invalid);
            }
            check_labels(&labels)?;
            rest = remaining.trim_start();
            if let Some(remaining) = rest.strip_prefix(',') {
                rest = remaining.trim_start();
            } else if !rest.starts_with('}') {
                return Err(MetricError::Invalid);
            }
        }
        rest = rest[1..].trim_start();
    }
    let mut fields = rest.split_whitespace();
    let value = fields
        .next()
        .and_then(parse_float)
        .ok_or(MetricError::Invalid)?;
    if let Some(timestamp) = fields.next() {
        timestamp.parse::<i64>().map_err(|_| MetricError::Invalid)?;
    }
    if fields.next().is_some() {
        return Err(MetricError::Invalid);
    }
    Ok((name, MetricPoint { labels, value }))
}

fn label_value(text: &str) -> Result<(String, &str), MetricError> {
    let text = text.strip_prefix('"').ok_or(MetricError::Invalid)?;
    let mut value = String::new();
    let mut chars = text.char_indices();
    while let Some((index, character)) = chars.next() {
        match character {
            '"' => return Ok((value, &text[index + 1..])),
            '\\' => {
                value.push(match chars.next().map(|(_, character)| character) {
                    Some('n') => '\n',
                    Some('\\') => '\\',
                    Some('"') => '"',
                    _ => return Err(MetricError::Invalid),
                });
            }
            '\n' => return Err(MetricError::Invalid),
            character => value.push(character),
        }
        if value.len() > MAX_TOKEN {
            return Err(MetricError::Limit);
        }
    }
    Err(MetricError::Invalid)
}
