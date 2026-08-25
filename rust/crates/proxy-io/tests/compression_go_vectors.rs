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

//! Bidirectional Go/Rust compressed-frame golden vectors.

use std::error::Error;

use proxy_io::compression::{CompressionAlgorithm, CompressionCodec, CompressionLimits};

type TestResult = Result<(), Box<dyn Error>>;

const GO_ZLIB_RAW_49: &str = "3100000000000072727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272";
const GO_ZLIB_LEVEL_6: &str = "49000000000f00789c0ac90c28caafa8d475f60dd02d4b4d2ec92fd23530343236313533b7b0b41e951d951d951d951d951d951d951d951d951d951d951d951d951d951d1eb280000000ffff39b890bd";
const GO_ZSTD_LEVEL_1: &str = "36000000000f0028b52ffd64000e450100e401546950726f78792d434d502d766563746f722d303132333435363738393b015415052f7e3b04e2c82b7e";
const GO_ZSTD_LEVEL_3: &str = GO_ZSTD_LEVEL_1;
const GO_ZSTD_LEVEL_9: &str = GO_ZSTD_LEVEL_1;
const GO_ZSTD_LEVEL_22: &str = GO_ZSTD_LEVEL_1;
const RUST_ZLIB_RAW_49: &str = GO_ZLIB_RAW_49;
const RUST_ZLIB_LEVEL_6: &str = "44000000000f00789cedc94b0a40111480e1159dbaef4b86c6cac00e6460a424b17bfbd03ffe42f6b58c29d679e929b652e538affb79bf5f691350144551144551144551740b5d39b890bd";
const RUST_ZSTD_LEVEL_1: &str = "30000000000f0028b52ffd60000e350100f0546950726f78792d434d502d766563746f722d303132333435363738393b01007e3bf8ca09";
const RUST_ZSTD_LEVEL_3: &str = RUST_ZSTD_LEVEL_1;
const RUST_ZSTD_LEVEL_9: &str = RUST_ZSTD_LEVEL_1;
const RUST_ZSTD_LEVEL_22: &str = RUST_ZSTD_LEVEL_1;

fn decode_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    if !input.len().is_multiple_of(2) {
        return Err("hex vector has an odd length");
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex vector"),
    }
}

fn encode_hex(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for &byte in input {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[test]
fn go_frames_decode_and_rust_encodes_stay_stable() -> TestResult {
    let raw = vec![b'r'; 49];
    let compressed = b"TiProxy-CMP-vector-0123456789;".repeat(128);
    let cases = [
        (
            "zlib-raw-49",
            CompressionAlgorithm::Zlib,
            GO_ZLIB_RAW_49,
            RUST_ZLIB_RAW_49,
            raw.as_slice(),
        ),
        (
            "zlib-level-6",
            CompressionAlgorithm::Zlib,
            GO_ZLIB_LEVEL_6,
            RUST_ZLIB_LEVEL_6,
            compressed.as_slice(),
        ),
        (
            "zstd-level-1",
            CompressionAlgorithm::Zstd { level: 1 },
            GO_ZSTD_LEVEL_1,
            RUST_ZSTD_LEVEL_1,
            compressed.as_slice(),
        ),
        (
            "zstd-level-3",
            CompressionAlgorithm::Zstd { level: 3 },
            GO_ZSTD_LEVEL_3,
            RUST_ZSTD_LEVEL_3,
            compressed.as_slice(),
        ),
        (
            "zstd-level-9",
            CompressionAlgorithm::Zstd { level: 9 },
            GO_ZSTD_LEVEL_9,
            RUST_ZSTD_LEVEL_9,
            compressed.as_slice(),
        ),
        (
            "zstd-level-22",
            CompressionAlgorithm::Zstd { level: 22 },
            GO_ZSTD_LEVEL_22,
            RUST_ZSTD_LEVEL_22,
            compressed.as_slice(),
        ),
    ];

    for (name, algorithm, go_hex, rust_hex, payload) in cases {
        let mut decoder = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        assert_eq!(
            decoder.decode_frame(&decode_hex(go_hex)?)?,
            payload,
            "{name}"
        );

        let mut encoder = CompressionCodec::new(algorithm, CompressionLimits::default())?;
        assert_eq!(
            encode_hex(&encoder.encode_frame(payload)?),
            rust_hex,
            "{name}"
        );
    }
    Ok(())
}
