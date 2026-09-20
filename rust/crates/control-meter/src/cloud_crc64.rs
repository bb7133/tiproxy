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

//! Reflected CRC-64/ECMA used by the Go OSS/COS upload clients.

const TABLE: [u64; 256] = {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u64;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1)
                ^ if value & 1 == 0 {
                    0
                } else {
                    0xc96c_5795_d787_0f42
                };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};
pub(crate) fn checksum(body: &[u8]) -> u64 {
    let mut value = u64::MAX;
    for byte in body {
        value = TABLE[usize::from(value.to_le_bytes()[0] ^ byte)] ^ (value >> 8);
    }
    !value
}
