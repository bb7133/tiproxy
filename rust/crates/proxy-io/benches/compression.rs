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

//! Criterion cases for bounded `MySQL` compressed-frame encode/decode.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use proxy_io::compression::{CompressionAlgorithm, CompressionCodec, CompressionLimits};

fn codec_or_exit(algorithm: CompressionAlgorithm) -> CompressionCodec {
    let Ok(codec) = CompressionCodec::new(algorithm, CompressionLimits::default()) else {
        eprintln!("benchmark used an invalid compression configuration");
        std::process::exit(2);
    };
    codec
}

fn encode_or_exit(codec: &mut CompressionCodec, payload: &[u8]) -> Vec<u8> {
    let Ok(frame) = codec.encode_frame(payload) else {
        eprintln!("benchmark compression failed");
        std::process::exit(2);
    };
    frame
}

fn decode_or_exit(codec: &mut CompressionCodec, frame: &[u8]) -> Vec<u8> {
    let Ok(payload) = codec.decode_frame(frame) else {
        eprintln!("benchmark decompression failed");
        std::process::exit(2);
    };
    payload
}

fn compression_benchmarks(criterion: &mut Criterion) {
    let algorithms = [
        ("zlib-6", CompressionAlgorithm::Zlib),
        ("zstd-3", CompressionAlgorithm::Zstd { level: 3 }),
    ];
    let sizes = [49_usize, 4 * 1024, 256 * 1024, 1024 * 1024];

    for (name, algorithm) in algorithms {
        let mut group = criterion.benchmark_group(name);
        for size in sizes {
            let payload = (0..size)
                .map(|index| u8::try_from(index % 31).unwrap_or(0))
                .collect::<Vec<_>>();
            group.throughput(Throughput::Bytes(u64::try_from(size).unwrap_or(u64::MAX)));
            group.bench_with_input(
                BenchmarkId::new("encode", size),
                &payload,
                |bencher, input| {
                    bencher.iter_batched(
                        || codec_or_exit(algorithm),
                        |mut codec| black_box(encode_or_exit(&mut codec, black_box(input))),
                        BatchSize::SmallInput,
                    );
                },
            );

            let frame = encode_or_exit(&mut codec_or_exit(algorithm), &payload);
            group.bench_with_input(
                BenchmarkId::new("decode", size),
                &frame,
                |bencher, input| {
                    bencher.iter_batched(
                        || codec_or_exit(algorithm),
                        |mut codec| black_box(decode_or_exit(&mut codec, black_box(input))),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, compression_benchmarks);
criterion_main!(benches);
