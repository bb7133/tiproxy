use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub iterations: usize,
    pub total_bytes: usize,
    pub elapsed: Duration,
}

impl BenchmarkResult {
    pub fn throughput_bytes_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs == 0.0 {
            0.0
        } else {
            self.total_bytes as f64 / secs
        }
    }
}

pub fn run_packet_header_bench(iterations: usize) -> BenchmarkResult {
    let input = [0x12, 0x34, 0x00, 0x07];
    let start = Instant::now();
    let mut total = 0usize;
    for _ in 0..iterations {
        let hdr = crate::mysql_packet::PacketHeader::parse(&input).expect("parse header");
        let out = hdr.encode();
        total += out.len();
    }
    BenchmarkResult {
        iterations,
        total_bytes: total,
        elapsed: start.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::run_packet_header_bench;

    #[test]
    fn benchmark_smoke() {
        let result = run_packet_header_bench(1000);
        assert_eq!(result.iterations, 1000);
        assert_eq!(result.total_bytes, 4000);
    }
}
