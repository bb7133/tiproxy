mod benchmark;
mod handshake;
mod mysql_packet;
mod proxy;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "mysql-proxy-poc")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:6000")]
    listen: String,

    #[arg(long, default_value = "127.0.0.1:4000")]
    backend: String,

    /// Run a tiny local benchmark instead of starting the proxy.
    #[arg(long, default_value_t = false)]
    bench: bool,

    #[arg(long, default_value_t = 1_000_000)]
    bench_iterations: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    if args.bench {
        let result = benchmark::run_packet_header_bench(args.bench_iterations);
        println!(
            "packet-header-bench iterations={} total_bytes={} elapsed_ms={} throughput_bytes_per_sec={:.2}",
            result.iterations,
            result.total_bytes,
            result.elapsed.as_millis(),
            result.throughput_bytes_per_sec(),
        );
        return Ok(());
    }

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(listen = %args.listen, backend = %args.backend, "mysql packet-aware proxy poc listening");

    loop {
        let (frontend, peer) = listener.accept().await?;
        let backend_addr = args.backend.clone();
        tokio::spawn(async move {
            match TcpStream::connect(&backend_addr).await {
                Ok(backend) => {
                    if let Err(err) = proxy::forward_mysql_packets(frontend, backend).await {
                        error!(peer = %peer, error = %err, "connection failed");
                    }
                }
                Err(err) => {
                    error!(peer = %peer, backend = %backend_addr, error = %err, "backend connect failed");
                }
            }
        });
    }
}
