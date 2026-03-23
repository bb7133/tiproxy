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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
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
