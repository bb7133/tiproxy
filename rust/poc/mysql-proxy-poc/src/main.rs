mod mysql_packet;
use anyhow::{Context, Result};
use clap::Parser;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "mysql-proxy-poc")]
struct Args {
    /// Listen address for the PoC proxy.
    #[arg(long, default_value = "127.0.0.1:6000")]
    listen: String,

    /// Backend address to forward traffic to.
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

    info!(listen = %args.listen, backend = %args.backend, "mysql proxy poc listening");

    loop {
        let (frontend, peer) = listener.accept().await?;
        let backend_addr = args.backend.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_conn(frontend, &backend_addr).await {
                error!(peer = %peer, error = %err, "connection failed");
            }
        });
    }
}

async fn handle_conn(frontend: TcpStream, backend_addr: &str) -> Result<()> {
    let backend = TcpStream::connect(backend_addr)
        .await
        .with_context(|| format!("failed to connect backend {}", backend_addr))?;

    let (mut fr, mut fw) = frontend.into_split();
    let (mut br, mut bw) = backend.into_split();

    let client_to_backend = tokio::spawn(async move { io::copy(&mut fr, &mut bw).await });
    let backend_to_client = tokio::spawn(async move { io::copy(&mut br, &mut fw).await });

    let (a, b) = tokio::join!(client_to_backend, backend_to_client);
    let _ = a??;
    let _ = b??;
    Ok(())
}
