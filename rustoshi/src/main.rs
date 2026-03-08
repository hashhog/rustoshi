use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rustoshi", version, about = "A Bitcoin full node in Rust")]
struct Cli {
    /// Network to connect to
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Data directory
    #[arg(long, default_value = "~/.rustoshi")]
    datadir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    tracing::info!("Starting rustoshi on {}", cli.network);
    Ok(())
}
