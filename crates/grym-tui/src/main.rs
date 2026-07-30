#![deny(unsafe_code)]

use anyhow::Result;
use clap::Parser;

/// GRYM TUI — real-time scan dashboard and control interface.
#[derive(Debug, Parser)]
#[command(name = "grym-tui", version, about)]
struct Args {
    /// Path to scope configuration file.
    #[arg(short, long, default_value = "config/scope.toml")]
    scope: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _args = Args::parse();
    grym_tui::run().await
}
