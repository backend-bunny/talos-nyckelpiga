use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Talos Linux KMS server backed by OpenBao transit.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Configuration file (TOML). Keys can be overridden with
    /// NYCKELPIGA_<TABLE>__<KEY> environment variables.
    #[arg(
        long,
        env = "NYCKELPIGA_CONFIG",
        default_value = "/etc/talos-nyckelpiga/config.toml"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // JSON logs; RUST_LOG overrides the level (default info).
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let result = async {
        let config = talos_nyckelpiga::config::Config::load(&args.config)?;
        talos_nyckelpiga::run(config, shutdown_signal()).await
    }
    .await;
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "fatal");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("shutting down");
}
