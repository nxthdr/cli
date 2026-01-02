use clap::{Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};

#[derive(Parser)]
#[command(name = "nxthdr")]
#[command(about = "CLI tool to interact with nxthdr platform", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Interact with peering platform")]
    Peering,
    #[command(about = "Interact with probing platform")]
    Probing,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(cli.verbose)
        .init();

    match cli.command {
        Commands::Peering => {
            println!("Peering command not yet implemented");
        }
        Commands::Probing => {
            println!("Probing command not yet implemented");
        }
    }

    Ok(())
}
