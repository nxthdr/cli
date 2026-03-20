mod api;
mod auth;
mod config;
mod output;
mod peering;
mod probing;

use clap::{Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "nxthdr")]
#[command(about = "CLI tool to interact with nxthdr platform", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    #[arg(long, short = 'o', global = true, value_enum, default_value = "text", help = "Output format")]
    output: output::OutputFormat,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Login to nxthdr platform")]
    Login,
    #[command(about = "Logout from nxthdr platform")]
    Logout,
    #[command(about = "Show authentication status")]
    Status,
    #[command(about = "Interact with peering platform")]
    Peering {
        #[command(subcommand)]
        command: PeeringCommands,
    },
    #[command(about = "Interact with probing platform")]
    Probing {
        #[command(subcommand)]
        command: ProbingCommands,
    },
}

#[derive(Subcommand)]
enum ProbingCommands {
    #[command(about = "Show your probing credits usage")]
    Credits,
    #[command(about = "List available probing agents")]
    Agents,
    #[command(about = "Query replies from ClickHouse")]
    Results {
        #[arg(long, help = "Source IP(s) to filter by", required = true, num_args = 1..)]
        src_ip: Vec<String>,
        #[arg(long, help = "Start of time window (e.g. '2026-03-19 21:00:00')")]
        since: Option<String>,
        #[arg(long, help = "End of time window (e.g. '2026-03-19 22:00:00')")]
        until: Option<String>,
    },
    #[command(
        about = "Send probes from one or more agents",
        long_about = "Send probes read from a file or stdin.\n\nEach line must be: dst_addr,src_port,dst_port,ttl,protocol\nProtocol is 'icmpv6' or 'udp' (case-insensitive).\n\nExamples:\n  nxthdr probing send --agent vltcdg01 probes.csv\n  prowl | nxthdr probing send --agent vltcdg01"
    )]
    Send {
        #[arg(help = "Input file with probes (reads from stdin if omitted)")]
        file: Option<std::path::PathBuf>,
        #[arg(short, long, help = "Agent ID(s) to use", required = true)]
        agent: Vec<String>,
        #[arg(long, help = "Override source IPv6 address (auto-detected per agent if not set)")]
        src_ip: Option<String>,
    },
}

#[derive(Subcommand)]
enum PeeringCommands {
    #[command(about = "Get your ASN")]
    Asn,
    #[command(about = "Manage prefix leases")]
    Prefix {
        #[command(subcommand)]
        command: PrefixCommands,
    },
    #[command(about = "PeerLab utilities")]
    Peerlab {
        #[command(subcommand)]
        command: PeerlabCommands,
    },
}

#[derive(Subcommand)]
enum PeerlabCommands {
    #[command(about = "Generate .env file for PeerLab")]
    Env,
}

#[derive(Subcommand)]
enum PrefixCommands {
    #[command(about = "List your active prefix leases")]
    List,
    #[command(about = "Request a new prefix lease")]
    Request {
        #[arg(value_name = "HOURS", help = "Lease duration in hours (1-24)")]
        duration: u32,
    },
    #[command(about = "Revoke a prefix lease")]
    Revoke {
        #[arg(help = "Prefix to revoke (e.g., 2001:db8::/48)")]
        prefix: String,
    },
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    output::set_format(cli.output);
    tracing_subscriber::fmt().with_max_level(cli.verbose).init();

    match cli.command {
        Commands::Login => handle_login().await?,
        Commands::Logout => handle_logout()?,
        Commands::Status => handle_status()?,
        Commands::Peering { command } => handle_peering(command).await?,
        Commands::Probing { command } => handle_probing(command).await?,
    }

    Ok(())
}

async fn handle_probing(command: ProbingCommands) -> anyhow::Result<()> {
    match command {
        ProbingCommands::Credits => probing::credits().await,
        ProbingCommands::Agents => probing::agents().await,
        ProbingCommands::Send { file, agent, src_ip } => probing::send(file, agent, src_ip).await,
        ProbingCommands::Results { src_ip, since, until } => probing::results(src_ip, since, until).await,
    }
}

async fn handle_peering(command: PeeringCommands) -> anyhow::Result<()> {
    match command {
        PeeringCommands::Asn => peering::asn().await,
        PeeringCommands::Prefix { command } => match command {
            PrefixCommands::List => peering::prefix_list().await,
            PrefixCommands::Request { duration } => peering::prefix_request(duration).await,
            PrefixCommands::Revoke { prefix } => peering::prefix_revoke(&prefix).await,
        },
        PeeringCommands::Peerlab { command } => match command {
            PeerlabCommands::Env => peering::peerlab_env().await,
        },
    }
}

async fn handle_login() -> anyhow::Result<()> {
    if config::tokens_exist() {
        let tokens = config::load_tokens()?;

        if tokens.expires_at >= now_secs() {
            output::kv(&[("auth", "already logged in")]);
            output::hint("nxthdr logout  # to switch accounts");
            return Ok(());
        }

        if tokens.refresh_token.is_empty() {
            anyhow::bail!("access token expired and no refresh token available — run 'nxthdr logout' then 'nxthdr login'");
        }

        output::info("refreshing token...");
        let (access_token, refresh_token, expires_at) = auth::refresh_access_token(&tokens.refresh_token)
            .await
            .map_err(|e| anyhow::anyhow!("failed to refresh token: {e} — run 'nxthdr logout' then 'nxthdr login'"))?;
        config::save_tokens(&config::TokenStorage { access_token, refresh_token, expires_at })?;
        output::success("token refreshed");
        return Ok(());
    }

    let device_code = auth::start_device_flow().await?;

    output::info("open the following URL to authenticate:");
    output::info(&format!("\n  {}\n", device_code.verification_uri_complete));
    output::info(&format!("or go to {} and enter code: {}\n", device_code.verification_uri, device_code.user_code));
    output::info("waiting...");

    let (access_token, refresh_token, expires_at) =
        auth::poll_for_token(&device_code.device_code, device_code.interval).await?;

    config::save_tokens(&config::TokenStorage { access_token, refresh_token, expires_at })?;
    output::success("authenticated");

    Ok(())
}

fn handle_logout() -> anyhow::Result<()> {
    if !config::tokens_exist() {
        output::info("not logged in");
        return Ok(());
    }
    config::delete_tokens()?;
    output::success("logged out");
    Ok(())
}

fn handle_status() -> anyhow::Result<()> {
    output::section("status");

    if !config::tokens_exist() {
        output::kv(&[("auth", "not logged in")]);
        output::hint("nxthdr login");
        return Ok(());
    }

    let tokens = config::load_tokens()?;
    let now = now_secs();

    if tokens.expires_at < now {
        output::kv(&[("auth", "logged in"), ("token", "expired")]);
        output::hint("nxthdr login  # to refresh");
    } else {
        let secs = tokens.expires_at - now;
        let expiry = format!("valid {}h {}m", secs / 3600, (secs % 3600) / 60);
        output::kv(&[("auth", "logged in"), ("token", &expiry)]);
    }

    Ok(())
}
