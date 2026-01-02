mod api;
mod auth;
mod config;

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
    Probing,
}

#[derive(Subcommand)]
enum PeeringCommands {
    #[command(about = "Manage ASN")]
    Asn {
        #[command(subcommand)]
        command: AsnCommands,
    },
    #[command(about = "Manage prefix leases")]
    Prefix {
        #[command(subcommand)]
        command: PrefixCommands,
    },
}

#[derive(Subcommand)]
enum AsnCommands {
    #[command(about = "Get your ASN information")]
    Get,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt().with_max_level(cli.verbose).init();

    match cli.command {
        Commands::Login => {
            handle_login().await?;
        }
        Commands::Logout => {
            handle_logout()?;
        }
        Commands::Status => {
            handle_status()?;
        }
        Commands::Peering { command } => {
            handle_peering(command).await?;
        }
        Commands::Probing => {
            println!("Probing command not yet implemented");
        }
    }

    Ok(())
}

async fn handle_peering(command: PeeringCommands) -> anyhow::Result<()> {
    match command {
        PeeringCommands::Asn { command } => match command {
            AsnCommands::Get => {
                handle_asn_get().await?;
            }
        },
        PeeringCommands::Prefix { command } => match command {
            PrefixCommands::List => {
                handle_prefix_list().await?;
            }
            PrefixCommands::Request { duration } => {
                handle_prefix_request(duration).await?;
            }
            PrefixCommands::Revoke { prefix } => {
                handle_prefix_revoke(&prefix).await?;
            }
        },
    }
    Ok(())
}

async fn handle_asn_get() -> anyhow::Result<()> {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct UserInfo {
        asn: Option<i32>,
    }

    let client = api::ApiClient::new();
    let user_info: UserInfo = client.get("/api/user/info").await?;

    if let Some(asn) = user_info.asn {
        println!("{}", asn);
    } else {
        println!("No ASN assigned yet. An ASN will be automatically assigned on first use.");
    }

    Ok(())
}

async fn handle_prefix_list() -> anyhow::Result<()> {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct PrefixLease {
        prefix: String,
        end_time: String,
    }

    #[derive(Deserialize)]
    struct UserInfo {
        active_leases: Vec<PrefixLease>,
    }

    let client = api::ApiClient::new();
    let user_info: UserInfo = client.get("/api/user/info").await?;

    if user_info.active_leases.is_empty() {
        println!("No active prefix leases.");
        println!("Run 'nxthdr peering prefix request <duration>' to request a prefix.");
    } else {
        println!("Active prefix leases:");
        for lease in user_info.active_leases {
            println!("  {} (expires: {})", lease.prefix, lease.end_time);
        }
    }

    Ok(())
}

async fn handle_prefix_request(duration: u32) -> anyhow::Result<()> {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize)]
    struct PrefixRequest {
        duration_hours: u32,
    }

    #[derive(Deserialize)]
    struct PrefixResponse {
        prefix: String,
        end_time: String,
        message: String,
    }

    let client = api::ApiClient::new();
    let response: PrefixResponse = client
        .post(
            "/api/user/prefix",
            &PrefixRequest {
                duration_hours: duration,
            },
        )
        .await?;

    println!("✓ {}", response.message);
    println!("Prefix: {}", response.prefix);
    println!("Valid until: {}", response.end_time);

    Ok(())
}

async fn handle_prefix_revoke(prefix: &str) -> anyhow::Result<()> {
    let client = api::ApiClient::new();
    let encoded_prefix = urlencoding::encode(prefix);
    let path = format!("/api/user/prefix/{}", encoded_prefix);
    client.delete(&path).await?;

    println!("✓ Prefix lease revoked successfully");

    Ok(())
}

async fn handle_login() -> anyhow::Result<()> {
    if config::tokens_exist() {
        println!(
            "You are already logged in. Run 'nxthdr logout' first if you want to login again."
        );
        return Ok(());
    }

    println!("Starting authentication...\n");

    let device_code = auth::start_device_flow().await?;

    println!("Please visit the following URL to authenticate:");
    println!("\n  {}\n", device_code.verification_uri_complete);
    println!(
        "Or go to {} and enter code: {}",
        device_code.verification_uri, device_code.user_code
    );
    println!("\nWaiting for authentication...");

    let (access_token, refresh_token, expires_at) =
        auth::poll_for_token(&device_code.device_code, device_code.interval).await?;

    let tokens = config::TokenStorage {
        access_token,
        refresh_token,
        expires_at,
    };

    config::save_tokens(&tokens)?;

    println!("\n✓ Successfully authenticated!");
    println!("Tokens saved to: {:?}", config::get_token_path()?);

    Ok(())
}

fn handle_logout() -> anyhow::Result<()> {
    if !config::tokens_exist() {
        println!("You are not logged in.");
        return Ok(());
    }

    config::delete_tokens()?;
    println!("✓ Successfully logged out.");

    Ok(())
}

fn handle_status() -> anyhow::Result<()> {
    if !config::tokens_exist() {
        println!("Status: Not logged in");
        println!("\nRun 'nxthdr login' to authenticate.");
        return Ok(());
    }

    let tokens = config::load_tokens()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let is_expired = tokens.expires_at < now;
    let time_until_expiry = tokens.expires_at - now;

    println!("Status: Logged in");
    println!("Token path: {:?}", config::get_token_path()?);

    if is_expired {
        println!("Access token: Expired");
        println!(
            "\nYour access token has expired. It will be automatically refreshed on next API call."
        );
    } else {
        let hours = time_until_expiry / 3600;
        let minutes = (time_until_expiry % 3600) / 60;
        println!("Access token: Valid for {}h {}m", hours, minutes);
    }

    Ok(())
}
