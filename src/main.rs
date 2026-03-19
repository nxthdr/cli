mod api;
mod auth;
mod config;
mod output;

use anyhow::Context;
use clap::{Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};
use serde::{Deserialize, Serialize};
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

/// Generate 48 random bits to use as the host part of a /80 source address.
/// All agents in a measurement share the same value so the replies are
/// identifiable as a group without any server-side state.
fn random_host_48() -> u64 {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let p = std::process::id() as u64;
    let mut x = t ^ (p.wrapping_mul(0x9e3779b97f4a7c15));
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x & 0x0000_ffff_ffff_ffff // 48 bits
}

/// Derive a source IP by replacing the host bits of a /80 prefix with `host48`.
fn src_ip_from_prefix(user_prefix: &str, host48: u64) -> anyhow::Result<String> {
    use std::net::Ipv6Addr;
    use std::str::FromStr;
    let (addr_str, len_str) = user_prefix.split_once('/').unwrap_or((user_prefix, "128"));
    let prefix_len: u32 = len_str.parse()?;
    let base = u128::from(Ipv6Addr::from_str(addr_str)?);
    let host_bits = 128u32.saturating_sub(prefix_len);
    let host_mask: u128 = if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
    let host = (host48 as u128).max(1) & host_mask;
    Ok(Ipv6Addr::from((base & !host_mask) | host).to_string())
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
        ProbingCommands::Credits => handle_probing_credits().await,
        ProbingCommands::Agents => handle_probing_agents().await,
        ProbingCommands::Send { file, agent, src_ip } => handle_probing_send(file, agent, src_ip).await,
        ProbingCommands::Results { src_ip, since, until } => handle_probing_results(src_ip, since, until).await,
    }
}

async fn handle_peering(command: PeeringCommands) -> anyhow::Result<()> {
    match command {
        PeeringCommands::Asn => handle_asn_get().await,
        PeeringCommands::Prefix { command } => match command {
            PrefixCommands::List => handle_prefix_list().await,
            PrefixCommands::Request { duration } => handle_prefix_request(duration).await,
            PrefixCommands::Revoke { prefix } => handle_prefix_revoke(&prefix).await,
        },
        PeeringCommands::Peerlab { command } => match command {
            PeerlabCommands::Env => handle_peerlab_env().await,
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

async fn handle_probing_credits() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct UserUsage {
        used: u32,
        limit: u32,
    }

    let usage: UserUsage = api::ApiClient::new_saimiris().get("/api/user/me").await?;
    let remaining = usage.limit.saturating_sub(usage.used);

    output::section("credits");
    output::kv(&[
        ("used", &usage.used.to_string()),
        ("limit", &usage.limit.to_string()),
        ("remaining", &remaining.to_string()),
    ]);

    if usage.used >= usage.limit {
        output::warn("daily limit reached — resets at midnight UTC");
    }

    Ok(())
}

async fn handle_probing_agents() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct AgentHealth {
        healthy: bool,
    }

    #[derive(Deserialize)]
    struct AgentConfig {
        name: Option<String>,
        src_ipv6_prefix: Option<String>,
    }

    #[derive(Deserialize)]
    struct Agent {
        id: String,
        config: Option<Vec<AgentConfig>>,
        health: Option<AgentHealth>,
    }

    let agents: Vec<Agent> = api::ApiClient::new_saimiris().get_public("/api/agents").await?;

    if agents.is_empty() {
        if output::is_json() { println!("[]"); } else { output::info("no agents available"); }
        return Ok(());
    }

    let rows: Vec<Vec<String>> = agents.iter().map(|agent| {
        let status = match &agent.health {
            Some(h) if h.healthy => "healthy",
            Some(_) => "unhealthy",
            None => "unknown",
        };
        let prefixes: Vec<String> = agent.config.as_deref().unwrap_or(&[]).iter()
            .filter_map(|c| {
                let prefix = c.src_ipv6_prefix.as_deref()?;
                let name = c.name.as_deref().unwrap_or("default");
                Some(format!("{prefix} ({name})"))
            })
            .collect();
        vec![
            agent.id.clone(),
            status.to_string(),
            if prefixes.is_empty() { "-".to_string() } else { prefixes.join(", ") },
        ]
    }).collect();

    output::table(&["id", "status", "prefixes"], &rows);

    Ok(())
}

async fn handle_probing_send(
    file: Option<std::path::PathBuf>,
    agent_ids: Vec<String>,
    src_ip: Option<String>,
) -> anyhow::Result<()> {
    use serde_json::{Value, json};
    use std::io::BufRead;

    #[derive(Deserialize)]
    struct UserPrefixEntry {
        user_prefix: String,
    }

    #[derive(Deserialize)]
    struct AgentPrefixes {
        agent_id: String,
        prefixes: Vec<UserPrefixEntry>,
    }

    #[derive(Deserialize)]
    struct UserPrefixesResponse {
        agents: Vec<AgentPrefixes>,
    }

    #[derive(Serialize)]
    struct AgentMetadata {
        id: String,
        ip_address: String,
    }

    #[derive(Serialize)]
    struct SubmitProbesRequest {
        metadata: Vec<AgentMetadata>,
        probes: Vec<Value>,
    }

    #[derive(Deserialize)]
    struct SubmitProbesResponse {
        id: String,
    }

    let reader: Box<dyn BufRead> = match file {
        Some(ref path) => Box::new(std::io::BufReader::new(
            std::fs::File::open(path).with_context(|| format!("Failed to open '{}'", path.display()))?,
        )),
        None => Box::new(std::io::BufReader::new(std::io::stdin())),
    };

    let mut probes: Vec<Value> = Vec::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.context("Failed to read input")?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, ',').collect();
        if parts.len() != 5 {
            anyhow::bail!(
                "Line {}: expected 5 comma-separated fields (dst_addr,src_port,dst_port,ttl,protocol), got: {:?}",
                lineno + 1, line
            );
        }
        let dst_addr = parts[0].trim();
        let src_port: u16 = parts[1].trim().parse().with_context(|| format!("Line {}: invalid src_port", lineno + 1))?;
        let dst_port: u16 = parts[2].trim().parse().with_context(|| format!("Line {}: invalid dst_port", lineno + 1))?;
        let ttl: u8 = parts[3].trim().parse().with_context(|| format!("Line {}: invalid ttl", lineno + 1))?;
        let protocol = parts[4].trim().to_lowercase();
        probes.push(json!([dst_addr, src_port, dst_port, ttl, protocol]));
    }

    anyhow::ensure!(!probes.is_empty(), "No probes found in input");

    let client = api::ApiClient::new_saimiris();
    let user_prefixes: UserPrefixesResponse = client.get("/api/user/prefixes").await?;

    // One shared random host part for all agents so all source IPs share the
    // same 48-bit identifier and can be queried together.
    let host48 = random_host_48();

    let mut metadata: Vec<AgentMetadata> = Vec::new();
    for agent_id in &agent_ids {
        let ip = if let Some(ref ip) = src_ip {
            ip.clone()
        } else {
            let agent_entry = user_prefixes.agents.iter()
                .find(|a| &a.agent_id == agent_id)
                .ok_or_else(|| anyhow::anyhow!(
                    "No prefix allocated for agent '{agent_id}'. Run 'nxthdr probing agents' to see available agents."
                ))?;
            let user_prefix = &agent_entry.prefixes.first()
                .ok_or_else(|| anyhow::anyhow!("Agent '{agent_id}' has no configured prefix"))?
                .user_prefix;
            let derived = src_ip_from_prefix(user_prefix, host48)?;
            tracing::debug!("agent {agent_id} user_prefix={user_prefix} derived src={derived}");
            derived
        };
        tracing::debug!("agent {agent_id} using src_ip={ip}");
        metadata.push(AgentMetadata { id: agent_id.clone(), ip_address: ip });
    }

    let probe_count = probes.len();
    // Capture (id, ip) pairs before metadata is moved into the request body.
    let agent_src: Vec<(String, String)> = metadata.iter()
        .map(|m| (m.id.clone(), m.ip_address.clone()))
        .collect();

    let response: SubmitProbesResponse = client
        .post("/api/probes", &SubmitProbesRequest { metadata, probes })
        .await?;

    let agents_label = format!("{probe_count} × {} agent{}", agent_ids.len(), if agent_ids.len() == 1 { "" } else { "s" });
    let mut pairs: Vec<(&str, &str)> = vec![("id", &response.id), ("probes", &agents_label)];
    for (agent, ip) in &agent_src {
        pairs.push((agent.as_str(), ip.as_str()));
    }
    output::success("measurement submitted");
    output::kv(&pairs);

    let hint = agent_src.iter().map(|(_, ip)| format!("--src-ip {ip}")).collect::<Vec<_>>().join(" ");
    output::hint(&format!("nxthdr probing results {hint}"));

    Ok(())
}

async fn query_clickhouse(sql: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let resp = reqwest::Client::new()
        .post("https://clickhouse.nxthdr.dev/?user=read&password=read")
        .header("Content-Type", "text/plain")
        .body(format!("{sql} FORMAT JSONEachRow"))
        .send()
        .await
        .context("Failed to connect to ClickHouse")?;

    if !resp.status().is_success() {
        anyhow::bail!("ClickHouse error {}: {}", resp.status(), resp.text().await.unwrap_or_default().trim());
    }

    let text = resp.text().await.context("Failed to read ClickHouse response")?;
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).context("Failed to parse ClickHouse row"))
        .collect()
}

async fn handle_probing_results(
    src_ips: Vec<String>,
    since: Option<String>,
    until: Option<String>,
) -> anyhow::Result<()> {
    let in_clause = src_ips.iter().map(|ip| format!("'{ip}'")).collect::<Vec<_>>().join(", ");
    let mut conditions = format!("probe_src_addr IN ({in_clause})");
    if let Some(ref s) = since {
        conditions.push_str(&format!(" AND time_received_ns >= parseDateTimeBestEffort('{s}')"));
    }
    if let Some(ref u) = until {
        conditions.push_str(&format!(" AND time_received_ns <= parseDateTimeBestEffort('{u}')"));
    }

    let sql = format!(
        "SELECT agent_id, probe_src_addr, probe_dst_addr, probe_ttl, reply_src_addr, rtt \
         FROM saimiris.replies WHERE {conditions} \
         ORDER BY agent_id, probe_src_addr, probe_dst_addr, probe_ttl"
    );

    let rows = query_clickhouse(&sql).await?;

    if rows.is_empty() {
        if output::is_json() { println!("[]"); } else { output::info(&format!("no replies found for {}", src_ips.join(", "))); }
        return Ok(());
    }

    let data: Vec<Vec<String>> = rows.iter().map(|row| vec![
        row["agent_id"].as_str().unwrap_or("-").to_string(),
        row["probe_src_addr"].as_str().unwrap_or("-").to_string(),
        row["probe_dst_addr"].as_str().unwrap_or("-").to_string(),
        row["probe_ttl"].as_u64().unwrap_or(0).to_string(),
        row["reply_src_addr"].as_str().unwrap_or("-").to_string(),
        format!("{:.2}ms", row["rtt"].as_u64().unwrap_or(0) as f64 / 1000.0),
    ]).collect();

    output::table(&["agent", "src", "dst", "ttl", "reply", "rtt"], &data);

    Ok(())
}

async fn handle_asn_get() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct UserInfo {
        asn: Option<i32>,
    }

    let user_info: UserInfo = api::ApiClient::new().get("/api/user/info").await?;

    output::section("asn");
    if let Some(asn) = user_info.asn {
        output::kv(&[("asn", &asn.to_string())]);
    } else {
        output::kv(&[("asn", "none")]);
        output::hint("nxthdr peering prefix request <hours>  # triggers ASN assignment");
    }

    Ok(())
}

async fn handle_prefix_list() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct PrefixLease {
        prefix: String,
        end_time: String,
    }

    #[derive(Deserialize)]
    struct UserInfo {
        active_leases: Vec<PrefixLease>,
    }

    let user_info: UserInfo = api::ApiClient::new().get("/api/user/info").await?;

    if user_info.active_leases.is_empty() {
        if output::is_json() { println!("[]"); } else {
            output::info("no active prefix leases");
            output::hint("nxthdr peering prefix request <hours>");
        }
        return Ok(());
    }

    let rows: Vec<Vec<String>> = user_info.active_leases.iter()
        .map(|l| vec![l.prefix.clone(), l.end_time.clone()])
        .collect();
    output::table(&["prefix", "expires"], &rows);

    Ok(())
}

async fn handle_prefix_request(duration: u32) -> anyhow::Result<()> {
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

    let response: PrefixResponse = api::ApiClient::new()
        .post("/api/user/prefix", &PrefixRequest { duration_hours: duration })
        .await?;

    output::success(&response.message);
    output::kv(&[("prefix", &response.prefix), ("expires", &response.end_time)]);
    output::hint("nxthdr peering prefix list");

    Ok(())
}

async fn handle_prefix_revoke(prefix: &str) -> anyhow::Result<()> {
    api::ApiClient::new()
        .delete(&format!("/api/user/prefix/{}", urlencoding::encode(prefix)))
        .await?;
    output::success("prefix lease revoked");
    Ok(())
}

async fn handle_peerlab_env() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct PrefixLease {
        prefix: String,
    }

    #[derive(Deserialize)]
    struct UserInfo {
        asn: Option<i32>,
        active_leases: Vec<PrefixLease>,
    }

    let user_info: UserInfo = api::ApiClient::new().get("/api/user/info").await?;

    let asn = match user_info.asn {
        Some(asn) => asn,
        None => {
            eprintln!("# Warning: No ASN assigned yet. Using placeholder value.");
            eprintln!("# An ASN will be automatically assigned on first use.");
            64512
        }
    };

    let prefixes = user_info.active_leases.iter()
        .map(|l| l.prefix.as_str())
        .collect::<Vec<_>>()
        .join(",");

    println!("# PeerLab User Configuration");
    println!();
    println!("# Your ASN (use a private ASN from the range 64512-65534)");
    println!("USER_ASN={asn}");
    println!();
    println!("# IPv6 prefixes to advertise (comma-separated list)");
    println!("# Examples:");
    println!("#   Single prefix:  USER_PREFIXES=2001:db8:1234::/48");
    println!("#   Multiple:       USER_PREFIXES=2001:db8:1234::/48,2001:db8:5678::/48");
    println!("# Leave empty to not advertise any prefixes (receive-only mode)");
    println!("USER_PREFIXES={prefixes}");
    println!();

    Ok(())
}
