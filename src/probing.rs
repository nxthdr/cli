use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{api, output};

pub async fn credits() -> anyhow::Result<()> {
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

pub async fn agents() -> anyhow::Result<()> {
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

pub async fn send(
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

pub async fn results(
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

/// Generate 48 random bits to use as the host part of a /80 source address.
/// All agents in a measurement share the same value so the replies are
/// identifiable as a group without any server-side state.
fn random_host_48() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
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
