use serde::{Deserialize, Serialize};

use crate::{api, output, ris};

pub async fn asn() -> anyhow::Result<()> {
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

pub async fn prefix_list() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct PrefixLease {
        prefix: String,
        end_time: String,
        #[serde(default)]
        rpki_enabled: bool,
    }

    #[derive(Deserialize)]
    struct UserInfo {
        active_leases: Vec<PrefixLease>,
    }

    let user_info: UserInfo = api::ApiClient::new().get("/api/user/info").await?;

    if user_info.active_leases.is_empty() {
        if !output::empty(&["prefix", "expires", "rpki"]) {
            output::info("no active prefix leases");
            output::hint("nxthdr peering prefix request <hours>");
        }
        return Ok(());
    }

    let rows: Vec<Vec<String>> = user_info.active_leases.iter()
        .map(|l| vec![
            l.prefix.clone(),
            l.end_time.clone(),
            if l.rpki_enabled { "enabled".to_string() } else { "disabled".to_string() },
        ])
        .collect();
    output::table(&["prefix", "expires", "rpki"], &rows);

    Ok(())
}

pub async fn prefix_request(duration: u32) -> anyhow::Result<()> {
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

pub async fn prefix_revoke(prefix: &str) -> anyhow::Result<()> {
    api::ApiClient::new()
        .delete(&format!("/api/user/prefix/{}", urlencoding::encode(prefix)))
        .await?;
    output::success("prefix lease revoked");
    Ok(())
}

pub async fn prefix_rpki(prefix: &str, enabled: bool) -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct SetRpkiRequest {
        enabled: bool,
    }

    #[derive(Deserialize)]
    struct SetRpkiResponse {
        rpki_enabled: bool,
        message: String,
    }

    let response: SetRpkiResponse = api::ApiClient::new()
        .put(
            &format!("/api/user/prefix/{}/rpki", urlencoding::encode(prefix)),
            &SetRpkiRequest { enabled },
        )
        .await?;

    output::success(&response.message);
    output::kv(&[
        ("prefix", prefix),
        ("rpki", if response.rpki_enabled { "enabled" } else { "disabled" }),
    ]);

    Ok(())
}

pub async fn peerlab_env() -> anyhow::Result<()> {
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

pub async fn routes() -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct PrefixLease {
        prefix: String,
    }

    #[derive(Deserialize)]
    struct UserInfo {
        active_leases: Vec<PrefixLease>,
    }

    let user_info: UserInfo = api::ApiClient::new().get("/api/user/info").await?;

    if user_info.active_leases.is_empty() {
        if !output::empty(&[
            "prefix",
            "visible",
            "propagation",
            "collectors",
            "peers",
            "origin",
            "shortest path",
        ]) {
            output::info("no active prefix leases — nothing to announce");
            output::hint("nxthdr peering prefix request <hours>");
        }
        return Ok(());
    }

    let full_feed = ris::full_feed_peers().await.ok();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut any_invisible = false;
    let mut as_of: Option<String> = None;
    for lease in &user_info.active_leases {
        let vis = ris::looking_glass(&lease.prefix).await?;
        let visible = vis.is_visible();
        any_invisible |= !visible;
        as_of = as_of.or_else(|| vis.query_time.clone());
        let origins = vis.origins();
        let propagation = full_feed
            .as_ref()
            .and_then(|ff| ris::propagation_pct(vis.peer_count(), ff.for_resource(&lease.prefix)))
            .map(|p| format!("{p}%"))
            .unwrap_or_else(|| "-".to_string());
        rows.push(vec![
            lease.prefix.clone(),
            if visible { "yes".to_string() } else { "no".to_string() },
            propagation,
            vis.collector_count().to_string(),
            vis.peer_count().to_string(),
            if origins.is_empty() { "-".to_string() } else { origins.join(", ") },
            vis.shortest_path().unwrap_or_else(|| "-".to_string()),
        ]);
    }

    output::table(
        &["prefix", "visible", "propagation", "collectors", "peers", "origin", "shortest path"],
        &rows,
    );

    if output::is_text() {
        let suffix = as_of.map(|t| format!(" (as of {t})")).unwrap_or_default();
        // AS215011 is PeerLab's export ASN; user (private) ASNs are stripped on export.
        output::info(&format!(
            "\nseen by public BGP collectors (RIPE RIS){suffix}; origin is AS215011 — your ASN is stripped on export"
        ));
        if any_invisible {
            output::hint("not visible? new announcements take a few minutes to propagate — re-run shortly");
        }
    }

    Ok(())
}

pub async fn lookup(prefix: &str) -> anyhow::Result<()> {
    let vis = ris::looking_glass(prefix).await?;

    if !vis.is_visible() {
        if !output::empty(&["origin", "as_path", "peers", "collectors"]) {
            output::info(&format!("{prefix} is not visible in any RIPE RIS collector"));
        }
        return Ok(());
    }

    if output::is_text() {
        let origins = vis.origins();
        let origin_str = if origins.is_empty() { "-".to_string() } else { origins.join(", ") };
        let collectors = vis.collector_count().to_string();
        let peers = vis.peer_count().to_string();
        let propagation = ris::full_feed_peers()
            .await
            .ok()
            .and_then(|ff| {
                let total = ff.for_resource(prefix);
                ris::propagation_pct(vis.peer_count(), total).map(|p| format!("{p}% of {total} full-feed RIS peers"))
            });
        output::section(&format!("looking glass: {prefix}"));
        let mut pairs: Vec<(&str, &str)> = vec![
            ("collectors", &collectors),
            ("peers", &peers),
            ("origin", &origin_str),
        ];
        if let Some(ref p) = propagation {
            pairs.push(("propagation", p));
        }
        if let Some(ref t) = vis.query_time {
            pairs.push(("as of", t));
        }
        output::kv(&pairs);
        println!();
    }

    let paths = vis.paths();
    // Machine formats (JSON/CSV) emit every path; the terminal table is capped.
    let shown = if output::is_text() { paths.len().min(20) } else { paths.len() };
    let rows: Vec<Vec<String>> = paths
        .iter()
        .take(shown)
        .map(|p| {
            vec![
                p.origin.clone(),
                p.as_path.clone(),
                p.peers.to_string(),
                p.collectors.to_string(),
            ]
        })
        .collect();

    output::table(&["origin", "as_path", "peers", "collectors"], &rows);

    if output::is_text() && paths.len() > shown {
        output::info(&format!("\n… and {} more distinct paths", paths.len() - shown));
    }

    Ok(())
}
