use serde::{Deserialize, Serialize};

use crate::{api, output};

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
        if output::is_json() { println!("[]"); } else {
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
