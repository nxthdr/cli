use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::Deserialize;

const DEFAULT_RIS_URL: &str = "https://stat.ripe.net";

#[derive(Deserialize)]
struct Envelope {
    data: LgData,
}

#[derive(Deserialize)]
struct LgData {
    #[serde(default)]
    rrcs: Vec<Rrc>,
    #[serde(default)]
    query_time: Option<String>,
}

#[derive(Deserialize)]
struct Rrc {
    #[serde(default)]
    rrc: String,
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Deserialize)]
struct Peer {
    #[serde(default)]
    asn_origin: String,
    #[serde(default)]
    as_path: String,
}

/// One distinct AS path observed for a resource, with how widely it is seen.
pub struct PathStat {
    pub origin: String,
    pub as_path: String,
    pub peers: usize,
    pub collectors: usize,
}

/// Aggregated RIS looking-glass view of a single resource (prefix or IP).
pub struct Visibility {
    pub query_time: Option<String>,
    rrcs: Vec<Rrc>,
}

impl Visibility {
    /// Total number of RIS peers observing the resource.
    pub fn peer_count(&self) -> usize {
        self.rrcs.iter().map(|r| r.peers.len()).sum()
    }

    /// Number of route collectors (RRCs) with at least one peer seeing it.
    pub fn collector_count(&self) -> usize {
        self.rrcs.iter().filter(|r| !r.peers.is_empty()).count()
    }

    pub fn is_visible(&self) -> bool {
        self.peer_count() > 0
    }

    /// Distinct origin ASNs observed across all peers.
    pub fn origins(&self) -> Vec<String> {
        self.rrcs
            .iter()
            .flat_map(|r| r.peers.iter())
            .filter(|p| !p.asn_origin.is_empty())
            .map(|p| p.asn_origin.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The shortest AS path observed (fewest hops), if any.
    pub fn shortest_path(&self) -> Option<String> {
        self.rrcs
            .iter()
            .flat_map(|r| r.peers.iter())
            .map(|p| p.as_path.clone())
            .filter(|p| !p.is_empty())
            .min_by_key(|p| p.split_whitespace().count())
    }

    /// Distinct AS paths, each annotated with how many peers and collectors
    /// observe it, sorted by peer count (most-seen first).
    pub fn paths(&self) -> Vec<PathStat> {
        let mut map: BTreeMap<String, (String, usize, BTreeSet<String>)> = BTreeMap::new();
        for r in &self.rrcs {
            for p in &r.peers {
                if p.as_path.is_empty() {
                    continue;
                }
                let entry = map
                    .entry(p.as_path.clone())
                    .or_insert_with(|| (p.asn_origin.clone(), 0, BTreeSet::new()));
                entry.1 += 1;
                entry.2.insert(r.rrc.clone());
            }
        }
        let mut paths: Vec<PathStat> = map
            .into_iter()
            .map(|(as_path, (origin, peers, rrcs))| PathStat {
                origin,
                as_path,
                peers,
                collectors: rrcs.len(),
            })
            .collect();
        paths.sort_by(|a, b| {
            b.peers
                .cmp(&a.peers)
                .then_with(|| a.as_path.split_whitespace().count().cmp(&b.as_path.split_whitespace().count()))
        });
        paths
    }
}

/// Number of RIS peers carrying a full table (v4, v6). These "full-feed" peers
/// are the universe that should see any globally-propagated prefix, so they make
/// the natural denominator for a propagation percentage.
pub struct FullFeedPeers {
    pub v4: u64,
    pub v6: u64,
}

impl FullFeedPeers {
    /// Pick the denominator matching a resource's address family.
    pub fn for_resource(&self, resource: &str) -> u64 {
        if resource.contains(':') {
            self.v6
        } else {
            self.v4
        }
    }
}

/// Fetch the current count of full-feed RIS peers (v4 and v6) from RIPEstat's
/// lightweight ris-peer-count endpoint.
pub async fn full_feed_peers() -> Result<FullFeedPeers> {
    let base = std::env::var("NXTHDR_RIS_URL").unwrap_or_else(|_| DEFAULT_RIS_URL.to_string());
    let url = format!("{base}/data/ris-peer-count/data.json?sourceapp=nxthdr-cli");

    let resp = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "nxthdr-cli")
        .send()
        .await
        .context("Failed to query RIPEstat")?;

    if !resp.status().is_success() {
        anyhow::bail!("RIPEstat ris-peer-count failed with status {}", resp.status());
    }

    let body: serde_json::Value = resp.json().await.context("Failed to parse RIPEstat response")?;
    let pc = &body["data"]["peer_count"];
    // full_feed is a time series; take the latest sample.
    let latest = |fam: &str| -> u64 {
        pc[fam]["full_feed"]
            .as_array()
            .and_then(|a| a.last())
            .and_then(|s| s["count"].as_u64())
            .unwrap_or(0)
    };
    Ok(FullFeedPeers {
        v4: latest("v4"),
        v6: latest("v6"),
    })
}

/// Compute a propagation percentage (0-100) of full-feed peers that see the
/// resource. Returns None when the denominator is unavailable.
pub fn propagation_pct(peers_seeing: usize, full_feed: u64) -> Option<u8> {
    if full_feed == 0 {
        return None;
    }
    Some(((peers_seeing as u64 * 100 / full_feed).min(100)) as u8)
}

/// Query the RIPEstat looking-glass for a resource (prefix or IP) and return an
/// aggregated view of how public BGP collectors (RIPE RIS) currently see it.
pub async fn looking_glass(resource: &str) -> Result<Visibility> {
    let base = std::env::var("NXTHDR_RIS_URL").unwrap_or_else(|_| DEFAULT_RIS_URL.to_string());
    let url = format!(
        "{base}/data/looking-glass/data.json?resource={}&sourceapp=nxthdr-cli",
        urlencoding::encode(resource)
    );

    tracing::debug!("RIS looking-glass: {url}");

    let resp = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "nxthdr-cli")
        .send()
        .await
        .context("Failed to query RIPEstat")?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "RIPEstat request failed with status {}: {}",
            status,
            resp.text().await.unwrap_or_default().trim()
        );
    }

    let envelope: Envelope = resp.json().await.context("Failed to parse RIPEstat response")?;
    Ok(Visibility {
        query_time: envelope.data.query_time,
        rrcs: envelope.data.rrcs,
    })
}
