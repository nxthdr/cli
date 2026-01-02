use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

const AUTH0_DOMAIN: &str = "dev-zk3qmxl3o0m8lvk3.eu.auth0.com";
const AUDIENCE: &str = "https://saimiris.nxthdr.dev";

fn get_client_id() -> String {
    env::var("NXTHDR_CLIENT_ID").unwrap_or_else(|_| "45xjiornjC1JYGkgbBb9HX7l890rasTw".to_string())
}

fn get_audience() -> String {
    AUDIENCE.to_string()
}

fn get_auth0_domain() -> String {
    AUTH0_DOMAIN.to_string()
}

#[derive(Debug, Serialize)]
struct DeviceCodeRequest {
    client_id: String,
    scope: String,
    audience: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub interval: u64,
}

#[derive(Debug, Serialize)]
struct TokenRequest {
    grant_type: String,
    device_code: String,
    client_id: String,
}

pub async fn start_device_flow() -> Result<DeviceCodeResponse> {
    let client = reqwest::Client::new();
    let domain = get_auth0_domain();
    let url = format!("https://{}/oauth/device/code", domain);

    let request = DeviceCodeRequest {
        client_id: get_client_id(),
        scope: "openid profile email offline_access".to_string(),
        audience: get_audience(),
    };

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .context("Failed to start device flow")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Device flow request failed with status {}: {}",
            status,
            body
        );
    }

    let device_code: DeviceCodeResponse = response
        .json()
        .await
        .context("Failed to parse device code response")?;

    Ok(device_code)
}

pub async fn poll_for_token(device_code: &str, interval: u64) -> Result<(String, String, i64)> {
    let client = reqwest::Client::new();
    let domain = get_auth0_domain();
    let url = format!("https://{}/oauth/token", domain);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

        let request = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            device_code: device_code.to_string(),
            client_id: get_client_id(),
        };

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to poll for token")?;

        let status = response.status();
        let response_text = response.text().await?;

        tracing::debug!("Token response status: {}", status);
        tracing::debug!("Token response body: {}", response_text);

        if status.is_success() {
            #[derive(Deserialize)]
            struct SuccessResponse {
                access_token: String,
                #[serde(default)]
                refresh_token: Option<String>,
                expires_in: u64,
            }

            let success: SuccessResponse = serde_json::from_str(&response_text).context(
                format!("Failed to parse success response. Body: {}", response_text),
            )?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let expires_at = now + success.expires_in as i64;

            return Ok((
                success.access_token,
                success.refresh_token.unwrap_or_default(),
                expires_at,
            ));
        } else {
            #[derive(Deserialize)]
            struct ErrorResponse {
                error: String,
            }

            let error_response: ErrorResponse = serde_json::from_str(&response_text).context(
                format!("Failed to parse error response. Body: {}", response_text),
            )?;

            if error_response.error == "authorization_pending" {
                continue;
            } else if error_response.error == "slow_down" {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            } else {
                anyhow::bail!("Authentication failed: {}", error_response.error);
            }
        }
    }
}
