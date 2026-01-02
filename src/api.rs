use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

const DEFAULT_API_BASE_URL: &str = "https://peerlab.nxthdr.dev";

pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new() -> Self {
        let base_url =
            std::env::var("NXTHDR_API_URL").unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string());

        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    async fn get_valid_token(&self) -> Result<String> {
        let tokens =
            config::load_tokens().context("Not logged in. Please run 'nxthdr login' first.")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if tokens.expires_at < now {
            config::delete_tokens()?;
            anyhow::bail!("Access token expired. Please run 'nxthdr login' again.");
        }

        Ok(tokens.access_token)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let token = self.get_valid_token().await?;
        let url = format!("{}{}", self.base_url, path);

        tracing::debug!("GET {}", url);

        let response = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .context("Failed to send request")?;

        let status = response.status();

        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("API request failed with status {}: {}", status, error_body);
        }

        let data = response
            .json::<T>()
            .await
            .context("Failed to parse response")?;

        Ok(data)
    }

    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let token = self.get_valid_token().await?;
        let url = format!("{}{}", self.base_url, path);

        tracing::debug!("POST {}", url);

        let response = self
            .client
            .post(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await
            .context("Failed to send request")?;

        let status = response.status();

        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("API request failed with status {}: {}", status, error_body);
        }

        let data = response
            .json::<T>()
            .await
            .context("Failed to parse response")?;

        Ok(data)
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        let token = self.get_valid_token().await?;
        let url = format!("{}{}", self.base_url, path);

        tracing::debug!("DELETE {}", url);

        let response = self
            .client
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .context("Failed to send request")?;

        let status = response.status();

        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            anyhow::bail!("API request failed with status {}: {}", status, error_body);
        }

        Ok(())
    }
}
