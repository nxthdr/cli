use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenStorage {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

pub fn get_config_dir() -> Result<PathBuf> {
    let project_dirs = ProjectDirs::from("dev", "nxthdr", "nxthdr")
        .context("Failed to determine config directory")?;

    let config_dir = project_dirs.config_dir();

    if !config_dir.exists() {
        fs::create_dir_all(config_dir).context("Failed to create config directory")?;
    }

    Ok(config_dir.to_path_buf())
}

pub fn get_token_path() -> Result<PathBuf> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join("tokens.json"))
}

pub fn save_tokens(tokens: &TokenStorage) -> Result<()> {
    let token_path = get_token_path()?;
    let json = serde_json::to_string_pretty(tokens).context("Failed to serialize tokens")?;

    fs::write(&token_path, json).context("Failed to write tokens to file")?;

    tracing::debug!("Tokens saved to {:?}", token_path);
    Ok(())
}

pub fn load_tokens() -> Result<TokenStorage> {
    let token_path = get_token_path()?;

    if !token_path.exists() {
        anyhow::bail!("No tokens found. Please run 'nxthdr login' first.");
    }

    let json = fs::read_to_string(&token_path).context("Failed to read tokens file")?;

    let tokens: TokenStorage =
        serde_json::from_str(&json).context("Failed to parse tokens file")?;

    Ok(tokens)
}

pub fn delete_tokens() -> Result<()> {
    let token_path = get_token_path()?;

    if token_path.exists() {
        fs::remove_file(&token_path).context("Failed to delete tokens file")?;
        tracing::debug!("Tokens deleted from {:?}", token_path);
    }

    Ok(())
}

pub fn tokens_exist() -> bool {
    get_token_path().map(|path| path.exists()).unwrap_or(false)
}
