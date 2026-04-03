use anyhow::{Context, Result};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_address: String,
    pub bridge_secret: String,
    pub allowed_origins: Vec<String>,
    pub livekit_host: String,
    pub livekit_public_url: String,
    pub livekit_api_key: String,
    pub livekit_api_secret: String,
    pub port: u16,
    pub zpulse_url: String,
}

/// Shared state passed into Axum handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let livekit_host =
            std::env::var("LIVEKIT_HOST").unwrap_or_else(|_| "http://localhost:7880".into());
        let livekit_public_url =
            std::env::var("LIVEKIT_PUBLIC_URL").unwrap_or_else(|_| livekit_host.clone());

        // Parse allowed origins from env
        let allowed_origins = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| {
                // Default: localhost origins + zpulse internal
                "http://localhost:3000,http://localhost:3002,https://localhost:3000,https://localhost:3002,http://127.0.0.1:3002".into()
            })
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let zpulse_url =
            std::env::var("ZPULSE_URL").unwrap_or_else(|_| "http://127.0.0.1:3002".into());

        Ok(Config {
            bind_address: std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".into()),
            bridge_secret: std::env::var("BRIDGE_SECRET").context("BRIDGE_SECRET must be set")?,
            allowed_origins,
            livekit_host,
            livekit_public_url,
            livekit_api_key: std::env::var("LIVEKIT_API_KEY")
                .context("LIVEKIT_API_KEY must be set")?,
            livekit_api_secret: std::env::var("LIVEKIT_API_SECRET")
                .context("LIVEKIT_API_SECRET must be set")?,
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .context("PORT must be a number")?,
            zpulse_url,
        })
    }

    pub fn into_app_state(self) -> AppState {
        AppState {
            config: Arc::new(self),
        }
    }
}
