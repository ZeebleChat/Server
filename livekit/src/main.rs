mod config;
mod error;
mod middleware;
mod routes;
mod token;
mod rooms;

use axum::{
    Router,
    middleware::from_fn_with_state,
};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;

use crate::{
    config::Config,
    middleware::{
        bridge_secret_middleware,
        build_cors_layer,
    },
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Init logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "livekit_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load config
    let config = Config::from_env()?;
    let bind_address = config.bind_address.clone();
    let port = config.port;
    let allowed_origins = config.allowed_origins.clone();
    let zpulse_url = config.zpulse_url.clone();

    info!("Starting LiveKit management server on {}:{}", bind_address, port);
    info!("LiveKit host: {}", config.livekit_host);
    info!("CORS allowed origins: {:?}", allowed_origins);
    info!("ZPULSE_URL (internal): {}", zpulse_url);

    // Create app state
    let app_state = config.into_app_state();

    // Create rate limiter
    let rate_limiter = routes::create_token_rate_limiter();

    // Build CORS layer
    let cors_layer = build_cors_layer(&allowed_origins, &zpulse_url);

    // Build router with middleware
    // Note: Layers are applied in reverse order - the last layer wraps the first
    let app = Router::new()
        // Token routes with rate limiting
        .merge(routes::token_routes(rate_limiter))
        // Room routes
        .merge(routes::room_routes())
        // Health routes (no auth required)
        .merge(routes::health_routes())
        // CORS layer (outermost - applied first, so runs last on response)
        .layer(cors_layer)
        // Trace layer for logging
        .layer(TraceLayer::new_for_http())
        // Bridge secret auth middleware (innermost - runs first on request)
        .layer(from_fn_with_state(
            app_state.clone(),
            bridge_secret_middleware,
        ))
        .with_state(app_state);

    // Bind to specific address (configurable via BIND_ADDRESS env var)
    let addr = format!("{}:{}", bind_address, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("Server listening on {} (bind address: {})", listener.local_addr()?, bind_address);
    info!("Bridge secret authentication enabled");
    info!("Rate limiting: 10 requests/minute per identity for /token endpoint");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    ).await?;

    Ok(())
}
