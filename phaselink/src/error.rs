use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use tracing::error;

/// Centralized application error type for consistent error handling.
#[derive(Debug)]
pub enum AppError {
    /// Database errors
    Db(rusqlite::Error),
    /// Authentication errors
    Auth(String),
    /// Authorization errors (forbidden)
    Forbidden(String),
    /// Not found errors
    NotFound(String),
    /// Bad request errors
    BadRequest(String),
    /// Rate limit exceeded
    RateLimited(String),
    /// Internal server errors
    Internal(anyhow::Error),
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Db(err)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::Db(ref e) => {
                error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                )
            }
            AppError::Auth(ref msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Forbidden(ref msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound(ref msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::RateLimited(ref msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AppError::Internal(ref e) => {
                error!("Internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Helper trait for converting Results to AppError
pub trait IntoAppResult<T> {
    fn into_app_result(self) -> Result<T, AppError>;
}

impl<T, E: std::fmt::Display> IntoAppResult<T> for Result<T, E> {
    fn into_app_result(self) -> Result<T, AppError> {
        self.map_err(|e| AppError::Internal(anyhow::anyhow!("{}", e)))
    }
}
