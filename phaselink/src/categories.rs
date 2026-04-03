// ── REST — categories ───────────────────────────────────────────────────────────

use axum::extract::{Extension, Path};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rusqlite::ToSql;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info};

use super::{require_auth, AppState};

#[derive(Serialize, utoipa::ToSchema)]
pub struct Category {
    pub id: i64,
    pub name: String,
    pub position: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateCategory {
    pub name: String,
    #[serde(default)]
    pub position: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateCategory {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub position: Option<i64>,
}

pub async fn list_categories(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers).await {
        return e.into_response();
    }
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };
    let mut stmt = match db.prepare("SELECT id, name, position FROM categories ORDER BY position ASC, name ASC") {
        Ok(s) => s,
        Err(e) => {
            error!("prepare: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response();
        }
    };
    let categories: Vec<Category> = match stmt.query_map([], |row| {
        Ok(Category {
            id: row.get(0)?,
            name: row.get(1)?,
            position: row.get(2)?,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            error!("query categories: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response();
        }
    };
    debug!("list_categories: returning {} categories", categories.len());
    Json(categories).into_response()
}

pub async fn create_category(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateCategory>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    // Only server owner can create categories
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can create categories" })),
        )
            .into_response();
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Category name must be 1–100 characters" })),
        )
            .into_response();
    }
    let insert_result = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "DB unavailable" })),
                )
                    .into_response();
            }
        };
        db.execute(
            "INSERT INTO categories (name, position) VALUES (?1, ?2)",
            rusqlite::params![name, body.position],
        )
    };
    match insert_result {
        Ok(_) => {
            let cat = {
                let db = state.db.lock().unwrap();
                let mut stmt = db.prepare("SELECT id, name, position FROM categories WHERE name = ?1").unwrap();
                let mut rows = stmt.query(rusqlite::params![name]).unwrap();
                if let Ok(Some(row)) = rows.next() {
                    Some(Category {
                        id: row.get(0).unwrap(),
                        name: row.get(1).unwrap(),
                        position: row.get(2).unwrap(),
                    })
                } else {
                    None
                }
            }; // db lock dropped here

            if let Some(cat) = cat {
                info!("category created: {} by {identity}", cat.name);
                // Broadcast category creation
                let server_id = state.settings.read().await.server_name.clone();
                let broadcast = serde_json::to_string(&json!({
                    "type": "category_created",
                    "category": {
                        "id": cat.id,
                        "name": cat.name.clone(),
                        "position": cat.position,
                    },
                    "server_id": server_id,
                }))
                .unwrap();
                let _ = state.server_bus.send(broadcast);
                Json(cat).into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Failed to retrieve created category" })),
                )
                    .into_response()
            }
        }
        Err(e) if e.to_string().contains("UNIQUE") => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "Category name already exists" })),
        )
            .into_response(),
        Err(e) => {
            error!("insert category: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

pub async fn delete_category(
    Extension(state): Extension<Arc<AppState>>,
    Path(category_id): Path<i64>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    // Only server owner can delete categories
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can delete categories" })),
        )
            .into_response();
    }
    // First, get the category name for logging
    let cat_name: Option<String> = {
        let db = state.db.lock().unwrap();
        db.query_row("SELECT name FROM categories WHERE id = ?1", rusqlite::params![category_id], |row| row.get(0))
            .ok()
    };

    let delete_result = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "DB unavailable" })),
                )
                    .into_response();
            }
        };
        // Set category_id to NULL for all channels in this category
        db.execute(
            "UPDATE channels SET category_id = NULL WHERE category_id = ?1",
            rusqlite::params![category_id],
        )
        .ok();

        db.execute(
            "DELETE FROM categories WHERE id = ?1",
            rusqlite::params![category_id],
        )
    };
    match delete_result {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Category not found" })),
        )
            .into_response(),
        Ok(_) => {
            info!("category deleted: {} by {identity}", cat_name.unwrap_or_default());
            // Broadcast category deletion
            let server_id = state.settings.read().await.server_name.clone();
            let broadcast = serde_json::to_string(&json!({
                "type": "category_deleted",
                "category_id": category_id,
                "server_id": server_id,
            }))
            .unwrap();
            let _ = state.server_bus.send(broadcast);
            (StatusCode::OK, Json(json!({ "deleted": true }))).into_response()
        }
        Err(e) => {
            error!("delete category: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

pub async fn update_category(
    Extension(state): Extension<Arc<AppState>>,
    Path(category_id): Path<i64>,
    headers: HeaderMap,
    Json(body): Json<UpdateCategory>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    // Only server owner can update categories
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can update categories" })),
        )
            .into_response();
    }
    if body.name.is_none() && body.position.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No name or position provided" })),
        )
            .into_response();
    }
    if let Some(name) = &body.name {
        if name.trim().is_empty() || name.trim().len() > 100 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Category name must be 1–100 characters" })),
            )
                .into_response();
        }
    }

    let update_result = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "DB unavailable" })),
                )
                    .into_response();
            }
        };

        let mut set_clauses = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(name) = &body.name {
            set_clauses.push(format!("name = ?{}", idx));
            params.push(Box::new(name.trim().to_string()));
            idx += 1;
        }
        if let Some(position) = body.position {
            set_clauses.push(format!("position = ?{}", idx));
            params.push(Box::new(position));
            idx += 1;
        }

        let sql = format!(
            "UPDATE categories SET {} WHERE id = ?{}",
            set_clauses.join(", "),
            idx
        );
        params.push(Box::new(category_id.clone()));
        let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let result = db.execute(&sql, param_refs.as_slice());
        drop(db);

        match result {
            Ok(0) => Err("Category not found"),
            Ok(_) => {
                let db = state.db.lock().unwrap();
                let mut stmt = db
                    .prepare("SELECT id, name, position FROM categories WHERE id = ?1")
                    .unwrap();
                let mut rows = stmt.query(rusqlite::params![category_id]).unwrap();
                match rows.next() {
                    Ok(Some(row)) => {
                        let id: i64 = row.get(0).unwrap();
                        let name: String = row.get(1).unwrap();
                        let position: i64 = row.get(2).unwrap();
                        Ok((id, name, position))
                    }
                    _ => Err("Category not found"),
                }
            }
            Err(e) => {
                error!("update category: {e}");
                Err("DB error")
            }
        }
    };

    match update_result {
        Ok((id, name, position)) => {
            info!("category updated: {} by {identity}", name);
            let server_id = state.settings.read().await.server_name.clone();
            let broadcast = serde_json::to_string(&json!({
                "type": "category_updated",
                "category": {
                    "id": id,
                    "name": name.clone(),
                    "position": position,
                },
                "server_id": server_id,
            }))
            .unwrap();
            let _ = state.server_bus.send(broadcast);
            (
                StatusCode::OK,
                Json(json!({ "id": id, "name": name, "position": position })),
            )
                .into_response()
        }
        Err(e) => match e {
            "Category not found" => {
                (StatusCode::NOT_FOUND, Json(json!({ "error": e }))).into_response()
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response(),
        },
    }
}
