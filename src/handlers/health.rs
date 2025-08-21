use actix_web::{web, Result, Error};
use serde_json;

pub async fn health_check() -> Result<web::Json<serde_json::Value>, Error> {
    Ok(web::Json(serde_json::json!({"status": "healthy"})))
}