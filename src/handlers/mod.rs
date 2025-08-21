pub mod user;
pub mod document;
pub mod health;

use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse {
    pub message: String,
}