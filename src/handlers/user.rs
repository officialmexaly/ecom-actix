use actix_web::{web, Result, Error};
use crate::handlers::ApiResponse;

pub async fn get_user(path: web::Path<String>) -> Result<web::Json<ApiResponse>, Error> {
    let user_id = path.into_inner();
    Ok(web::Json(ApiResponse {
        message: format!("User {} data accessed successfully", user_id),
    }))
}

pub async fn update_user(path: web::Path<String>) -> Result<web::Json<ApiResponse>, Error> {
    let user_id = path.into_inner();
    Ok(web::Json(ApiResponse {
        message: format!("User {} updated successfully", user_id),
    }))
}