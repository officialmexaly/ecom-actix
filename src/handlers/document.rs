use actix_web::{web, Result, Error};
use crate::handlers::ApiResponse;

pub async fn get_document(path: web::Path<String>) -> Result<web::Json<ApiResponse>, Error> {
    let doc_id = path.into_inner();
    Ok(web::Json(ApiResponse {
        message: format!("Document {} accessed successfully", doc_id),
    }))
}

pub async fn update_document(path: web::Path<String>) -> Result<web::Json<ApiResponse>, Error> {
    let doc_id = path.into_inner();
    Ok(web::Json(ApiResponse {
        message: format!("Document {} updated successfully", doc_id),
    }))
}