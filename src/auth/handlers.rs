// src/auth/handlers.rs
use actix_web::{web, HttpRequest, HttpResponse, Result, HttpMessage};
use serde_json;
use std::sync::{Arc, Mutex};
use crate::auth::service::AuthService;
use crate::auth::user::{CreateUserRequest, LoginRequest, RefreshTokenRequest, ChangePasswordRequest, ResetPasswordRequest};

pub type AuthServiceData = web::Data<Arc<Mutex<AuthService>>>;

// Helper macro for authentication
macro_rules! require_auth {
    ($req:expr) => {{
        match $req.extensions().get::<crate::auth::UserInfo>() {
            Some(user) => user.clone(),
            None => {
                return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Authentication required"
                })));
            }
        }
    }};
}

// Helper macro for role checking
macro_rules! require_role {
    ($req:expr, $role:expr) => {{
        match $req.extensions().get::<crate::auth::UserInfo>() {
            Some(user) => {
                if !user.roles.contains(&$role.to_string()) {
                    return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "Insufficient permissions",
                        "required_role": $role
                    })));
                }
                user.clone()
            },
            None => {
                return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Authentication required"
                })));
            }
        }
    }};
}

// Register a new user
pub async fn register(
    auth_service: AuthServiceData,
    request: web::Json<CreateUserRequest>
) -> Result<HttpResponse> {
    match auth_service.lock().unwrap().create_user(request.into_inner()) {
        Ok(user_info) => Ok(HttpResponse::Created().json(serde_json::json!({
            "message": "User created successfully",
            "user": user_info
        }))),
        Err(auth_error) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Registration failed",
            "message": auth_error.to_string()
        })))
    }
}

// User login
pub async fn login(
    auth_service: AuthServiceData,
    request: web::Json<LoginRequest>,
    req: HttpRequest
) -> Result<HttpResponse> {
    // Extract client info
    let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
    let user_agent = req.headers().get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match auth_service.lock().unwrap().login(request.into_inner(), ip_address, user_agent) {
        Ok(login_response) => Ok(HttpResponse::Ok().json(login_response)),
        Err(auth_error) => {
            let mut status = match auth_error {
                crate::auth::service::AuthError::InvalidCredentials => HttpResponse::Unauthorized(),
                crate::auth::service::AuthError::UserLocked => HttpResponse::Locked(),
                crate::auth::service::AuthError::UserInactive => HttpResponse::Forbidden(),
                crate::auth::service::AuthError::PasswordExpired => HttpResponse::UnprocessableEntity(),
                crate::auth::service::AuthError::MustChangePassword => HttpResponse::UnprocessableEntity(),
                _ => HttpResponse::BadRequest(),
            };

            Ok(status.json(serde_json::json!({
                "error": "Login failed",
                "message": auth_error.to_string()
            })))
        }
    }
}

// Refresh access token
pub async fn refresh_token(
    auth_service: AuthServiceData,
    request: web::Json<RefreshTokenRequest>
) -> Result<HttpResponse> {
    match auth_service.lock().unwrap().refresh_token(request.into_inner()) {
        Ok(token_pair) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "expires_in": token_pair.expires_in
        }))),
        Err(auth_error) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Token refresh failed",
            "message": auth_error.to_string()
        })))
    }
}

// User logout
pub async fn logout(
    auth_service: AuthServiceData,
    req: HttpRequest
) -> Result<HttpResponse> {
    let _user = require_auth!(req);
    
    // Extract session ID from JWT claims
    if let Some(auth_header) = req.headers().get("Authorization")
        .and_then(|h| h.to_str().ok()) {
        
        let auth_service_ref = auth_service.lock().unwrap();
        if let Ok(token) = auth_service_ref.jwt_manager.extract_token_from_header(auth_header) {
            if let Ok(claims) = auth_service_ref.jwt_manager.verify_access_token(&token) {
                drop(auth_service_ref); // Release lock
                match auth_service.lock().unwrap().logout(&claims.session_id) {
                    Ok(_) => return Ok(HttpResponse::Ok().json(serde_json::json!({
                        "message": "Logged out successfully"
                    }))),
                    Err(auth_error) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "Logout failed",
                        "message": auth_error.to_string()
                    })))
                }
            }
        }
    }

    Ok(HttpResponse::BadRequest().json(serde_json::json!({
        "error": "Invalid session"
    })))
}

// Get current user profile
pub async fn get_profile(req: HttpRequest) -> Result<HttpResponse> {
    let user = require_auth!(req);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user": user
    })))
}

// Change password
pub async fn change_password(
    auth_service: AuthServiceData,
    request: web::Json<ChangePasswordRequest>,
    req: HttpRequest
) -> Result<HttpResponse> {
    let user = require_auth!(req);
    
    match auth_service.lock().unwrap().change_password(&user.id, request.into_inner()) {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Password changed successfully"
        }))),
        Err(auth_error) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password change failed",
            "message": auth_error.to_string()
        })))
    }
}

// Request password reset
pub async fn request_password_reset(
    auth_service: AuthServiceData,
    request: web::Json<ResetPasswordRequest>
) -> Result<HttpResponse> {
    match auth_service.lock().unwrap().request_password_reset(request.into_inner()) {
        Ok(reset_token) => {
            // In production, this token should be sent via email, not returned in response
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Password reset instructions sent to your email",
                "reset_token": reset_token // Remove this in production
            })))
        },
        Err(auth_error) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password reset request failed",
            "message": auth_error.to_string()
        })))
    }
}

// Reset password with token
pub async fn reset_password(
    auth_service: AuthServiceData,
    query: web::Query<serde_json::Value>,
    request: web::Json<serde_json::Value>
) -> Result<HttpResponse> {
    let token = query.get("token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing reset token"))?;

    let new_password = request.get("new_password")
        .and_then(|p| p.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing new password"))?;

    match auth_service.lock().unwrap().reset_password(token, new_password) {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Password reset successfully"
        }))),
        Err(auth_error) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password reset failed",
            "message": auth_error.to_string()
        })))
    }
}

// Get user sessions (admin only)
pub async fn get_user_sessions(
    auth_service: AuthServiceData,
    path: web::Path<String>,
    req: HttpRequest
) -> Result<HttpResponse> {
    require_role!(req, "admin");
    
    let target_user_id = path.into_inner();
    let auth_service_ref = auth_service.lock().unwrap();
    let sessions: Vec<_> = auth_service_ref.get_user_sessions(&target_user_id).into_iter().cloned().collect();
    drop(auth_service_ref);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": target_user_id,
        "sessions": sessions
    })))
}

// Invalidate user sessions (admin only)
pub async fn invalidate_user_sessions(
    auth_service: AuthServiceData,
    path: web::Path<String>,
    req: HttpRequest
) -> Result<HttpResponse> {
    require_role!(req, "admin");
    
    let target_user_id = path.into_inner();
    auth_service.lock().unwrap().invalidate_user_sessions(&target_user_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("All sessions for user {} have been invalidated", target_user_id)
    })))
}

// Get my active sessions
pub async fn get_my_sessions(
    auth_service: AuthServiceData,
    req: HttpRequest
) -> Result<HttpResponse> {
    let user = require_auth!(req);
    
    let auth_service_ref = auth_service.lock().unwrap();
    let sessions: Vec<_> = auth_service_ref.get_user_sessions(&user.id).into_iter().cloned().collect();
    drop(auth_service_ref);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sessions": sessions
    })))
}

// Validate token endpoint (for other services)
pub async fn validate_token(
    auth_service: AuthServiceData,
    req: HttpRequest
) -> Result<HttpResponse> {
    if let Some(auth_header) = req.headers().get("Authorization")
        .and_then(|h| h.to_str().ok()) {
        
        let auth_service_ref = auth_service.lock().unwrap();
        if let Ok(token) = auth_service_ref.jwt_manager.extract_token_from_header(auth_header) {
            match auth_service_ref.verify_token(&token) {
                Ok(user_info) => Ok(HttpResponse::Ok().json(serde_json::json!({
                    "valid": true,
                    "user": user_info
                }))),
                Err(auth_error) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                    "valid": false,
                    "error": auth_error.to_string()
                })))
            }
        } else {
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "valid": false,
                "error": "Invalid authorization header"
            })))
        }
    } else {
        Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "valid": false,
            "error": "Missing authorization header"
        })))
    }
}