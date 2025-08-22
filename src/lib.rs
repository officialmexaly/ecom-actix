// src/lib.rs
pub mod rbac;
pub mod abac;
pub mod hybrid;
pub mod middleware;
pub mod handlers;
pub mod types;
pub mod auth; // New authentication module

// Re-export commonly used types

// Authentication
pub use auth::{
    AuthService, AuthError, AuthMiddlewareFactory,
    User, UserInfo, LoginRequest, LoginResponse, CreateUserRequest,
    JwtManager, AccessTokenClaims, RefreshTokenClaims, TokenPair
};

// Authorization
pub use rbac::engine::RbacEngine;
pub use abac::attribute::{AttributeValue, Subject, Resource, Action, Environment};
pub use hybrid::engine::HybridPolicyEngine;
pub use middleware::context::AccessContext;
pub use types::common::Decision;

// Macros for route protection
#[macro_export]
macro_rules! require_auth {
    ($req:expr) => {{
        match $req.extensions().get::<$crate::auth::UserInfo>() {
            Some(user) => user.clone(),
            None => {
                return Ok(actix_web::HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Authentication required"
                })));
            }
        }
    }};
}

#[macro_export]
macro_rules! require_role {
    ($req:expr, $role:expr) => {{
        match $req.extensions().get::<$crate::auth::UserInfo>() {
            Some(user) => {
                if !user.roles.contains(&$role.to_string()) {
                    return Ok(actix_web::HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "Insufficient permissions",
                        "required_role": $role
                    })));
                }
                user.clone()
            },
            None => {
                return Ok(actix_web::HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Authentication required"
                })));
            }
        }
    }};
}

#[macro_export]
macro_rules! require_any_role {
    ($req:expr, $roles:expr) => {{
        match $req.extensions().get::<$crate::auth::UserInfo>() {
            Some(user) => {
                let has_role = $roles.iter().any(|role| user.roles.contains(&role.to_string()));
                if !has_role {
                    return Ok(actix_web::HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "Insufficient permissions",
                        "required_roles": $roles
                    })));
                }
                user.clone()
            },
            None => {
                return Ok(actix_web::HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Authentication required"
                })));
            }
        }
    }};
}