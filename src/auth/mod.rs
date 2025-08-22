// src/auth/mod.rs
pub mod user;
pub mod jwt;
pub mod service;
pub mod middleware;
pub mod handlers;

// Re-export commonly used types
pub use user::{User, CreateUserRequest, LoginRequest, LoginResponse, RefreshTokenRequest, 
               ChangePasswordRequest, ResetPasswordRequest, UserInfo, UserProfile};
pub use jwt::{JwtManager, AccessTokenClaims, RefreshTokenClaims, TokenPair};
pub use service::{AuthService, AuthError, UserSession};
pub use middleware::{AuthMiddleware, AuthMiddlewareFactory, get_current_user};
pub use handlers::AuthServiceData;