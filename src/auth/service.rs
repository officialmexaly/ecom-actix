// src/auth/service.rs
use std::collections::HashMap;
use chrono::{Duration, Utc};
use crate::auth::user::{User, CreateUserRequest, LoginRequest, LoginResponse, RefreshTokenRequest, ChangePasswordRequest, ResetPasswordRequest, UserInfo};
use crate::auth::jwt::{JwtManager, TokenPair};
use crate::rbac::engine::RbacEngine;

#[derive(Clone)]
pub struct AuthService {
    users: HashMap<String, User>, // In production, use a database
    pub jwt_manager: JwtManager, // Make public for access
    rbac_engine: RbacEngine,
    active_sessions: HashMap<String, UserSession>, // session_id -> session
    refresh_tokens: HashMap<String, String>, // refresh_token -> user_id
    password_reset_tokens: HashMap<String, PasswordResetToken>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserSession {
    pub session_id: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<Utc>,
    pub last_activity: chrono::DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PasswordResetToken {
    pub token: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub is_used: bool,
}

#[derive(Debug)]
pub enum AuthError {
    UserNotFound,
    InvalidCredentials,
    UserLocked,
    UserInactive,
    PasswordExpired,
    MustChangePassword,
    TokenExpired,
    TokenInvalid,
    SessionExpired,
    SessionInvalid,
    UserAlreadyExists,
    WeakPassword,
    InvalidEmail,
    InternalError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::UserLocked => write!(f, "Account is locked"),
            AuthError::UserInactive => write!(f, "Account is inactive"),
            AuthError::PasswordExpired => write!(f, "Password has expired"),
            AuthError::MustChangePassword => write!(f, "Password must be changed"),
            AuthError::TokenExpired => write!(f, "Token has expired"),
            AuthError::TokenInvalid => write!(f, "Token is invalid"),
            AuthError::SessionExpired => write!(f, "Session has expired"),
            AuthError::SessionInvalid => write!(f, "Session is invalid"),
            AuthError::UserAlreadyExists => write!(f, "User already exists"),
            AuthError::WeakPassword => write!(f, "Password is too weak"),
            AuthError::InvalidEmail => write!(f, "Invalid email address"),
            AuthError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl AuthService {
    pub fn new(rbac_engine: RbacEngine) -> Self {
        Self {
            users: HashMap::new(),
            jwt_manager: JwtManager::new(),
            rbac_engine,
            active_sessions: HashMap::new(),
            refresh_tokens: HashMap::new(),
            password_reset_tokens: HashMap::new(),
        }
    }

    pub fn create_user(&mut self, request: CreateUserRequest) -> Result<UserInfo, AuthError> {
        // Check if user already exists
        if self.users.values().any(|u| u.username == request.username || u.email == request.email) {
            return Err(AuthError::UserAlreadyExists);
        }

        // Validate email format
        if !self.is_valid_email(&request.email) {
            return Err(AuthError::InvalidEmail);
        }

        // Validate password strength
        if !self.is_strong_password(&request.password) {
            return Err(AuthError::WeakPassword);
        }

        // Create user
        let user = User::new(request).map_err(|e| AuthError::InternalError(e))?;
        let user_id = user.id.clone();
        let user_info = user.to_user_info();

        // Add user to RBAC engine
        for role in &user.roles {
            self.rbac_engine.assign_role_to_user(&user_id, role);
        }

        // Store user
        self.users.insert(user_id, user);

        Ok(user_info)
    }

    pub fn login(&mut self, request: LoginRequest, ip_address: Option<String>, user_agent: Option<String>) -> Result<LoginResponse, AuthError> {
        // Find user by username or email and clone needed data
        let (user_id, user_valid, user_active, user_locked, user_password_expired, user_must_change_password) = {
            let user = self.find_user_by_username_or_email(&request.username_or_email)?;
            (user.id.clone(), user.verify_password(&request.password), user.is_active, user.is_locked(), user.is_password_expired(), user.must_change_password)
        };
        
        // Check if user is active
        if !user_active {
            return Err(AuthError::UserInactive);
        }

        // Check if user is locked
        if user_locked {
            return Err(AuthError::UserLocked);
        }

        // Verify password
        if !user_valid {
            // Increment failed attempts
            if let Some(user) = self.users.get_mut(&user_id) {
                user.increment_failed_attempts();
            }
            return Err(AuthError::InvalidCredentials);
        }

        // Check if password is expired
        if user_password_expired {
            return Err(AuthError::PasswordExpired);
        }

        // Check if user must change password
        if user_must_change_password {
            return Err(AuthError::MustChangePassword);
        }

        // Get user reference again for token generation
        let user = self.users.get(&user_id).unwrap();

        // Generate tokens
        let token_pair = self.jwt_manager.generate_token_pair(user, request.remember_me.unwrap_or(false))
            .map_err(|e| AuthError::InternalError(e))?;

        // Create session
        let session = UserSession {
            session_id: token_pair.session_id.clone(),
            user_id: user_id.clone(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
            is_active: true,
        };

        // Store session and refresh token
        self.active_sessions.insert(token_pair.session_id.clone(), session);
        self.refresh_tokens.insert(token_pair.refresh_token.clone(), user_id.clone());

        // Update user's last login and reset failed attempts
        if let Some(user) = self.users.get_mut(&user_id) {
            user.update_last_login();
        }

        // Start RBAC session
        self.rbac_engine.start_user_session(
            &user_id,
            &token_pair.session_id,
            ip_address,
            &user_agent.unwrap_or_default()
        );

        // Get user info for response
        let user_info = self.users.get(&user_id).unwrap().to_user_info();

        Ok(LoginResponse {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            expires_in: token_pair.expires_in,
            user: user_info,
        })
    }

    pub fn refresh_token(&mut self, request: RefreshTokenRequest) -> Result<TokenPair, AuthError> {
        // Verify refresh token exists
        let user_id = self.refresh_tokens.get(&request.refresh_token)
            .ok_or(AuthError::TokenInvalid)?
            .clone();

        // Get user
        let user = self.users.get(&user_id)
            .ok_or(AuthError::UserNotFound)?;

        // Check if user is still active
        if !user.is_active {
            return Err(AuthError::UserInactive);
        }

        // Generate new token pair
        let new_token_pair = self.jwt_manager.refresh_access_token(user, &request.refresh_token)
            .map_err(|e| AuthError::InternalError(e))?;

        // Remove old refresh token and add new one
        self.refresh_tokens.remove(&request.refresh_token);
        self.refresh_tokens.insert(new_token_pair.refresh_token.clone(), user_id);

        Ok(new_token_pair)
    }

    pub fn logout(&mut self, session_id: &str) -> Result<(), AuthError> {
        // Remove session
        if let Some(session) = self.active_sessions.remove(session_id) {
            // Find and remove associated refresh tokens
            self.refresh_tokens.retain(|_, user_id| *user_id != session.user_id);
            Ok(())
        } else {
            Err(AuthError::SessionInvalid)
        }
    }

    pub fn verify_token(&self, token: &str) -> Result<UserInfo, AuthError> {
        let claims = self.jwt_manager.verify_access_token(token)
            .map_err(|_| AuthError::TokenInvalid)?;

        // Check if session is still active
        if let Some(session) = self.active_sessions.get(&claims.session_id) {
            if !session.is_active {
                return Err(AuthError::SessionExpired);
            }

            // Check session timeout (30 minutes of inactivity)
            if Utc::now().signed_duration_since(session.last_activity) > Duration::minutes(30) {
                return Err(AuthError::SessionExpired);
            }
        } else {
            return Err(AuthError::SessionInvalid);
        }

        // Get user and return user info
        let user = self.users.get(&claims.sub)
            .ok_or(AuthError::UserNotFound)?;

        if !user.is_active {
            return Err(AuthError::UserInactive);
        }

        Ok(user.to_user_info())
    }

    pub fn change_password(&mut self, user_id: &str, request: ChangePasswordRequest) -> Result<(), AuthError> {
        // Validate new password strength first
        if !self.is_strong_password(&request.new_password) {
            return Err(AuthError::WeakPassword);
        }

        let user = self.users.get_mut(user_id)
            .ok_or(AuthError::UserNotFound)?;

        // Verify current password
        if !user.verify_password(&request.current_password) {
            return Err(AuthError::InvalidCredentials);
        }

        // Update password
        user.update_password(&request.new_password)
            .map_err(|e| AuthError::InternalError(e))?;

        Ok(())
    }

    pub fn request_password_reset(&mut self, request: ResetPasswordRequest) -> Result<String, AuthError> {
        let user = self.find_user_by_email(&request.email)?;
        
        // Generate reset token
        let reset_token = self.jwt_manager.create_password_reset_token(&user.id)
            .map_err(|e| AuthError::InternalError(e))?;

        // Store reset token
        let reset_token_info = PasswordResetToken {
            token: reset_token.clone(),
            user_id: user.id.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            is_used: false,
        };

        self.password_reset_tokens.insert(reset_token.clone(), reset_token_info);

        // In production, send this token via email
        Ok(reset_token)
    }

    pub fn reset_password(&mut self, token: &str, new_password: &str) -> Result<(), AuthError> {
        // Verify and get user ID from token
        let user_id = self.jwt_manager.verify_password_reset_token(token)
            .map_err(|_| AuthError::TokenInvalid)?;

        // Validate new password strength first
        if !self.is_strong_password(new_password) {
            return Err(AuthError::WeakPassword);
        }

        // Check if reset token exists and is valid
        let reset_token_info = self.password_reset_tokens.get_mut(token)
            .ok_or(AuthError::TokenInvalid)?;

        if reset_token_info.is_used {
            return Err(AuthError::TokenInvalid);
        }

        if Utc::now() > reset_token_info.expires_at {
            return Err(AuthError::TokenExpired);
        }

        // Update password
        let user = self.users.get_mut(&user_id)
            .ok_or(AuthError::UserNotFound)?;

        user.update_password(new_password)
            .map_err(|e| AuthError::InternalError(e))?;

        // Mark token as used
        reset_token_info.is_used = true;

        // Invalidate all sessions for this user
        self.invalidate_user_sessions(&user_id);

        Ok(())
    }

    pub fn get_user_sessions(&self, user_id: &str) -> Vec<&UserSession> {
        self.active_sessions.values()
            .filter(|session| session.user_id == user_id && session.is_active)
            .collect()
    }

    pub fn invalidate_user_sessions(&mut self, user_id: &str) {
        // Deactivate all sessions for the user
        for session in self.active_sessions.values_mut() {
            if session.user_id == user_id {
                session.is_active = false;
            }
        }

        // Remove refresh tokens for the user
        self.refresh_tokens.retain(|_, uid| uid != user_id);
    }

    pub fn update_session_activity(&mut self, session_id: &str) {
        if let Some(session) = self.active_sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
        }
    }

    fn find_user_by_username_or_email(&self, username_or_email: &str) -> Result<&User, AuthError> {
        self.users.values()
            .find(|user| user.username == username_or_email || user.email == username_or_email)
            .ok_or(AuthError::UserNotFound)
    }

    fn find_user_by_email(&self, email: &str) -> Result<&User, AuthError> {
        self.users.values()
            .find(|user| user.email == email)
            .ok_or(AuthError::UserNotFound)
    }

    fn is_valid_email(&self, email: &str) -> bool {
        // Simple email validation
        email.contains('@') && email.contains('.') && email.len() > 5
    }

    fn is_strong_password(&self, password: &str) -> bool {
        // Basic password strength requirements
        password.len() >= 8 &&
        password.chars().any(|c| c.is_uppercase()) &&
        password.chars().any(|c| c.is_lowercase()) &&
        password.chars().any(|c| c.is_numeric()) &&
        password.chars().any(|c| !c.is_alphanumeric())
    }

    // Cleanup expired sessions and tokens
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();

        // Remove expired sessions
        self.active_sessions.retain(|_, session| {
            session.is_active && 
            now.signed_duration_since(session.last_activity) <= Duration::hours(24)
        });

        // Remove expired password reset tokens
        self.password_reset_tokens.retain(|_, token| now <= token.expires_at && !token.is_used);
    }
}

// Implement Debug manually to avoid issues with non-Debug fields
impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("users", &self.users.len())
            .field("active_sessions", &self.active_sessions.len())
            .field("refresh_tokens", &self.refresh_tokens.len())
            .field("password_reset_tokens", &self.password_reset_tokens.len())
            .finish()
    }
}