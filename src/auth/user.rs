// src/auth/user.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub failed_login_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub must_change_password: bool,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub profile: UserProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub first_name: String,
    pub last_name: String,
    pub department: Option<String>,
    pub phone: Option<String>,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub roles: Vec<String>,
    pub profile: UserProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username_or_email: String,
    pub password: String,
    pub remember_me: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub profile: UserProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
}

impl User {
    pub fn new(request: CreateUserRequest) -> Result<Self, String> {
        let password_hash = hash(&request.password, DEFAULT_COST)
            .map_err(|_| "Failed to hash password")?;

        Ok(User {
            id: Uuid::new_v4().to_string(),
            username: request.username,
            email: request.email,
            password_hash,
            roles: request.roles,
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            failed_login_attempts: 0,
            locked_until: None,
            must_change_password: false,
            password_expires_at: None,
            profile: request.profile,
        })
    }

    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password_hash).unwrap_or(false)
    }

    pub fn update_password(&mut self, new_password: &str) -> Result<(), String> {
        self.password_hash = hash(new_password, DEFAULT_COST)
            .map_err(|_| "Failed to hash password")?;
        self.must_change_password = false;
        self.password_expires_at = Some(Utc::now() + chrono::Duration::days(90));
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }

    pub fn lock_account(&mut self, duration_minutes: i64) {
        self.locked_until = Some(Utc::now() + chrono::Duration::minutes(duration_minutes));
    }

    pub fn unlock_account(&mut self) {
        self.locked_until = None;
        self.failed_login_attempts = 0;
    }

    pub fn increment_failed_attempts(&mut self) {
        self.failed_login_attempts += 1;
        
        // Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5 {
            self.lock_account(30); // Lock for 30 minutes
        }
    }

    pub fn reset_failed_attempts(&mut self) {
        self.failed_login_attempts = 0;
        self.locked_until = None;
    }

    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
        self.reset_failed_attempts();
    }

    pub fn to_user_info(&self) -> UserInfo {
        UserInfo {
            id: self.id.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            roles: self.roles.clone(),
            profile: self.profile.clone(),
        }
    }

    pub fn is_password_expired(&self) -> bool {
        if let Some(expires_at) = self.password_expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}