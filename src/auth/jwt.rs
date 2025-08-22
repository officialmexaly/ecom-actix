// src/auth/jwt.rs
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use chrono::{Duration, Utc};
use uuid::Uuid;
use std::collections::HashMap;
use crate::auth::user::User;

const JWT_SECRET: &str = "your-super-secret-jwt-key-change-this-in-production";
const ACCESS_TOKEN_EXPIRY_HOURS: i64 = 1;
const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,           // User ID
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub session_id: String,
    pub exp: i64,             // Expiration time
    pub iat: i64,             // Issued at
    pub iss: String,          // Issuer
    pub aud: String,          // Audience
    pub token_type: String,   // "access"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,           // User ID
    pub session_id: String,
    pub exp: i64,             // Expiration time
    pub iat: i64,             // Issued at
    pub iss: String,          // Issuer
    pub aud: String,          // Audience
    pub token_type: String,   // "refresh"
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub session_id: String,
}

#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtManager {
    pub fn new() -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["ecom-api"]);
        validation.set_issuer(&["ecom-auth-service"]);

        Self {
            encoding_key: EncodingKey::from_secret(JWT_SECRET.as_ref()),
            decoding_key: DecodingKey::from_secret(JWT_SECRET.as_ref()),
            validation,
        }
    }

    pub fn generate_token_pair(&self, user: &User, remember_me: bool) -> Result<TokenPair, String> {
        let now = Utc::now();
        let session_id = Uuid::new_v4().to_string();
        
        // Determine expiry times
        let access_expiry = if remember_me {
            now + Duration::hours(ACCESS_TOKEN_EXPIRY_HOURS * 2) // Extended for remember me
        } else {
            now + Duration::hours(ACCESS_TOKEN_EXPIRY_HOURS)
        };
        
        let refresh_expiry = if remember_me {
            now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS * 2) // Extended for remember me
        } else {
            now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS)
        };

        // Create access token
        let access_claims = AccessTokenClaims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            roles: user.roles.clone(),
            session_id: session_id.clone(),
            exp: access_expiry.timestamp(),
            iat: now.timestamp(),
            iss: "ecom-auth-service".to_string(),
            aud: "ecom-api".to_string(),
            token_type: "access".to_string(),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|_| "Failed to generate access token")?;

        // Create refresh token
        let refresh_claims = RefreshTokenClaims {
            sub: user.id.clone(),
            session_id: session_id.clone(),
            exp: refresh_expiry.timestamp(),
            iat: now.timestamp(),
            iss: "ecom-auth-service".to_string(),
            aud: "ecom-api".to_string(),
            token_type: "refresh".to_string(),
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|_| "Failed to generate refresh token")?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: access_expiry.timestamp() - now.timestamp(),
            session_id,
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, String> {
        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| format!("Invalid access token: {}", e))?;

        if token_data.claims.token_type != "access" {
            return Err("Invalid token type".to_string());
        }

        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, String> {
        let token_data = decode::<RefreshTokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| format!("Invalid refresh token: {}", e))?;

        if token_data.claims.token_type != "refresh" {
            return Err("Invalid token type".to_string());
        }

        Ok(token_data.claims)
    }

    pub fn extract_token_from_header(&self, auth_header: &str) -> Result<String, String> {
        if !auth_header.starts_with("Bearer ") {
            return Err("Invalid authorization header format".to_string());
        }

        let token = auth_header.trim_start_matches("Bearer ");
        if token.is_empty() {
            return Err("Empty token".to_string());
        }

        Ok(token.to_string())
    }

    pub fn refresh_access_token(&self, user: &User, refresh_token: &str) -> Result<TokenPair, String> {
        // Verify the refresh token first
        let refresh_claims = self.verify_refresh_token(refresh_token)?;
        
        // Check if the refresh token belongs to this user
        if refresh_claims.sub != user.id {
            return Err("Refresh token doesn't belong to this user".to_string());
        }

        // Generate new token pair
        self.generate_token_pair(user, false)
    }

    pub fn create_password_reset_token(&self, user_id: &str) -> Result<String, String> {
        let now = Utc::now();
        let mut claims = HashMap::new();
        
        claims.insert("sub".to_string(), user_id.to_string());
        claims.insert("exp".to_string(), (now + Duration::hours(1)).timestamp().to_string()); // 1 hour expiry
        claims.insert("iat".to_string(), now.timestamp().to_string());
        claims.insert("iss".to_string(), "ecom-auth-service".to_string());
        claims.insert("token_type".to_string(), "password_reset".to_string());

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| "Failed to generate password reset token".to_string())
    }

    pub fn verify_password_reset_token(&self, token: &str) -> Result<String, String> {
        let token_data = decode::<HashMap<String, serde_json::Value>>(token, &self.decoding_key, &self.validation)
            .map_err(|e| format!("Invalid password reset token: {}", e))?;

        let token_type = token_data.claims.get("token_type")
            .and_then(|v| v.as_str())
            .ok_or("Missing token type")?;

        if token_type != "password_reset" {
            return Err("Invalid token type for password reset".to_string());
        }

        let user_id = token_data.claims.get("sub")
            .and_then(|v| v.as_str())
            .ok_or("Missing user ID in token")?;

        Ok(user_id.to_string())
    }
}

// Implement Debug manually to avoid issues with non-Debug fields
impl std::fmt::Debug for JwtManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtManager")
            .field("algorithm", &self.validation.algorithms)
            .finish()
    }
}

impl Default for JwtManager {
    fn default() -> Self {
        Self::new()
    }
}