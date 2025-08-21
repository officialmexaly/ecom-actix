use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct UserSession {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub location: Option<String>,
    pub device_info: String,
    pub active_roles: Vec<String>,
}