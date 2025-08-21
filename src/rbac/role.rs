use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use crate::rbac::permission::Permission;
use crate::types::time::TimeWindow;
// Removed unused import: use crate::types::common::AttributeValue;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
    pub constraints: RoleConstraints,
    pub hierarchy_level: u32, // 0 = highest privilege
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoleConstraints {
    pub max_duration: Option<Duration>, // Auto-expire after duration
    pub valid_time_windows: Vec<TimeWindow>,
    pub required_attributes: HashMap<String, String>, // Simplified for hashing
    pub location_restrictions: Vec<String>,
    pub concurrent_limit: Option<u32>, // Max concurrent sessions
}

#[derive(Debug, Clone, PartialEq)]
pub struct DynamicRoleAssignment {
    pub role_name: String,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub assigned_by: String,
    pub conditions: AssignmentConditions,
    pub delegation_depth: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssignmentConditions {
    pub location: Option<String>,
    pub time_windows: Vec<TimeWindow>,
    pub required_attributes: HashMap<String, String>, // Simplified
    pub auto_revoke_conditions: Vec<RevocationCondition>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RevocationCondition {
    InactivityTimeout(Duration),
    AttributeChange(String, String), // Simplified
    LocationChange,
    TimeExpiry(DateTime<Utc>),
    SecurityEvent(String),
}