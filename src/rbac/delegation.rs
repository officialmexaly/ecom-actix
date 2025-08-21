use chrono::{DateTime, Utc};
use crate::rbac::permission::Permission;
use crate::types::time::TimeWindow;

#[derive(Debug, Clone)]
pub struct RoleDelegation {
    pub id: String,
    pub delegator: String,
    pub delegatee: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub conditions: DelegationConditions,
    pub max_depth: u32,
}

#[derive(Debug, Clone)]
pub struct DelegationConditions {
    pub can_further_delegate: bool,
    pub restricted_permissions: Vec<Permission>, // Changed from HashSet
    pub time_windows: Vec<TimeWindow>,
    pub approval_required: bool,
    pub max_depth: u32, // Added missing field
}