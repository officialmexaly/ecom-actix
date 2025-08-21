use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration, Weekday, NaiveTime, Datelike};
use crate::rbac::{Role, DynamicRoleAssignment, AssignmentConditions, RevocationCondition, RoleDelegation, DelegationConditions, UserSession};
use crate::types::{TimeWindow, AttributeValue, ExceptionType};
use crate::middleware::context::AccessContext;
use crate::abac::attribute::Environment;

#[derive(Debug, Clone)]
pub struct RbacEngine {
    pub roles: HashMap<String, Role>,
    pub user_roles: HashMap<String, Vec<DynamicRoleAssignment>>, // Changed to Vec
    pub role_hierarchy: HashMap<String, Vec<String>>, // role -> inherited roles
    pub delegations: Vec<RoleDelegation>,
    pub active_sessions: HashMap<String, Vec<UserSession>>, // user_id -> sessions
}

impl RbacEngine {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            user_roles: HashMap::new(),
            role_hierarchy: HashMap::new(),
            delegations: Vec::new(),
            active_sessions: HashMap::new(),
        }
    }

    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    pub fn set_role_hierarchy(&mut self, parent_role: &str, child_roles: Vec<String>) {
        self.role_hierarchy.insert(parent_role.to_string(), child_roles);
    }

    pub fn assign_role_dynamic(
        &mut self, 
        user_id: &str, 
        role_name: &str, 
        assigned_by: &str,
        duration: Option<Duration>,
        conditions: AssignmentConditions
    ) -> Result<(), String> {
        // Check if assigner has permission to assign this role
        if !self.can_assign_role(assigned_by, role_name) {
            return Err("Insufficient privileges to assign role".to_string());
        }

        let expires_at = duration.map(|d| Utc::now() + d);
        
        let assignment = DynamicRoleAssignment {
            role_name: role_name.to_string(),
            assigned_at: Utc::now(),
            expires_at,
            assigned_by: assigned_by.to_string(),
            conditions,
            delegation_depth: 0,
        };

        self.user_roles
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(assignment);

        Ok(())
    }

    pub fn assign_role_to_user(&mut self, user_id: &str, role_name: &str) {
        let conditions = AssignmentConditions {
            location: None,
            time_windows: Vec::new(),
            required_attributes: HashMap::new(),
            auto_revoke_conditions: Vec::new(),
        };

        let assignment = DynamicRoleAssignment {
            role_name: role_name.to_string(),
            assigned_at: Utc::now(),
            expires_at: None,
            assigned_by: "system".to_string(),
            conditions,
            delegation_depth: 0,
        };

        self.user_roles
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(assignment);
    }

    pub fn delegate_role(
        &mut self,
        delegator: &str,
        delegatee: &str,
        role: &str,
        duration: Duration,
        conditions: DelegationConditions,
    ) -> Result<String, String> {
        // Check if delegator has the role and can delegate
        if !self.has_active_role(delegator, role) {
            return Err("Delegator does not have the role".to_string());
        }

        // Check delegation depth
        let current_depth = self.get_delegation_depth(delegator, role);
        if current_depth >= 3 { // Use fixed value instead of conditions.max_depth
            return Err("Maximum delegation depth exceeded".to_string());
        }

        let delegation_id = format!("del_{}", Utc::now().timestamp());
        let delegation = RoleDelegation {
            id: delegation_id.clone(),
            delegator: delegator.to_string(),
            delegatee: delegatee.to_string(),
            role: role.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + duration,
            conditions: conditions.clone(),
            max_depth: 3, // Default max depth
        };

        self.delegations.push(delegation);

        // Create dynamic role assignment for delegatee
        let assignment_conditions = AssignmentConditions {
            location: None,
            time_windows: conditions.time_windows,
            required_attributes: HashMap::new(),
            auto_revoke_conditions: vec![
                RevocationCondition::TimeExpiry(Utc::now() + duration)
            ],
        };

        let assignment = DynamicRoleAssignment {
            role_name: role.to_string(),
            assigned_at: Utc::now(),
            expires_at: Some(Utc::now() + duration),
            assigned_by: delegator.to_string(),
            conditions: assignment_conditions,
            delegation_depth: current_depth + 1,
        };

        self.user_roles
            .entry(delegatee.to_string())
            .or_insert_with(Vec::new)
            .push(assignment);

        Ok(delegation_id)
    }

    pub fn revoke_role(&mut self, user_id: &str, role_name: &str, revoked_by: &str) -> Result<(), String> {
        if !self.can_revoke_role(revoked_by, role_name) {
            return Err("Insufficient privileges to revoke role".to_string());
        }

        if let Some(user_roles) = self.user_roles.get_mut(user_id) {
            user_roles.retain(|assignment| assignment.role_name != role_name);
        }

        Ok(())
    }

    pub fn cleanup_expired_assignments(&mut self) {
        let now = Utc::now();
        
        for user_roles in self.user_roles.values_mut() {
            user_roles.retain(|assignment| {
                if let Some(expires_at) = assignment.expires_at {
                    expires_at > now
                } else {
                    true
                }
            });
        }

        // Clean up expired delegations
        self.delegations.retain(|delegation| delegation.expires_at > now);
    }

    pub fn start_user_session(&mut self, user_id: &str, session_id: &str, location: Option<String>, device_info: &str) {
        let active_roles = self.get_active_roles_at_time(user_id, &Utc::now(), location.as_deref());
        
        let session = UserSession {
            session_id: session_id.to_string(),
            started_at: Utc::now(),
            last_activity: Utc::now(),
            location,
            device_info: device_info.to_string(),
            active_roles,
        };

        self.active_sessions
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(session);
    }

    pub fn update_session_activity(&mut self, user_id: &str, session_id: &str) {
        if let Some(sessions) = self.active_sessions.get_mut(user_id) {
            for session in sessions.iter_mut() {
                if session.session_id == session_id {
                    session.last_activity = Utc::now();
                    break;
                }
            }
        }
    }

    pub fn has_permission_with_context(
        &self, 
        user_id: &str, 
        resource: &str, 
        action: &str,
        context: &AccessContext
    ) -> bool {
        let current_time = Utc::now();
        let location = context.environment.attributes
            .get("location")
            .and_then(|l| if let AttributeValue::String(loc) = l { Some(loc.as_str()) } else { None });

        let active_roles = self.get_active_roles_at_time(user_id, &current_time, location);

        for role_name in active_roles {
            if let Some(role) = self.roles.get(&role_name) {
                for permission in &role.permissions {
                    if permission.resource == resource && permission.action == action {
                        // Check permission conditions
                        if self.check_permission_conditions(&permission.conditions, context, &current_time) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    pub fn get_active_roles_at_time(&self, user_id: &str, time: &DateTime<Utc>, location: Option<&str>) -> Vec<String> {
        let mut active_roles = Vec::new();

        if let Some(user_assignments) = self.user_roles.get(user_id) {
            for assignment in user_assignments {
                // Check expiration
                if let Some(expires_at) = assignment.expires_at {
                    if expires_at <= *time {
                        continue;
                    }
                }

                // Check time windows
                if !self.is_time_allowed(&assignment.conditions.time_windows, time) {
                    continue;
                }

                // Check location restrictions
                if let Some(required_location) = &assignment.conditions.location {
                    if location.map(|l| l != required_location).unwrap_or(true) {
                        continue;
                    }
                }

                active_roles.push(assignment.role_name.clone());

                // Add inherited roles
                if let Some(inherited) = self.role_hierarchy.get(&assignment.role_name) {
                    active_roles.extend(inherited.clone());
                }
            }
        }

        active_roles
    }

    fn is_time_allowed(&self, time_windows: &[TimeWindow], current_time: &DateTime<Utc>) -> bool {
        if time_windows.is_empty() {
            return true; // No restrictions
        }

        let current_weekday = current_time.weekday();
        let current_time_of_day = current_time.time();

        for window in time_windows {
            if window.days_of_week.contains(&current_weekday) {
                // Check for date exceptions
                let current_date = current_time.date_naive();
                let mut exception_applies = false;
                
                for exception in &window.exceptions {
                    if exception.date == current_date {
                        match exception.exception_type {
                            ExceptionType::Holiday => return false,
                            ExceptionType::Emergency => return true,
                            ExceptionType::Maintenance => {
                                // Limited access - could implement specific rules
                                exception_applies = true;
                            }
                        }
                    }
                }

                if !exception_applies {
                    if current_time_of_day >= window.start_time && current_time_of_day <= window.end_time {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn check_permission_conditions(
        &self,
        _conditions: &[String], // Simplified
        _context: &AccessContext,
        _current_time: &DateTime<Utc>
    ) -> bool {
        // Simplified implementation - always return true for now
        true
    }

    fn can_assign_role(&self, assigner: &str, role_name: &str) -> bool {
        // Check if assigner has admin role or specific delegation permissions
        self.has_active_role(assigner, "admin") || 
        self.has_active_role(assigner, &format!("{}-manager", role_name))
    }

    fn can_revoke_role(&self, revoker: &str, role_name: &str) -> bool {
        // Similar to assign but for revocation
        self.can_assign_role(revoker, role_name)
    }

    fn has_active_role(&self, user_id: &str, role_name: &str) -> bool {
        let current_time = Utc::now();
        self.get_active_roles_at_time(user_id, &current_time, None)
            .contains(&role_name.to_string())
    }

    fn get_delegation_depth(&self, user_id: &str, role: &str) -> u32 {
        if let Some(user_roles) = self.user_roles.get(user_id) {
            user_roles.iter()
                .filter(|assignment| role.is_empty() || assignment.role_name == role)
                .map(|assignment| assignment.delegation_depth)
                .max()
                .unwrap_or(0)
        } else {
            0
        }
    }

    pub fn check_time_window_advanced(&self, time_window_value: &AttributeValue, environment: &Environment) -> bool {
        let current_time = if let Some(AttributeValue::String(time_str)) = environment.attributes.get("current_time") {
            DateTime::parse_from_rfc3339(time_str).map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now())
        } else {
            Utc::now()
        };

        match time_window_value {
            AttributeValue::Array(time_specs) => {
                for spec in time_specs {
                    if self.parse_and_check_time_spec(spec, &current_time, environment) {
                        return true;
                    }
                }
                false
            },
            AttributeValue::String(time_spec) => {
                self.parse_and_check_time_spec(time_spec, &current_time, environment)
            },
            _ => false,
        }
    }

    fn parse_and_check_time_spec(&self, spec: &str, current_time: &DateTime<Utc>, environment: &Environment) -> bool {
        // Parse various time specification formats:
        // "09:00-17:00" - Daily time range
        // "MON-FRI:09:00-17:00" - Weekday time range  
        // "BUSINESS_HOURS" - Predefined business hours
        // "EMERGENCY" - Always allow during emergency
        // "MAINTENANCE:SUN:02:00-04:00" - Maintenance window
        
        if spec == "EMERGENCY" {
            return environment.attributes.get("emergency_mode")
                .map(|v| matches!(v, AttributeValue::Boolean(true)))
                .unwrap_or(false);
        }

        if spec == "BUSINESS_HOURS" {
            let weekday = current_time.weekday();
            let time_of_day = current_time.time();
            return matches!(weekday, Weekday::Mon | Weekday::Tue | Weekday::Wed | Weekday::Thu | Weekday::Fri) &&
                   time_of_day >= NaiveTime::from_hms_opt(9, 0, 0).unwrap() &&
                   time_of_day <= NaiveTime::from_hms_opt(17, 0, 0).unwrap();
        }

        if spec.starts_with("MAINTENANCE:") {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() >= 3 {
                let day_part = parts[1];
                let time_part = parts[2];
                
                if let Ok(target_weekday) = self.parse_weekday(day_part) {
                    if current_time.weekday() == target_weekday {
                        return self.parse_time_range(time_part, current_time);
                    }
                }
            }
            return false;
        }

        // Handle "MON-FRI:09:00-17:00" format
        if spec.contains(':') && spec.contains('-') {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() == 2 {
                let day_range = parts[0];
                let time_range = parts[1];
                
                if self.is_weekday_in_range(day_range, current_time.weekday()) {
                    return self.parse_time_range(time_range, current_time);
                }
            }
        }

        // Handle simple time range "09:00-17:00"
        if spec.contains('-') && !spec.contains(':') {
            return self.parse_time_range(spec, current_time);
        }

        false
    }

    fn parse_weekday(&self, day_str: &str) -> Result<Weekday, ()> {
        match day_str.to_uppercase().as_str() {
            "MON" | "MONDAY" => Ok(Weekday::Mon),
            "TUE" | "TUESDAY" => Ok(Weekday::Tue),
            "WED" | "WEDNESDAY" => Ok(Weekday::Wed),
            "THU" | "THURSDAY" => Ok(Weekday::Thu),
            "FRI" | "FRIDAY" => Ok(Weekday::Fri),
            "SAT" | "SATURDAY" => Ok(Weekday::Sat),
            "SUN" | "SUNDAY" => Ok(Weekday::Sun),
            _ => Err(()),
        }
    }

    fn is_weekday_in_range(&self, range: &str, current_day: Weekday) -> bool {
        if range.contains('-') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start_day), Ok(end_day)) = (self.parse_weekday(parts[0]), self.parse_weekday(parts[1])) {
                    let start_num = start_day.number_from_monday();
                    let end_num = end_day.number_from_monday();
                    let current_num = current_day.number_from_monday();
                    
                    return current_num >= start_num && current_num <= end_num;
                }
            }
        } else {
            if let Ok(target_day) = self.parse_weekday(range) {
                return current_day == target_day;
            }
        }
        false
    }

    fn parse_time_range(&self, time_range: &str, current_time: &DateTime<Utc>) -> bool {
        let parts: Vec<&str> = time_range.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start_time), Ok(end_time)) = (self.parse_time(parts[0]), self.parse_time(parts[1])) {
                let current_time_of_day = current_time.time();
                return current_time_of_day >= start_time && current_time_of_day <= end_time;
            }
        }
        false
    }

    fn parse_time(&self, time_str: &str) -> Result<NaiveTime, ()> {
        let parts: Vec<&str> = time_str.split(':').collect();
        if parts.len() == 2 {
            if let (Ok(hour), Ok(minute)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                if let Some(time) = NaiveTime::from_hms_opt(hour, minute, 0) {
                    return Ok(time);
                }
            }
        }
        Err(())
    }

    pub fn is_session_active(&self, session: &UserSession) -> bool {
        let now = Utc::now();
        let inactive_duration = now.signed_duration_since(session.last_activity);
        
        // Consider session inactive after 30 minutes of inactivity
        inactive_duration < Duration::minutes(30)
    }

    pub fn check_delegation_validity(&self, user_id: &str, value: &AttributeValue) -> bool {
        // Check if user has valid delegations
        if let AttributeValue::String(role_name) = value {
            self.delegations.iter().any(|delegation| {
                delegation.delegatee == user_id && 
                delegation.role == *role_name &&
                delegation.expires_at > Utc::now()
            })
        } else {
            false
        }
    }

    pub fn has_permission(&self, user_id: &str, resource: &str, action: &str) -> bool {
        // Legacy method - kept for compatibility
        let current_time = Utc::now();
        let active_roles = self.get_active_roles_at_time(user_id, &current_time, None);
        
        for role_name in active_roles {
            if let Some(role) = self.roles.get(&role_name) {
                for permission in &role.permissions {
                    if permission.resource == resource && permission.action == action {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_user_roles(&self, user_id: &str) -> Vec<String> {
        let current_time = Utc::now();
        self.get_active_roles_at_time(user_id, &current_time, None)
    }
}