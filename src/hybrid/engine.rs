use crate::rbac::engine::RbacEngine;
use crate::abac::{Subject, Resource, Action, Environment, AttributeMatcher};
use crate::abac::condition::{Condition, Operator, RbacRequirement};
use crate::abac::policy::AbacPolicy;
use crate::hybrid::policy::{PolicyType, HybridPolicy, CombinationLogic};
use crate::types::common::{Decision, Effect, AttributeValue};
use crate::middleware::context::AccessContext;
use std::collections::HashMap;

// Hybrid Policy Engine
pub struct HybridPolicyEngine {
    rbac_engine: RbacEngine,
    policies: Vec<PolicyType>,
}

impl HybridPolicyEngine {
    pub fn new(rbac_engine: RbacEngine) -> Self {
        Self {
            rbac_engine,
            policies: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: PolicyType) {
        self.policies.push(policy);
    }

    pub fn evaluate(&self, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> Decision {
        let mut decisions = Vec::new();

        for policy in &self.policies {
            let decision = match policy {
                PolicyType::Rbac(rbac_policy) => self.evaluate_rbac_policy(rbac_policy, subject, resource, action),
                PolicyType::Abac(abac_policy) => self.evaluate_abac_policy(abac_policy, subject, resource, action, environment),
                PolicyType::Hybrid(hybrid_policy) => self.evaluate_hybrid_policy(hybrid_policy, subject, resource, action, environment),
            };
            decisions.push(decision);
        }

        // Policy combination: Deny overrides (any deny = deny, otherwise permit if any permit)
        if decisions.contains(&Decision::Deny) {
            Decision::Deny
        } else if decisions.contains(&Decision::Permit) {
            Decision::Permit
        } else {
            Decision::Deny
        }
    }

    fn evaluate_rbac_policy(&self, policy: &crate::rbac::policy::RbacPolicy, subject: &Subject, resource: &Resource, action: &Action) -> Decision {
        // Check if resource and action match
        if resource.type_name != policy.resource || action.name != policy.action {
            return Decision::NotApplicable;
        }

        // Check if user has required role
        if subject.roles.contains(&policy.required_role) {
            Decision::Permit
        } else {
            Decision::Deny
        }
    }

    fn evaluate_abac_policy(&self, policy: &AbacPolicy, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> Decision {
        if !self.matches_target(&policy.target, subject, resource, action, environment) {
            return Decision::NotApplicable;
        }

        if let Some(ref condition) = policy.condition {
            if !self.evaluate_condition(condition, subject, resource, action, environment) {
                return Decision::NotApplicable;
            }
        }

        match policy.effect {
            Effect::Permit => Decision::Permit,
            Effect::Deny => Decision::Deny,
        }
    }

    fn evaluate_hybrid_policy(&self, policy: &HybridPolicy, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> Decision {
        let rbac_result = self.evaluate_rbac_requirement(&policy.rbac_requirement, subject, resource, action);
        let abac_result = policy.abac_conditions.iter()
            .all(|condition| self.evaluate_condition(condition, subject, resource, action, environment));

        match policy.combination_logic {
            CombinationLogic::RbacAndAbac => {
                if rbac_result && abac_result {
                    Decision::Permit
                } else {
                    Decision::Deny
                }
            },
            CombinationLogic::RbacOrAbac => {
                if rbac_result || abac_result {
                    Decision::Permit
                } else {
                    Decision::Deny
                }
            },
            CombinationLogic::RbacThenAbac => {
                if rbac_result {
                    if abac_result {
                        Decision::Permit
                    } else {
                        Decision::Deny
                    }
                } else {
                    Decision::Deny
                }
            },
        }
    }

    fn evaluate_rbac_requirement(&self, requirement: &RbacRequirement, subject: &Subject, resource: &Resource, action: &Action) -> bool {
        match requirement {
            RbacRequirement::AnyRole(roles) => {
                roles.iter().any(|role| subject.roles.contains(role))
            },
            RbacRequirement::AllRoles(roles) => {
                roles.iter().all(|role| subject.roles.contains(role))
            },
            RbacRequirement::Permission(permission) => {
                // Create a mock context for permission checking
                let mock_env = Environment { attributes: HashMap::new() };
                let context = AccessContext {
                    subject: subject.clone(),
                    resource: resource.clone(),
                    action: action.clone(),
                    environment: mock_env,
                };
                self.rbac_engine.has_permission_with_context(&subject.id, &permission.resource, &permission.action, &context)
            },
        }
    }

    fn matches_target(&self, target: &crate::abac::policy::Target, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> bool {
        if let Some(ref matcher) = target.subject {
            if !self.matches_attribute_enhanced(matcher, subject, resource, action, environment) {
                return false;
            }
        }
        
        if let Some(ref matcher) = target.resource {
            if !self.matches_attribute_enhanced(matcher, subject, resource, action, environment) {
                return false;
            }
        }
        
        if let Some(ref matcher) = target.action {
            if !self.matches_attribute_enhanced(matcher, subject, resource, action, environment) {
                return false;
            }
        }
        
        if let Some(ref matcher) = target.environment {
            if !self.matches_attribute_enhanced(matcher, subject, resource, action, environment) {
                return false;
            }
        }
        
        true
    }

    fn matches_attribute_enhanced(&self, matcher: &AttributeMatcher, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> bool {
        match &matcher.operator {
            Operator::HasRole => {
                if let AttributeValue::String(role) = &matcher.value {
                    subject.roles.contains(role)
                } else {
                    false
                }
            },
            Operator::IsOwner => {
                if let Some(ref owner) = resource.owner {
                    owner == &subject.id
                } else {
                    false
                }
            },
            Operator::InTimeWindow => {
                self.rbac_engine.check_time_window_advanced(&matcher.value, environment)
            },
            Operator::HasAttribute => {
                if let AttributeValue::String(attr_name) = &matcher.value {
                    subject.attributes.contains_key(attr_name)
                } else {
                    false
                }
            },
            Operator::LocationMatch => {
                if let Some(AttributeValue::String(current_location)) = environment.attributes.get("location") {
                    if let AttributeValue::String(required_location) = &matcher.value {
                        current_location == required_location
                    } else if let AttributeValue::Array(allowed_locations) = &matcher.value {
                        allowed_locations.contains(current_location)
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            Operator::SessionValid => {
                if let Some(AttributeValue::String(session_id)) = environment.attributes.get("session_id") {
                    self.rbac_engine.active_sessions.get(&subject.id)
                        .map(|sessions| sessions.iter().any(|s| &s.session_id == session_id && self.rbac_engine.is_session_active(s)))
                        .unwrap_or(false)
                } else {
                    false
                }
            },
            Operator::DelegationValid => {
                self.rbac_engine.check_delegation_validity(&subject.id, &matcher.value)
            },
            Operator::TimeWindow => {
                self.rbac_engine.check_time_window_advanced(&matcher.value, environment)
            },
            _ => {
                // Check in all attribute collections
                self.check_standard_attributes(matcher, subject, resource, action, environment)
            }
        }
    }

    fn check_standard_attributes(&self, matcher: &AttributeMatcher, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> bool {
        // Check subject attributes
        if let Some(attr_value) = subject.attributes.get(&matcher.name) {
            if self.apply_operator(&matcher.operator, attr_value, &matcher.value) {
                return true;
            }
        }

        // Check resource attributes
        if let Some(attr_value) = resource.attributes.get(&matcher.name) {
            if self.apply_operator(&matcher.operator, attr_value, &matcher.value) {
                return true;
            }
        }

        // Check action attributes
        if let Some(attr_value) = action.attributes.get(&matcher.name) {
            if self.apply_operator(&matcher.operator, attr_value, &matcher.value) {
                return true;
            }
        }

        // Check environment attributes
        if let Some(attr_value) = environment.attributes.get(&matcher.name) {
            if self.apply_operator(&matcher.operator, attr_value, &matcher.value) {
                return true;
            }
        }

        false
    }

    fn apply_operator(&self, operator: &Operator, left: &AttributeValue, right: &AttributeValue) -> bool {
        match operator {
            Operator::Equals => left == right,
            Operator::NotEquals => left != right,
            Operator::Contains => {
                match (left, right) {
                    (AttributeValue::String(l), AttributeValue::String(r)) => l.contains(r),
                    (AttributeValue::Array(l), AttributeValue::String(r)) => l.contains(r),
                    _ => false,
                }
            },
            Operator::GreaterThan => {
                match (left, right) {
                    (AttributeValue::Number(l), AttributeValue::Number(r)) => l > r,
                    _ => false,
                }
            },
            Operator::LessThan => {
                match (left, right) {
                    (AttributeValue::Number(l), AttributeValue::Number(r)) => l < r,
                    _ => false,
                }
            },
            Operator::In => {
                match right {
                    AttributeValue::Array(array) => {
                        if let AttributeValue::String(val) = left {
                            array.contains(val)
                        } else {
                            false
                        }
                    },
                    _ => false,
                }
            },
            _ => false, // Other operators handled elsewhere
        }
    }

    fn evaluate_condition(&self, condition: &Condition, subject: &Subject, resource: &Resource, action: &Action, environment: &Environment) -> bool {
        match condition {
            Condition::And(conditions) => {
                conditions.iter().all(|c| self.evaluate_condition(c, subject, resource, action, environment))
            },
            Condition::Or(conditions) => {
                conditions.iter().any(|c| self.evaluate_condition(c, subject, resource, action, environment))
            },
            Condition::Attribute(matcher) => {
                self.matches_attribute_enhanced(matcher, subject, resource, action, environment)
            },
            Condition::RbacCheck(rbac_req) => {
                self.evaluate_rbac_requirement(rbac_req, subject, resource, action)
            },
        }
    }
}

impl Clone for HybridPolicyEngine {
    fn clone(&self) -> Self {
        Self {
            rbac_engine: self.rbac_engine.clone(),
            policies: self.policies.clone(),
        }
    }
}