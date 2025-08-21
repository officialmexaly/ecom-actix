use crate::rbac::policy::RbacPolicy;
use crate::abac::policy::AbacPolicy;
use crate::abac::condition::Condition;
use crate::rbac::permission::Permission;

// Hybrid Policy Types
#[derive(Debug, Clone)]
pub enum PolicyType {
    Rbac(RbacPolicy),
    Abac(AbacPolicy),
    Hybrid(HybridPolicy),
}

#[derive(Debug, Clone)]
pub struct HybridPolicy {
    pub id: String,
    pub rbac_requirement: RbacRequirement,
    pub abac_conditions: Vec<Condition>,
    pub combination_logic: CombinationLogic,
}

#[derive(Debug, Clone)]
pub enum RbacRequirement {
    AnyRole(Vec<String>),
    AllRoles(Vec<String>),
    Permission(Permission),
}

#[derive(Debug, Clone)]
pub enum CombinationLogic {
    RbacAndAbac,  // Both RBAC and ABAC must pass
    RbacOrAbac,   // Either RBAC or ABAC must pass
    RbacThenAbac, // RBAC first, then ABAC for fine-grained control
}