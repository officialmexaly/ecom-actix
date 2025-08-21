use crate::abac::attribute::AttributeMatcher;
use crate::rbac::permission::Permission;

#[derive(Debug, Clone)]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    In,
    TimeWindow,   // Time-based access with sophisticated rules
    HasRole,      // Special operator for RBAC integration
    IsOwner,      // Check if subject owns the resource
    InTimeWindow, // Check if current time falls within allowed windows
    HasAttribute, // Check if subject has required attribute
    LocationMatch, // Check if current location matches requirement
    SessionValid,  // Check if user session is valid and active
    DelegationValid, // Check if role was properly delegated
}

#[derive(Debug, Clone)]
pub enum Condition {
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Attribute(AttributeMatcher),
    RbacCheck(RbacRequirement),
}

#[derive(Debug, Clone)]
pub enum RbacRequirement {
    AnyRole(Vec<String>),
    AllRoles(Vec<String>),
    Permission(Permission),
}