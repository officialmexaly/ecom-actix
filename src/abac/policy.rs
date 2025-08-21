use crate::types::common::Effect;
use crate::abac::attribute::AttributeMatcher;
use crate::abac::condition::Condition;

#[derive(Debug, Clone)]
pub struct AbacPolicy {
    pub id: String,
    pub effect: Effect,
    pub target: Target,
    pub condition: Option<Condition>,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub subject: Option<AttributeMatcher>,
    pub resource: Option<AttributeMatcher>,
    pub action: Option<AttributeMatcher>,
    pub environment: Option<AttributeMatcher>,
}