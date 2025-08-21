use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::common::AttributeValue;
use crate::abac::condition::Operator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: AttributeValue,
}

#[derive(Debug, Clone)]
pub struct Subject {
    pub id: String,
    pub roles: Vec<String>, // Integration with RBAC
    pub attributes: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub id: String,
    pub type_name: String,
    pub owner: Option<String>,
    pub attributes: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone)]
pub struct Action {
    pub name: String,
    pub attributes: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone)]
pub struct Environment {
    pub attributes: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone)]
pub struct AttributeMatcher {
    pub name: String,
    pub operator: Operator,
    pub value: AttributeValue,
}