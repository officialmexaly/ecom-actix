use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttributeValue {
    String(String),
    Number(i64),
    Boolean(bool),
    Array(Vec<String>),
}

#[derive(Debug, PartialEq, Clone)]
pub enum Decision {
    Permit,
    Deny,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    Permit,
    Deny,
}