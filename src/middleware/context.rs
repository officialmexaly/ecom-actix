use actix_web::dev::ServiceRequest;
use std::collections::HashMap;
use crate::abac::{Subject, Resource, Action, Environment};
use crate::types::common::AttributeValue;

#[derive(Debug, Clone)]
pub struct AccessContext {
    pub subject: Subject,
    pub resource: Resource,
    pub action: Action,
    pub environment: Environment,
}

impl AccessContext {
    pub fn new(user_id: &str, user_roles: Vec<String>) -> Self {
        let mut environment_attrs = HashMap::new();
        environment_attrs.insert(
            "current_time".to_string(),
            AttributeValue::String(chrono::Utc::now().to_rfc3339())
        );

        Self {
            subject: Subject {
                id: user_id.to_string(),
                roles: user_roles,
                attributes: HashMap::new(),
            },
            resource: Resource {
                id: String::new(),
                type_name: String::new(),
                owner: None,
                attributes: HashMap::new(),
            },
            action: Action {
                name: String::new(),
                attributes: HashMap::new(),
            },
            environment: Environment {
                attributes: environment_attrs,
            },
        }
    }

    pub fn with_resource(mut self, id: &str, type_name: &str, owner: Option<&str>) -> Self {
        self.resource.id = id.to_string();
        self.resource.type_name = type_name.to_string();
        self.resource.owner = owner.map(String::from);
        self
    }

    pub fn with_action(mut self, name: &str) -> Self {
        self.action.name = name.to_string();
        self
    }

    pub fn with_subject_attr(mut self, name: &str, value: AttributeValue) -> Self {
        self.subject.attributes.insert(name.to_string(), value);
        self
    }

    pub fn with_resource_attr(mut self, name: &str, value: AttributeValue) -> Self {
        self.resource.attributes.insert(name.to_string(), value);
        self
    }

    pub fn with_environment_attr(mut self, name: &str, value: AttributeValue) -> Self {
        self.environment.attributes.insert(name.to_string(), value);
        self
    }
}

// Helper function to extract context from request
pub fn extract_context_from_request(req: &ServiceRequest) -> AccessContext {
    // Extract user information from headers, JWT, session, etc.
    let user_id = req.headers()
        .get("x-user-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("anonymous");

    let user_roles = req.headers()
        .get("x-user-roles")
        .and_then(|h| h.to_str().ok())
        .map(|roles| roles.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(Vec::new);

    // Extract resource and action from request path and method
    let path = req.path();
    let method = req.method().as_str();

    let (resource_type, resource_id) = extract_resource_from_path(path);
    let action = match method {
        "GET" => "read",
        "POST" => "create",
        "PUT" | "PATCH" => "update",
        "DELETE" => "delete",
        _ => "unknown",
    };

    AccessContext::new(user_id, user_roles)
        .with_resource(&resource_id, &resource_type, None)
        .with_action(action)
        .with_environment_attr("ip_address", 
                              AttributeValue::String(
                                  req.connection_info().realip_remote_addr()
                                     .unwrap_or("unknown").to_string()
                              ))
}

fn extract_resource_from_path(path: &str) -> (String, String) {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    
    if segments.len() >= 2 {
        (segments[0].to_string(), segments[1].to_string())
    } else if segments.len() == 1 {
        (segments[0].to_string(), "all".to_string())
    } else {
        ("unknown".to_string(), "unknown".to_string())
    }
}