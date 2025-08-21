use actix_web::{web, App, HttpServer, HttpResponse};
use serde_json;

mod rbac;
mod abac;
mod hybrid;
mod middleware;
mod handlers;
mod types;

use hybrid::engine::HybridPolicyEngine;
use middleware::access::HybridAccessMiddlewareFactory;
use handlers::{user, document, health};
use rbac::engine::RbacEngine;
use rbac::role::{Role, RoleConstraints};
use rbac::permission::Permission;
use types::time::TimeWindow;
use types::common::{AttributeValue, Effect};
use abac::policy::{AbacPolicy, Target};
use abac::attribute::AttributeMatcher;
use abac::condition::{Condition, Operator};
use hybrid::policy::{PolicyType, HybridPolicy, RbacRequirement, CombinationLogic};
use chrono::{Duration, Weekday, NaiveTime};
use std::collections::HashMap;

fn setup_hybrid_engine() -> HybridPolicyEngine {
    // Setup RBAC
    let mut rbac_engine = RbacEngine::new();
    
    // Define roles with constraints
    let admin_constraints = RoleConstraints {
        max_duration: None,
        valid_time_windows: vec![],
        required_attributes: HashMap::new(),
        location_restrictions: vec![],
        concurrent_limit: Some(5),
    };

    let mut admin_permissions = Vec::new();
    admin_permissions.push(Permission {
        resource: "users".to_string(),
        action: "read".to_string(),
        conditions: vec![],
    });
    admin_permissions.push(Permission {
        resource: "users".to_string(),
        action: "update".to_string(),
        conditions: vec![],
    });
    admin_permissions.push(Permission {
        resource: "documents".to_string(),
        action: "read".to_string(),
        conditions: vec![],
    });
    admin_permissions.push(Permission {
        resource: "documents".to_string(),
        action: "update".to_string(),
        conditions: vec![],
    });

    let admin_role = Role {
        name: "admin".to_string(),
        permissions: admin_permissions,
        constraints: admin_constraints,
        hierarchy_level: 0,
    };

    let user_constraints = RoleConstraints {
        max_duration: Some(Duration::hours(8)),
        valid_time_windows: vec![TimeWindow {
            days_of_week: vec![Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu, Weekday::Fri],
            start_time: NaiveTime::from_hms_opt(9, 0, 0).unwrap(),
            end_time: NaiveTime::from_hms_opt(17, 0, 0).unwrap(),
            timezone: "UTC".to_string(),
            exceptions: vec![],
        }],
        required_attributes: HashMap::new(),
        location_restrictions: vec![],
        concurrent_limit: Some(3),
    };

    let mut user_permissions = Vec::new();
    user_permissions.push(Permission {
        resource: "documents".to_string(),
        action: "read".to_string(),
        conditions: vec!["ownership_required".to_string()],
    });

    let user_role = Role {
        name: "user".to_string(),
        permissions: user_permissions,
        constraints: user_constraints,
        hierarchy_level: 1,
    };

    rbac_engine.add_role(admin_role);
    rbac_engine.add_role(user_role);
    
    // Assign roles to users
    rbac_engine.assign_role_to_user("alice", "admin");
    rbac_engine.assign_role_to_user("bob", "user");

    // Create hybrid engine
    let mut hybrid_engine = HybridPolicyEngine::new(rbac_engine);

    // Add RBAC policy for admin access to users
    hybrid_engine.add_policy(PolicyType::Rbac(rbac::policy::RbacPolicy {
        id: "admin-users-access".to_string(),
        required_role: "admin".to_string(),
        resource: "users".to_string(),
        action: "read".to_string(),
    }));

    // Add ABAC policy for document ownership
    hybrid_engine.add_policy(PolicyType::Abac(AbacPolicy {
        id: "owner-read-documents".to_string(),
        effect: Effect::Permit,
        target: Target {
            subject: None,
            resource: Some(AttributeMatcher {
                name: "type_name".to_string(),
                operator: Operator::Equals,
                value: AttributeValue::String("documents".to_string()),
            }),
            action: Some(AttributeMatcher {
                name: "name".to_string(),
                operator: Operator::Equals,
                value: AttributeValue::String("read".to_string()),
            }),
            environment: None,
        },
        condition: Some(Condition::Attribute(AttributeMatcher {
            name: "owner".to_string(),
            operator: Operator::IsOwner,
            value: AttributeValue::Boolean(true),
        })),
    }));

    // Add hybrid policy: Users can read their own documents during business hours
    hybrid_engine.add_policy(PolicyType::Hybrid(HybridPolicy {
        id: "user-own-docs-business-hours".to_string(),
        rbac_requirement: RbacRequirement::AnyRole(vec!["user".to_string()]),
        abac_conditions: vec![
            Condition::Attribute(AttributeMatcher {
                name: "owner".to_string(),
                operator: Operator::IsOwner,
                value: AttributeValue::Boolean(true),
            }),
            Condition::Attribute(AttributeMatcher {
                name: "current_time".to_string(),
                operator: Operator::InTimeWindow,
                value: AttributeValue::String("BUSINESS_HOURS".to_string()),
            }),
        ],
        combination_logic: CombinationLogic::RbacAndAbac,
    }));

    // Add time-based emergency access policy
    hybrid_engine.add_policy(PolicyType::Abac(AbacPolicy {
        id: "emergency-access".to_string(),
        effect: Effect::Permit,
        target: Target {
            subject: None,
            resource: None,
            action: None,
            environment: Some(AttributeMatcher {
                name: "emergency_mode".to_string(),
                operator: Operator::Equals,
                value: AttributeValue::Boolean(true),
            }),
        },
        condition: Some(Condition::Attribute(AttributeMatcher {
            name: "current_time".to_string(),
            operator: Operator::InTimeWindow,
            value: AttributeValue::String("EMERGENCY".to_string()),
        })),
    }));

    hybrid_engine
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let hybrid_engine = setup_hybrid_engine();

    println!("Starting Hybrid RBAC-ABAC server on http://127.0.0.1:8080");
    println!("Example endpoints:");
    println!("  GET /users/123 (requires admin role)");
    println!("  GET /documents/456 (requires ownership or admin)");
    println!("  Use headers: x-user-id=alice, x-user-roles=admin");

    HttpServer::new(move || {
        App::new()
            .wrap(HybridAccessMiddlewareFactory::new(hybrid_engine.clone()))
            .service(
                web::scope("/api")
                    .route("/users/{id}", web::get().to(user::get_user))
                    .route("/users/{id}", web::put().to(user::update_user))
                    .route("/documents/{id}", web::get().to(document::get_document))
                    .route("/documents/{id}", web::put().to(document::update_document))
                    .route("/health", web::get().to(health::health_check))
            )
            .route("/", web::get().to(|| async {
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "Hybrid RBAC-ABAC Access Control System",
                    "version": "1.0.0",
                    "endpoints": [
                        "GET /api/users/{id}",
                        "PUT /api/users/{id}",
                        "GET /api/documents/{id}",
                        "PUT /api/documents/{id}",
                        "GET /api/health"
                    ]
                }))
            }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}