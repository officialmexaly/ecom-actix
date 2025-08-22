// src/main.rs
use actix_web::{web, App, HttpServer, HttpResponse};
use serde_json;
use std::sync::{Arc, Mutex};

mod rbac;
mod abac;
mod hybrid;
mod middleware;
mod handlers;
mod types;
mod auth; // New authentication module

use hybrid::engine::HybridPolicyEngine;
use middleware::access::HybridAccessMiddlewareFactory;
use auth::{AuthService, AuthMiddlewareFactory, CreateUserRequest, UserProfile};
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

fn setup_auth_service(rbac_engine: RbacEngine) -> AuthService {
    let mut auth_service = AuthService::new(rbac_engine);

    // Create default admin user
    let admin_profile = UserProfile {
        first_name: "Admin".to_string(),
        last_name: "User".to_string(),
        department: Some("IT".to_string()),
        phone: None,
        attributes: HashMap::new(),
    };

    let admin_request = CreateUserRequest {
        username: "admin".to_string(),
        email: "admin@example.com".to_string(),
        password: "Admin123!@#".to_string(),
        roles: vec!["admin".to_string()],
        profile: admin_profile,
    };

    if let Err(e) = auth_service.create_user(admin_request) {
        eprintln!("Warning: Could not create default admin user: {}", e);
    }

    // Create default regular user
    let user_profile = UserProfile {
        first_name: "John".to_string(),
        last_name: "Doe".to_string(),
        department: Some("Marketing".to_string()),
        phone: Some("+1234567890".to_string()),
        attributes: HashMap::new(),
    };

    let user_request = CreateUserRequest {
        username: "user".to_string(),
        email: "user@example.com".to_string(),
        password: "User123!@#".to_string(),
        roles: vec!["user".to_string()],
        profile: user_profile,
    };

    if let Err(e) = auth_service.create_user(user_request) {
        eprintln!("Warning: Could not create default user: {}", e);
    }

    auth_service
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    // Setup RBAC engine
    let rbac_engine = {
        let mut engine = RbacEngine::new();
        
        // Define roles
        let admin_role = Role {
            name: "admin".to_string(),
            permissions: vec![
                Permission {
                    resource: "users".to_string(),
                    action: "read".to_string(),
                    conditions: vec![],
                },
                Permission {
                    resource: "users".to_string(),
                    action: "update".to_string(),
                    conditions: vec![],
                },
                Permission {
                    resource: "documents".to_string(),
                    action: "read".to_string(),
                    conditions: vec![],
                },
                Permission {
                    resource: "documents".to_string(),
                    action: "update".to_string(),
                    conditions: vec![],
                },
            ],
            constraints: RoleConstraints {
                max_duration: None,
                valid_time_windows: vec![],
                required_attributes: HashMap::new(),
                location_restrictions: vec![],
                concurrent_limit: Some(5),
            },
            hierarchy_level: 0,
        };

        let user_role = Role {
            name: "user".to_string(),
            permissions: vec![
                Permission {
                    resource: "documents".to_string(),
                    action: "read".to_string(),
                    conditions: vec!["ownership_required".to_string()],
                },
            ],
            constraints: RoleConstraints {
                max_duration: Some(Duration::hours(8)),
                valid_time_windows: vec![],
                required_attributes: HashMap::new(),
                location_restrictions: vec![],
                concurrent_limit: Some(3),
            },
            hierarchy_level: 1,
        };

        engine.add_role(admin_role);
        engine.add_role(user_role);
        engine
    };

    // Setup authentication service
    let auth_service = setup_auth_service(rbac_engine.clone());
    
    // Setup hybrid policy engine
    let hybrid_engine = setup_hybrid_engine();

    // Wrap auth service in Arc<Mutex<>> for sharing between middleware and handlers
    let auth_service_data = web::Data::new(Arc::new(Mutex::new(auth_service)));

    println!("🚀 Starting Hybrid RBAC-ABAC Authentication & Authorization Server");
    println!("📍 Server running on: http://127.0.0.1:8080");
    println!();
    println!("🔐 Authentication Endpoints:");
    println!("  POST /api/auth/register     - Register new user");
    println!("  POST /api/auth/login        - User login");
    println!("  POST /api/auth/refresh      - Refresh access token");
    println!("  POST /api/auth/logout       - User logout");
    println!("  GET  /api/auth/profile      - Get user profile");
    println!("  POST /api/auth/change-password - Change password");
    println!("  POST /api/auth/reset-password  - Request password reset");
    println!("  POST /api/auth/reset           - Reset password with token");
    println!();
    println!("🛡️ Protected Resource Endpoints:");
    println!("  GET  /api/users/{{id}}        - Get user (requires admin role)");
    println!("  PUT  /api/users/{{id}}        - Update user (requires admin role)");  
    println!("  GET  /api/documents/{{id}}    - Get document (requires ownership or admin)");
    println!("  PUT  /api/documents/{{id}}    - Update document (requires ownership or admin)");
    println!();
    println!("👤 Default Users:");
    println!("  Username: admin | Password: Admin123!@# | Roles: admin");
    println!("  Username: user  | Password: User123!@#  | Roles: user");
    println!();
    println!("📖 Usage Example:");
    println!("  1. POST /api/auth/login with username and password");
    println!("  2. Use returned access_token in Authorization header: 'Bearer <token>'");
    println!("  3. Access protected endpoints with the token");

    HttpServer::new(move || {
        App::new()
            .app_data(auth_service_data.clone())
            // Authentication routes (no auth/authz required)
            .service(
                web::scope("/api/auth")
                    .route("/register", web::post().to(auth::handlers::register))
                    .route("/login", web::post().to(auth::handlers::login))
                    .route("/refresh", web::post().to(auth::handlers::refresh_token))
                    .route("/reset-password", web::post().to(auth::handlers::request_password_reset))
                    .route("/reset", web::post().to(auth::handlers::reset_password))
                    .route("/validate", web::post().to(auth::handlers::validate_token))
                    // Protected auth routes (auth required)
                    .wrap(
                        AuthMiddlewareFactory::new((**auth_service_data.get_ref()).lock().unwrap().clone())
                            .with_skip_paths(vec![])
                    )
                    .route("/logout", web::post().to(auth::handlers::logout))
                    .route("/profile", web::get().to(auth::handlers::get_profile))
                    .route("/change-password", web::post().to(auth::handlers::change_password))
                    .route("/sessions/{user_id}", web::get().to(auth::handlers::get_user_sessions))
                    .route("/sessions/{user_id}/invalidate", web::post().to(auth::handlers::invalidate_user_sessions))
                    .route("/my-sessions", web::get().to(auth::handlers::get_my_sessions))
            )
            // Protected API routes (auth + authz required)
            .service(
                web::scope("/api")
                    .wrap(
                        AuthMiddlewareFactory::new((**auth_service_data.get_ref()).lock().unwrap().clone())
                            .with_skip_paths(vec![])
                    )
                    .wrap(HybridAccessMiddlewareFactory::new(hybrid_engine.clone()))
                    .route("/users/{id}", web::get().to(user::get_user))
                    .route("/users/{id}", web::put().to(user::update_user))
                    .route("/documents/{id}", web::get().to(document::get_document))
                    .route("/documents/{id}", web::put().to(document::update_document))
                    .route("/health", web::get().to(health::health_check))
            )
            // Public routes (no auth required)
            .route("/", web::get().to(|| async {
                HttpResponse::Ok().json(serde_json::json!({
                    "name": "Hybrid RBAC-ABAC Authentication & Authorization System",
                    "version": "1.0.0",
                    "features": [
                        "JWT-based authentication",
                        "Role-based access control (RBAC)",
                        "Attribute-based access control (ABAC)",
                        "Hybrid policy engine",
                        "Session management",
                        "Password reset functionality",
                        "Account lockout protection",
                        "Time-based access controls"
                    ],
                    "auth_endpoints": {
                        "register": "POST /api/auth/register",
                        "login": "POST /api/auth/login",
                        "refresh": "POST /api/auth/refresh",
                        "logout": "POST /api/auth/logout",
                        "profile": "GET /api/auth/profile",
                        "change_password": "POST /api/auth/change-password",
                        "reset_password": "POST /api/auth/reset-password"
                    },
                    "protected_endpoints": {
                        "users": "GET/PUT /api/users/{{id}}",
                        "documents": "GET/PUT /api/documents/{{id}}",
                        "health": "GET /api/health"
                    },
                    "default_users": {
                        "admin": {
                            "username": "admin",
                            "password": "Admin123!@#",
                            "roles": ["admin"]
                        },
                        "user": {
                            "username": "user", 
                            "password": "User123!@#",
                            "roles": ["user"]
                        }
                    }
                }))
            }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}