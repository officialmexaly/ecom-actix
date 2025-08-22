// src/auth/middleware.rs
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse, Result, body::EitherBody,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::cell::RefCell;
use crate::auth::service::AuthService;
use crate::auth::user::UserInfo;

// Authentication middleware that validates JWT tokens
pub struct AuthMiddleware<S> {
    service: Rc<S>,
    auth_service: Rc<RefCell<AuthService>>,
    skip_paths: Vec<String>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let auth_service = self.auth_service.clone();
        let skip_paths = self.skip_paths.clone();

        Box::pin(async move {
            let path = req.path();
            
            // Skip authentication for certain paths
            if skip_paths.iter().any(|skip_path| path.starts_with(skip_path)) {
                let res = service.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // Extract authorization header
            let auth_header = req.headers().get("Authorization")
                .and_then(|h| h.to_str().ok());

            if let Some(auth_header) = auth_header {
                // Extract and verify token
                let auth_service_ref = auth_service.borrow();
                match auth_service_ref.jwt_manager.extract_token_from_header(auth_header) {
                    Ok(token) => {
                        match auth_service_ref.verify_token(&token) {
                            Ok(user_info) => {
                                // Token is valid, add user info to request extensions
                                req.extensions_mut().insert(user_info.clone());
                                
                                // Update session activity
                                if let Ok(claims) = auth_service_ref.jwt_manager.verify_access_token(&token) {
                                    drop(auth_service_ref); // Release borrow
                                    auth_service.borrow_mut().update_session_activity(&claims.session_id);
                                } else {
                                    drop(auth_service_ref);
                                }
                                
                                let res = service.call(req).await?;
                                Ok(res.map_into_left_body())
                            },
                            Err(auth_error) => {
                                drop(auth_service_ref);
                                let response = HttpResponse::Unauthorized()
                                    .json(serde_json::json!({
                                        "error": "Authentication failed",
                                        "message": auth_error.to_string()
                                    }));
                                Ok(req.into_response(response).map_into_right_body())
                            }
                        }
                    },
                    Err(error) => {
                        drop(auth_service_ref);
                        let response = HttpResponse::Unauthorized()
                            .json(serde_json::json!({
                                "error": "Invalid authorization header",
                                "message": error
                            }));
                        Ok(req.into_response(response).map_into_right_body())
                    }
                }
            } else {
                // No authorization header
                let response = HttpResponse::Unauthorized()
                    .json(serde_json::json!({
                        "error": "Missing authorization header",
                        "message": "Authorization header is required"
                    }));
                Ok(req.into_response(response).map_into_right_body())
            }
        })
    }
}

pub struct AuthMiddlewareFactory {
    auth_service: Rc<RefCell<AuthService>>,
    skip_paths: Vec<String>,
}

impl AuthMiddlewareFactory {
    pub fn new(auth_service: AuthService) -> Self {
        Self {
            auth_service: Rc::new(RefCell::new(auth_service)),
            skip_paths: vec![
                "/api/auth/".to_string(),
                "/api/health".to_string(),
                "/".to_string(),
            ],
        }
    }

    pub fn with_skip_paths(mut self, paths: Vec<String>) -> Self {
        self.skip_paths = paths;
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service: Rc::new(service),
            auth_service: self.auth_service.clone(),
            skip_paths: self.skip_paths.clone(),
        }))
    }
}

// Helper function to extract user info from request
pub fn get_current_user(req: &ServiceRequest) -> Option<UserInfo> {
    req.extensions().get::<UserInfo>().cloned()
}