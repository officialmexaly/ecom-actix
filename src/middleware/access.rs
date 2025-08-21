use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse, Result, body::EitherBody,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;
use crate::hybrid::engine::HybridPolicyEngine;
use crate::middleware::context::extract_context_from_request;
use crate::types::common::Decision;

// Actix Web Integration
pub struct HybridAccessMiddleware<S> {
    service: Rc<S>,
    policy_engine: Rc<HybridPolicyEngine>,
}

impl<S, B> Service<ServiceRequest> for HybridAccessMiddleware<S>
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
        let policy_engine = self.policy_engine.clone();

        Box::pin(async move {
            // Extract context directly in the middleware
            let context = extract_context_from_request(&req);
            
            let decision = policy_engine.evaluate(
                &context.subject,
                &context.resource,
                &context.action,
                &context.environment,
            );

            match decision {
                Decision::Permit => {
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                },
                Decision::Deny | Decision::NotApplicable => {
                    let response = HttpResponse::Forbidden()
                        .json(serde_json::json!({
                            "error": "Access denied",
                            "decision": format!("{:?}", decision)
                        }));
                    Ok(req.into_response(response).map_into_right_body())
                }
            }
        })
    }
}

pub struct HybridAccessMiddlewareFactory {
    policy_engine: Rc<HybridPolicyEngine>,
}

impl HybridAccessMiddlewareFactory {
    pub fn new(policy_engine: HybridPolicyEngine) -> Self {
        Self {
            policy_engine: Rc::new(policy_engine),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for HybridAccessMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = HybridAccessMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(HybridAccessMiddleware {
            service: Rc::new(service),
            policy_engine: self.policy_engine.clone(),
        }))
    }
}