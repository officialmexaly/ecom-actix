#[derive(Debug, Clone)]
pub struct RbacPolicy {
    pub id: String,
    pub required_role: String,
    pub resource: String,
    pub action: String,
}