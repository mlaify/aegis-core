use aegis_proto::{IdentityDocument, IdentityId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid identity id")]
    InvalidIdentityId,
}

pub fn parse_identity_id(input: &str) -> Result<IdentityId, IdentityError> {
    if input.starts_with("amp:did:key:") {
        Ok(IdentityId(input.to_string()))
    } else {
        Err(IdentityError::InvalidIdentityId)
    }
}

pub fn supports_suite(doc: &IdentityDocument, suite: &str) -> bool {
    doc.supported_suites.iter().any(|s| s == suite)
}
