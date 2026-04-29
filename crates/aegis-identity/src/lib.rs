use aegis_proto::{IdentityDocument, IdentityId};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid identity id")]
    InvalidIdentityId,
}

pub fn parse_identity_id(input: &str) -> Result<IdentityId, IdentityError> {
    if is_valid_identity_id(input) {
        Ok(IdentityId(input.to_string()))
    } else {
        Err(IdentityError::InvalidIdentityId)
    }
}

pub fn is_valid_identity_id(input: &str) -> bool {
    let Some(suffix) = input.strip_prefix("amp:did:key:") else {
        return false;
    };

    if suffix.is_empty() {
        return false;
    }

    suffix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub fn supports_suite(doc: &IdentityDocument, suite: &str) -> bool {
    doc.supported_suites.iter().any(|s| s == suite)
}

pub trait LocalIdentityStore {
    fn default_identity_id(&self) -> Result<Option<IdentityId>, IdentityError>;
    fn list_identity_ids(&self) -> Result<Vec<IdentityId>, IdentityError>;
}

pub trait AliasResolver {
    fn resolve_alias(&self, alias: &str) -> Result<Option<IdentityId>, IdentityError>;
}

pub trait IdentityDocumentResolver {
    fn resolve_identity_document(
        &self,
        identity_id: &IdentityId,
    ) -> Result<Option<IdentityDocument>, IdentityError>;
}

#[derive(Debug, Default, Clone)]
pub struct StaticAliasResolver {
    map: HashMap<String, IdentityId>,
}

impl StaticAliasResolver {
    pub fn new(map: HashMap<String, IdentityId>) -> Self {
        Self { map }
    }
}

impl AliasResolver for StaticAliasResolver {
    fn resolve_alias(&self, alias: &str) -> Result<Option<IdentityId>, IdentityError> {
        Ok(self.map.get(alias).cloned())
    }
}

#[derive(Debug, Default, Clone)]
pub struct StaticIdentityDocumentResolver {
    map: HashMap<String, IdentityDocument>,
}

impl StaticIdentityDocumentResolver {
    pub fn new(map: HashMap<String, IdentityDocument>) -> Self {
        Self { map }
    }
}

impl IdentityDocumentResolver for StaticIdentityDocumentResolver {
    fn resolve_identity_document(
        &self,
        identity_id: &IdentityId,
    ) -> Result<Option<IdentityDocument>, IdentityError> {
        Ok(self.map.get(&identity_id.0).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::PublicKeyRecord;
    use std::collections::HashMap;

    #[test]
    fn parse_identity_id_accepts_canonical_prefix() {
        let id = parse_identity_id("amp:did:key:z6MkRecipient").expect("valid id");
        assert_eq!(id.0, "amp:did:key:z6MkRecipient");
    }

    #[test]
    fn parse_identity_id_rejects_non_canonical_prefix() {
        assert!(parse_identity_id("mailto:alice@example.com").is_err());
    }

    #[test]
    fn parse_identity_id_rejects_empty_suffix() {
        assert!(parse_identity_id("amp:did:key:").is_err());
    }

    #[test]
    fn parse_identity_id_rejects_invalid_characters() {
        assert!(parse_identity_id("amp:did:key:z6MkRecipient/extra").is_err());
    }

    #[test]
    fn static_alias_resolver_returns_matching_identity() {
        let mut map = HashMap::new();
        map.insert(
            "alice@mesh".to_string(),
            IdentityId("amp:did:key:z6MkAlice".to_string()),
        );
        let resolver = StaticAliasResolver::new(map);

        let resolved = resolver.resolve_alias("alice@mesh").expect("resolve alias");
        assert_eq!(resolved.unwrap().0, "amp:did:key:z6MkAlice");
        assert!(resolver
            .resolve_alias("unknown@mesh")
            .expect("resolve unknown")
            .is_none());
    }

    #[test]
    fn static_identity_document_resolver_returns_matching_document() {
        let identity = IdentityId("amp:did:key:z6MkAlice".to_string());
        let doc = IdentityDocument {
            version: 1,
            identity_id: identity.clone(),
            aliases: vec!["alice@mesh".to_string()],
            signing_keys: vec![PublicKeyRecord {
                key_id: "sig-1".to_string(),
                algorithm: "ed25519".to_string(),
                public_key_b64: "c2ln".to_string(),
            }],
            encryption_keys: vec![],
            supported_suites: vec!["AMP-DEMO-XCHACHA20POLY1305".to_string()],
            relay_endpoints: vec![],
            signature: None,
        };

        let mut map = HashMap::new();
        map.insert(identity.0.clone(), doc.clone());
        let resolver = StaticIdentityDocumentResolver::new(map);

        let resolved = resolver
            .resolve_identity_document(&identity)
            .expect("resolve document")
            .expect("found doc");
        assert_eq!(resolved.identity_id.0, doc.identity_id.0);

        let missing = resolver
            .resolve_identity_document(&IdentityId("amp:did:key:z6MkMissing".to_string()))
            .expect("resolve missing");
        assert!(missing.is_none());
    }
}
