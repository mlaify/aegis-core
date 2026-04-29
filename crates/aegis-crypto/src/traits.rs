use thiserror::Error;

use aegis_proto::{EncryptedBlob, Envelope, PrivatePayload, SuiteId};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("encryption failed")]
    Encryption,

    #[error("decryption failed")]
    Decryption,

    #[error("invalid key material")]
    InvalidKeyMaterial,

    #[error("signature generation failed")]
    SigningFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("key agreement is not supported by this suite")]
    KeyAgreementUnsupported,
}

pub trait PayloadCipher {
    fn suite_id(&self) -> SuiteId;
    fn encrypt_payload(&self, payload: &PrivatePayload) -> Result<EncryptedBlob, CryptoError>;
    fn decrypt_payload(&self, blob: &EncryptedBlob) -> Result<PrivatePayload, CryptoError>;
}

pub trait EnvelopeSigner {
    fn sign_envelope(&self, envelope: &Envelope) -> Result<String, CryptoError>;
}

pub trait EnvelopeVerifier {
    fn verify_envelope(&self, envelope: &Envelope, signature_b64: &str) -> Result<(), CryptoError>;
}

pub trait KeyAgreement {
    /// Future-facing key agreement/KEM hook. v0.1 demo suites MAY return `KeyAgreementUnsupported`.
    fn derive_shared_secret(
        &self,
        _local_private_key: &[u8],
        _peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::KeyAgreementUnsupported)
    }
}

/// Backward-compatible alias kept for v0.1 code paths that still refer to `CryptoSuite`.
pub trait CryptoSuite: PayloadCipher {}

impl<T: PayloadCipher> CryptoSuite for T {}
