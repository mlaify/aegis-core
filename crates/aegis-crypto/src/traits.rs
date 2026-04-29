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
}

pub trait CryptoSuite {
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
