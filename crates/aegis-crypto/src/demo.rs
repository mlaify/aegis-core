use aegis_proto::{EncryptedBlob, Envelope, PrivatePayload, SuiteId};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

use crate::{CryptoError, EnvelopeSigner, EnvelopeVerifier, KeyAgreement, PayloadCipher};

pub struct DemoSuite {
    key: [u8; 32],
}

impl DemoSuite {
    /// Local-development helper only. This passphrase-derived keying model is non-production.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let hash = blake3::hash(passphrase.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_bytes());
        Self { key }
    }

    pub fn from_signing_key_bytes(key_material: &[u8]) -> Result<Self, CryptoError> {
        if key_material.len() != 32 {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(key_material);
        Ok(Self { key })
    }

    pub fn from_signing_key_b64(signing_key_b64: &str) -> Result<Self, CryptoError> {
        let key = STANDARD
            .decode(signing_key_b64.as_bytes())
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Self::from_signing_key_bytes(&key)
    }
}

impl PayloadCipher for DemoSuite {
    fn suite_id(&self) -> SuiteId {
        SuiteId::DemoXChaCha20Poly1305
    }

    fn encrypt_payload(&self, payload: &PrivatePayload) -> Result<EncryptedBlob, CryptoError> {
        let serialized =
            serde_json::to_vec(payload).map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));

        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), serialized.as_ref())
            .map_err(|_| CryptoError::Encryption)?;

        Ok(EncryptedBlob {
            nonce_b64: STANDARD.encode(nonce),
            ciphertext_b64: STANDARD.encode(ciphertext),
        })
    }

    fn decrypt_payload(&self, blob: &EncryptedBlob) -> Result<PrivatePayload, CryptoError> {
        let nonce = STANDARD
            .decode(&blob.nonce_b64)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        let ciphertext = STANDARD
            .decode(&blob.ciphertext_b64)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        if nonce.len() != 24 {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| CryptoError::Decryption)?;

        serde_json::from_slice(&plaintext).map_err(|e| CryptoError::Serialization(e.to_string()))
    }
}

impl KeyAgreement for DemoSuite {}

impl EnvelopeSigner for DemoSuite {
    fn sign_envelope(&self, envelope: &Envelope) -> Result<String, CryptoError> {
        let mut to_sign = envelope.clone();
        to_sign.outer_signature_b64 = None;
        let encoded =
            serde_json::to_vec(&to_sign).map_err(|e| CryptoError::Serialization(e.to_string()))?;

        let signature = blake3::keyed_hash(&self.key, &encoded);
        Ok(STANDARD.encode(signature.as_bytes()))
    }
}

impl EnvelopeVerifier for DemoSuite {
    fn verify_envelope(&self, envelope: &Envelope, signature_b64: &str) -> Result<(), CryptoError> {
        let expected = self.sign_envelope(envelope)?;
        if expected == signature_b64 {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::{IdentityId, PrivateHeaders};

    #[test]
    fn encrypt_and_decrypt_payload_round_trip() {
        let suite = DemoSuite::from_passphrase("dev-passphrase");
        let payload = PrivatePayload {
            private_headers: PrivateHeaders {
                subject: Some("payload".to_string()),
                thread_id: Some("thread-1".to_string()),
                in_reply_to: None,
            },
            body: aegis_proto::MessageBody {
                mime: "text/plain".to_string(),
                content: "hello".to_string(),
            },
            attachments: vec![],
            extensions: serde_json::json!({ "k": "v" }),
        };

        let encrypted = suite.encrypt_payload(&payload).expect("encrypt");
        let decrypted = suite.decrypt_payload(&encrypted).expect("decrypt");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let suite = DemoSuite::from_passphrase("dev-passphrase");
        let payload = PrivatePayload {
            private_headers: PrivateHeaders {
                subject: Some("hi".to_string()),
                thread_id: None,
                in_reply_to: None,
            },
            body: aegis_proto::MessageBody {
                mime: "text/plain".to_string(),
                content: "hello".to_string(),
            },
            attachments: vec![],
            extensions: serde_json::json!({}),
        };
        let encrypted = suite.encrypt_payload(&payload).expect("encrypt");
        let envelope = Envelope::new(
            IdentityId("amp:did:key:z6MkRecipient".to_string()),
            Some(IdentityId("amp:did:key:z6MkSender".to_string())),
            suite.suite_id(),
            encrypted,
        );

        let signature = suite.sign_envelope(&envelope).expect("sign");
        suite
            .verify_envelope(&envelope, &signature)
            .expect("verify");
    }

    #[test]
    fn verify_fails_for_tampered_envelope() {
        let suite = DemoSuite::from_passphrase("dev-passphrase");
        let payload = PrivatePayload {
            private_headers: PrivateHeaders {
                subject: Some("hi".to_string()),
                thread_id: None,
                in_reply_to: None,
            },
            body: aegis_proto::MessageBody {
                mime: "text/plain".to_string(),
                content: "hello".to_string(),
            },
            attachments: vec![],
            extensions: serde_json::json!({}),
        };
        let encrypted = suite.encrypt_payload(&payload).expect("encrypt");
        let mut envelope = Envelope::new(
            IdentityId("amp:did:key:z6MkRecipient".to_string()),
            Some(IdentityId("amp:did:key:z6MkSender".to_string())),
            suite.suite_id(),
            encrypted,
        );

        let signature = suite.sign_envelope(&envelope).expect("sign");
        envelope.content_type = "message/private-tampered".to_string();
        let result = suite.verify_envelope(&envelope, &signature);
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn key_agreement_is_explicitly_unsupported_for_demo_suite() {
        let suite = DemoSuite::from_passphrase("dev-passphrase");
        let result = suite.derive_shared_secret(b"local", b"peer");
        assert!(matches!(result, Err(CryptoError::KeyAgreementUnsupported)));
    }
}
