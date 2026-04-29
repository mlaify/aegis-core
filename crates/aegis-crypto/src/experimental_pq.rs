use blake3::Hasher;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};

use crate::{CryptoError, KeyAgreement};

/// Experimental-only placeholder for future PQ KEM integration.
///
/// This is not a real PQ algorithm. It exists to validate trait boundaries and
/// feature-gated wiring without affecting default builds.
#[derive(Debug, Clone, Default)]
pub struct ExperimentalPqKem;

impl ExperimentalPqKem {
    pub fn suite_label(&self) -> &'static str {
        "AMP-HYBRID-PQ-PLACEHOLDER-EXPERIMENTAL"
    }
}

impl KeyAgreement for ExperimentalPqKem {
    fn derive_shared_secret(
        &self,
        local_private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if local_private_key.is_empty() || peer_public_key.is_empty() {
            return Err(CryptoError::InvalidKeyMaterial);
        }

        // Deterministic test-only placeholder: this is NOT cryptographic KEM.
        let mut hasher = Hasher::new();
        hasher.update(local_private_key);
        hasher.update(peer_public_key);
        Ok(hasher.finalize().as_bytes().to_vec())
    }
}

/// Experimental Kyber/ML-KEM-compatible wrapper backed by `pqcrypto-kyber`.
///
/// This remains non-production and is feature-gated for local experimentation.
#[derive(Debug, Clone, Default)]
pub struct ExperimentalKyber768Kem;

impl ExperimentalKyber768Kem {
    pub fn suite_label(&self) -> &'static str {
        "AMP-HYBRID-PQ-KYBER768-EXPERIMENTAL"
    }

    pub fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = kyber768::keypair();
        (
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        )
    }

    pub fn encapsulate_to_public_key(
        &self,
        peer_public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let public_key = kyber768::PublicKey::from_bytes(peer_public_key)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let (shared_secret, ciphertext) = kyber768::encapsulate(&public_key);
        Ok((
            ciphertext.as_bytes().to_vec(),
            shared_secret.as_bytes().to_vec(),
        ))
    }

    pub fn decapsulate_with_secret_key(
        &self,
        local_secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let secret_key = kyber768::SecretKey::from_bytes(local_secret_key)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let ciphertext = kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let shared_secret = kyber768::decapsulate(&ciphertext, &secret_key);
        Ok(shared_secret.as_bytes().to_vec())
    }
}

impl KeyAgreement for ExperimentalKyber768Kem {
    fn derive_shared_secret(
        &self,
        local_private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (ciphertext, _encapsulated_shared_secret) =
            self.encapsulate_to_public_key(peer_public_key)?;
        self.decapsulate_with_secret_key(local_private_key, &ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::{ExperimentalKyber768Kem, ExperimentalPqKem};
    use crate::{CryptoError, KeyAgreement};

    #[test]
    fn derives_placeholder_shared_secret() {
        let kem = ExperimentalPqKem;
        let secret = kem
            .derive_shared_secret(b"local-private", b"peer-public")
            .expect("derive");
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn empty_material_is_rejected() {
        let kem = ExperimentalPqKem;
        let result = kem.derive_shared_secret(b"", b"peer-public");
        assert!(matches!(result, Err(CryptoError::InvalidKeyMaterial)));
    }

    #[test]
    fn kyber_keypair_and_encap_decap_round_trip() {
        let kem = ExperimentalKyber768Kem;
        let (public_key, secret_key) = kem.generate_keypair();
        let (ciphertext, sender_secret) = kem
            .encapsulate_to_public_key(&public_key)
            .expect("encapsulate");
        let receiver_secret = kem
            .decapsulate_with_secret_key(&secret_key, &ciphertext)
            .expect("decapsulate");
        assert_eq!(sender_secret, receiver_secret);
    }

    #[test]
    fn kyber_invalid_material_is_rejected() {
        let kem = ExperimentalKyber768Kem;
        let result = kem.encapsulate_to_public_key(b"not-a-valid-public-key");
        assert!(matches!(result, Err(CryptoError::InvalidKeyMaterial)));
    }
}
