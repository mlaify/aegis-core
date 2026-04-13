use aegis_proto::Envelope;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreEnvelopeRequest {
    pub envelope: Envelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreEnvelopeResponse {
    pub accepted: bool,
    pub relay_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FetchEnvelopeResponse {
    pub envelopes: Vec<Envelope>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::{EncryptedBlob, IdentityId, SuiteId};

    fn sample_envelope() -> Envelope {
        Envelope::new(
            IdentityId("amp:did:key:z6MkRecipient".to_string()),
            Some(IdentityId("amp:did:key:z6MkSender".to_string())),
            SuiteId::DemoXChaCha20Poly1305,
            EncryptedBlob {
                nonce_b64: "bm9uY2U=".to_string(),
                ciphertext_b64: "Y2lwaGVydGV4dA==".to_string(),
            },
        )
    }

    #[test]
    fn store_envelope_request_json_round_trip() {
        let request = StoreEnvelopeRequest {
            envelope: sample_envelope(),
        };

        let json = serde_json::to_string(&request).expect("serialize store request");
        let decoded: StoreEnvelopeRequest =
            serde_json::from_str(&json).expect("deserialize store request");

        assert_eq!(decoded, request);
    }

    #[test]
    fn fetch_envelope_response_json_round_trip() {
        let response = FetchEnvelopeResponse {
            envelopes: vec![sample_envelope()],
        };

        let json = serde_json::to_string(&response).expect("serialize fetch response");
        let decoded: FetchEnvelopeResponse =
            serde_json::from_str(&json).expect("deserialize fetch response");

        assert_eq!(decoded, response);
    }
}
