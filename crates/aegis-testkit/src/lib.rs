use aegis_proto::{IdentityId, MessageBody, PrivateHeaders, PrivatePayload};

pub fn sample_payload() -> PrivatePayload {
    PrivatePayload {
        private_headers: PrivateHeaders {
            subject: Some("hello".to_string()),
            thread_id: Some("thr-01".to_string()),
            in_reply_to: None,
        },
        body: MessageBody {
            mime: "text/plain".to_string(),
            content: "hello from aegis".to_string(),
        },
        attachments: vec![],
        extensions: serde_json::json!({}),
    }
}

pub fn sample_recipient() -> IdentityId {
    IdentityId("amp:did:key:z6MkRecipient".to_string())
}
