use std::{fs, path::PathBuf};

use aegis_proto::{Envelope, IdentityDocument, PrekeyBundle, PrivatePayload};
use serde::de::DeserializeOwned;
use serde_json::Value;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn fixture_value(name: &str) -> Value {
    let path = fixture_path(name);
    let raw = fs::read_to_string(path).expect("read fixture");
    serde_json::from_str(&raw).expect("parse fixture JSON")
}

fn round_trip_normalized<T>(name: &str) -> (T, Value)
where
    T: DeserializeOwned + serde::Serialize,
{
    let fixture_json = fixture_value(name);
    let parsed: T =
        serde_json::from_value(fixture_json.clone()).expect("deserialize fixture into Rust type");
    let pretty = serde_json::to_string_pretty(&parsed).expect("serialize type to pretty JSON");
    let normalized: Value = serde_json::from_str(&pretty).expect("parse pretty JSON");

    assert_eq!(
        normalized, fixture_json,
        "normalized JSON mismatch for fixture {name}"
    );

    (parsed, normalized)
}

#[test]
fn envelope_fixture_round_trip() {
    let (envelope, normalized) = round_trip_normalized::<Envelope>("envelope.v0.1.json");

    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.recipient_id.0, "amp:did:key:z6MkRecipient");
    assert_eq!(
        envelope.sender_hint.as_ref().map(|v| v.0.as_str()),
        Some("amp:did:key:z6MkSender")
    );
    assert_eq!(envelope.content_type, "message/private");
    assert_eq!(
        normalized["suite_id"],
        Value::String("DemoXChaCha20Poly1305".to_string())
    );
}

#[test]
fn private_payload_fixture_round_trip() {
    let (payload, normalized) =
        round_trip_normalized::<PrivatePayload>("private_payload.v0.1.json");

    assert_eq!(payload.private_headers.subject.as_deref(), Some("hello"));
    assert_eq!(payload.body.mime, "text/plain");
    assert_eq!(payload.attachments.len(), 1);
    assert_eq!(
        normalized["attachments"][0]["filename"],
        Value::String("note.txt".to_string())
    );
}

#[test]
fn identity_document_fixture_round_trip() {
    let (identity_doc, normalized) =
        round_trip_normalized::<IdentityDocument>("identity_document.v0.1.json");

    assert_eq!(identity_doc.version, 1);
    assert_eq!(identity_doc.identity_id.0, "amp:did:key:z6MkAlice");
    assert_eq!(identity_doc.aliases.len(), 2);
    assert_eq!(
        identity_doc.supported_suites,
        vec!["AMP-DEMO-XCHACHA20POLY1305"]
    );
    assert_eq!(normalized["signature"], Value::Null);
}

#[test]
fn prekey_bundle_fixture_round_trip() {
    let (bundle, normalized) = round_trip_normalized::<PrekeyBundle>("prekey_bundle.v0.1.json");

    assert_eq!(bundle.identity_id.0, "amp:did:key:z6MkAlice");
    assert_eq!(bundle.signed_prekeys.len(), 1);
    assert_eq!(bundle.one_time_prekeys.len(), 1);
    assert_eq!(
        normalized["expires_at"],
        Value::String("2026-12-31T23:59:59Z".to_string())
    );
}
