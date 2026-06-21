use cred_core::{
    canonical_hash_hex, sign_presentation, verify_presentation_signature, CredPresentation,
    PresentedArtifact,
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn builds_and_verifies_social_graph_presentation_bound_to_freebird_request() {
    let controller_secret = [0x11; 32];
    let controller_key = SigningKey::from_bytes(&controller_secret);
    let controller_public = controller_key.verifying_key();
    let holder_commitment = hex::encode(Sha256::digest(controller_public.to_bytes()));

    let attestation = json!({
        "contract_version": "sophia/v1",
        "artifact_type": "social_graph.attestation",
        "version": "1",
        "attester_id": "attester:example:v1",
        "kid": "attester-key-2026-06",
        "policy_id": "clout-trust-v1",
        "issued_at": 1718999700_u64,
        "expires_at": 1719000000_u64,
        "eligibility_level": 2,
        "quota_nullifier": "9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7",
        "jti": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "holder_commitment": holder_commitment,
        "signature": "9b4f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    });
    let attestation_hash = canonical_hash_hex(&attestation).unwrap();

    let request_binding = "freebird:issue:v1:issuer:freebird:example:YmxlbmRlZF9lbGVtZW50";
    let request_binding_hash = hex::encode(Sha256::digest(request_binding.as_bytes()));

    let presentation = CredPresentation {
        contract_version: "sophia/v1".to_owned(),
        artifact_type: "cred.presentation".to_owned(),
        presentation_id: "presentation-social-graph-1".to_owned(),
        cred_id: "cred:local:example".to_owned(),
        request_id: "request-freebird-issue-1".to_owned(),
        grant_id: Some("grant-social-graph-1".to_owned()),
        app_id: "issuer:freebird:example".to_owned(),
        created_at: 1718999800,
        artifacts: vec![PresentedArtifact {
            artifact_type: "social_graph.attestation".to_owned(),
            artifact_hash: attestation_hash,
            record_id: Some("record-social-graph-attestation-1".to_owned()),
            disclosure: "embedded".to_owned(),
            artifact: Some(attestation),
        }],
        request_binding_hash: Some(request_binding_hash.clone()),
        cred_signature: None,
    };

    let secret_key_hex = hex::encode(controller_secret);
    let signed = sign_presentation(presentation, &secret_key_hex).unwrap();

    assert_eq!(
        signed.request_binding_hash.as_deref().unwrap(),
        &request_binding_hash
    );
    assert_eq!(
        signed.cred_signature.as_ref().unwrap().scheme,
        "ed25519"
    );
    assert_eq!(
        signed.cred_signature.as_ref().unwrap().public_key,
        hex::encode(controller_public.to_bytes())
    );

    verify_presentation_signature(&signed).unwrap();

    // Tampering with any field must break verification.
    let mut tampered = signed.clone();
    tampered.app_id = "issuer:freebird:other".to_owned();
    assert!(verify_presentation_signature(&tampered).is_err());

    // Tampering with request_binding_hash must break verification.
    let mut tampered_binding = signed.clone();
    tampered_binding.request_binding_hash = Some(
        "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    );
    assert!(verify_presentation_signature(&tampered_binding).is_err());

    let expected_request_binding_hash = hex::encode(Sha256::digest(request_binding.as_bytes()));
    assert_eq!(
        signed.request_binding_hash.as_deref().unwrap(),
        expected_request_binding_hash
    );
}
