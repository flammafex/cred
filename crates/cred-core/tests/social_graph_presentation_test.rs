use cred_core::{canonical_hash_hex, canonical_json};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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

    let mut presentation = json!({
        "contract_version": "sophia/v1",
        "artifact_type": "cred.presentation",
        "presentation_id": "presentation-social-graph-1",
        "cred_id": "cred:local:example",
        "request_id": "request-freebird-issue-1",
        "grant_id": "grant-social-graph-1",
        "app_id": "issuer:freebird:example",
        "created_at": 1718999800_u64,
        "artifacts": [{
            "artifact_type": "social_graph.attestation",
            "artifact_hash": attestation_hash,
            "record_id": "record-social-graph-attestation-1",
            "disclosure": "embedded",
            "artifact": attestation
        }],
        "request_binding_hash": request_binding_hash
    });

    let unsigned_payload = canonical_json(&presentation).unwrap();
    assert_eq!(
        String::from_utf8(unsigned_payload.clone()).unwrap(),
        r#"{"app_id":"issuer:freebird:example","artifact_type":"cred.presentation","artifacts":[{"artifact":{"artifact_type":"social_graph.attestation","attester_id":"attester:example:v1","contract_version":"sophia/v1","eligibility_level":2,"expires_at":1719000000,"holder_commitment":"b6ce80cfe6c4764fd70d409b5bbd8be81bc04c519229c16867afebd8950e979d","issued_at":1718999700,"jti":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kid":"attester-key-2026-06","policy_id":"clout-trust-v1","quota_nullifier":"9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7","signature":"9b4f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0","version":"1"},"artifact_hash":""#.to_owned()
            + presentation["artifacts"][0]["artifact_hash"].as_str().unwrap()
            + r#"","artifact_type":"social_graph.attestation","disclosure":"embedded","record_id":"record-social-graph-attestation-1"}],"contract_version":"sophia/v1","created_at":1718999800,"cred_id":"cred:local:example","grant_id":"grant-social-graph-1","presentation_id":"presentation-social-graph-1","request_binding_hash":""#
            + presentation["request_binding_hash"].as_str().unwrap()
            + r#"","request_id":"request-freebird-issue-1"}"#
    );
    let presentation_signature = controller_key.sign(&unsigned_payload);
    presentation["presentation_signature"] = json!(hex::encode(presentation_signature.to_bytes()));

    let mut verification_payload = presentation.clone();
    verification_payload
        .as_object_mut()
        .unwrap()
        .remove("presentation_signature");
    let verification_payload = canonical_json(&verification_payload).unwrap();
    let signature_hex = presentation["presentation_signature"].as_str().unwrap();
    let signature_bytes: [u8; 64] = hex::decode(signature_hex).unwrap().try_into().unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(&controller_public.to_bytes()).unwrap();
    verifying_key
        .verify(&verification_payload, &signature)
        .unwrap();

    let expected_request_binding_hash = hex::encode(Sha256::digest(request_binding.as_bytes()));
    assert_eq!(
        presentation["request_binding_hash"].as_str().unwrap(),
        expected_request_binding_hash
    );
}
