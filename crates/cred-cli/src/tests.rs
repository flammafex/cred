use crate::commands::*;
use crate::grant::{grant_review_summary, grant_review_warnings};
use crate::presentation::*;
use crate::util::*;
use crate::adapters::witness::ensure_witness_signed_attestation;
use crate::adapters::freebird::ensure_freebird_check_request;
use crate::adapters::matchlock::ensure_matchlock_presentation_safe_artifact;
use crate::adapters::social_graph::social_graph_import_attestation;
use cred_core::{artifact_record, canonical_hash_hex, sign_presentation, verify_presentation_signature, CredAction, CredActionRequest, CredGrantConstraints, CredPermissionGrant, CredPresentation, GrantUsage, PresentedArtifact};
use cred_store::{GrantApproval, RecordStore};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn record_backed_presentations_are_references() {
        let source = presentation_source_from_record(sample_record(), None).unwrap();

        assert_eq!(source.artifact_type, "witness.signed_attestation");
        assert_eq!(
            source.artifact_hash,
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(source.record_id.as_deref(), Some("record-1"));
        assert_eq!(source.disclosure, "reference");
        assert!(source.artifact.is_none());
    }

    #[test]
    fn record_backed_presentations_reject_embedded_disclosure() {
        let err = presentation_source_from_record(sample_record(), Some("embedded")).unwrap_err();

        assert!(err
            .to_string()
            .contains("record-backed presentations cannot use embedded disclosure"));
    }

    #[test]
    fn presentation_grant_allows_matching_artifact_type() {
        enforce_presentation_grant(
            &sample_grant(Some(vec!["witness.signed_attestation".to_owned()])),
            &sample_request(Some("witness.signed_attestation")),
            "cred:local:test",
            "witness.signed_attestation",
            GrantUsage {
                now: 10,
                uses_so_far: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn presentation_grant_denies_unallowed_presented_artifact_type() {
        let err = enforce_presentation_grant(
            &sample_grant(Some(vec!["cred.presentation".to_owned()])),
            &sample_request(None),
            "cred:local:test",
            "witness.signed_attestation",
            GrantUsage {
                now: 10,
                uses_so_far: 0,
            },
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("permission grant denied presentation"));
    }

    #[test]
    fn request_denies_unrequested_artifact_type() {
        let err = ensure_request_allows_artifact(
            &sample_request(Some("cred.presentation")),
            "witness.signed_attestation",
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("request does not allow presented artifact type"));
    }

    #[test]
    fn test_import_attestation() {
        let root = temp_store_root("social-graph-import");
        social_graph_import_attestation(
            SocialGraphImportAttestationCommand {
                attestation: social_graph_example("social-graph-attestation.json"),
                record_id: "record-social-graph-attestation-1".to_owned(),
                cred_id: "cred:local:example".to_owned(),
                privacy: "selective".to_owned(),
                custody: "external_reference".to_owned(),
                artifact_uri: Some(
                    social_graph_example("social-graph-attestation.json")
                        .display()
                        .to_string(),
                ),
                labels: Vec::new(),
                vault_passphrase: None,
            },
            Some(root.clone()),
        )
        .unwrap();

        let record = RecordStore::new(&root)
            .get_record("record-social-graph-attestation-1")
            .unwrap()
            .unwrap();
        assert_eq!(record.stored_artifact_type, "social_graph.attestation");
        assert_eq!(record.privacy, "selective");
        assert_eq!(record.source_app.as_deref(), Some("attester:example:v1"));
        assert_eq!(
            record.labels.as_deref().unwrap(),
            &["social_graph".to_owned(), "clout-trust-v1".to_owned()]
        );
        cleanup(root);
    }

    #[test]
    fn test_present_attestation() {
        let attestation =
            read_json(&social_graph_example("social-graph-attestation.json")).unwrap();
        let request = read_json(&social_graph_example(
            "social-graph-presentation-request.json",
        ))
        .unwrap();
        let request: CredActionRequest = serde_json::from_value(request).unwrap();
        let grant = read_json(&social_graph_example("social-graph-permission-grant.json")).unwrap();
        let grant: CredPermissionGrant = serde_json::from_value(grant).unwrap();
        enforce_presentation_grant(
            &grant,
            &request,
            "cred:local:example",
            "social_graph.attestation",
            GrantUsage {
                now: 1718999800,
                uses_so_far: 0,
            },
        )
        .unwrap();

        let presentation = CredPresentation {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.presentation".to_owned(),
            presentation_id: "presentation-social-graph-1".to_owned(),
            cred_id: "cred:local:example".to_owned(),
            request_id: request.request_id,
            grant_id: Some(grant.grant_id),
            app_id: request.app_id,
            created_at: 1718999800,
            artifacts: vec![PresentedArtifact {
                artifact_type: "social_graph.attestation".to_owned(),
                artifact_hash: canonical_hash_hex(&attestation).unwrap(),
                record_id: Some("record-social-graph-attestation-1".to_owned()),
                disclosure: "embedded".to_owned(),
                artifact: Some(attestation),
            }],
            request_binding_hash: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            ),
            cred_signature: None,
        };
        let secret_key = "2222222222222222222222222222222222222222222222222222222222222222";
        let signed = sign_presentation(presentation, secret_key).unwrap();
        verify_presentation_signature(&signed).unwrap();

        assert_eq!(
            signed.request_binding_hash.as_deref().unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(signed.cred_signature.is_some());
    }

    #[test]
    fn test_present_rejects_invalid_grant() {
        let request = social_graph_request();
        let mut grant = social_graph_grant();
        grant.capabilities = vec!["freebird.present".to_owned()];
        assert!(enforce_presentation_grant(
            &grant,
            &request,
            "cred:local:example",
            "social_graph.attestation",
            GrantUsage {
                now: 1718999800,
                uses_so_far: 0
            },
        )
        .unwrap_err()
        .to_string()
        .contains("permission grant denied"));
    }

    #[test]
    fn test_present_rejects_expired_grant() {
        let request = social_graph_request();
        let mut grant = social_graph_grant();
        grant.constraints.expires_at = Some(1);
        let err = enforce_presentation_grant(
            &grant,
            &request,
            "cred:local:example",
            "social_graph.attestation",
            GrantUsage {
                now: 1718999800,
                uses_so_far: 0,
            },
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("expired"));
    }

    #[test]
    fn presentation_requires_local_grant_approval() {
        let root = temp_store_root("requires-approval");
        let grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        let grant_hash = grant_hash(&grant);

        let err =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, None).unwrap_err();
        assert!(err.to_string().contains("no local approval record"));

        let store = RecordStore::new(&root);
        let approval = sample_approval(&grant, &grant_hash, "approved", "approval-1");
        store.append_grant_approval(&approval).unwrap();

        let approved =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, None).unwrap();
        assert_eq!(approved.approval_id, "approval-1");

        cleanup(root);
    }

    #[test]
    fn latest_denial_blocks_even_with_pinned_approval() {
        let root = temp_store_root("latest-approval");
        let grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        let grant_hash = grant_hash(&grant);
        let store = RecordStore::new(&root);
        store
            .append_grant_approval(&sample_approval(
                &grant,
                &grant_hash,
                "approved",
                "approval-1",
            ))
            .unwrap();
        store
            .append_grant_approval(&sample_approval(&grant, &grant_hash, "denied", "denial-1"))
            .unwrap();

        let err =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("permission grant was not approved"));

        let pinned_err =
            require_approved_grant(Some(root.clone()), &grant, &grant_hash, Some("approval-1"))
                .unwrap_err();
        assert!(pinned_err
            .to_string()
            .contains("permission grant was not approved"));

        cleanup(root);
    }

    #[test]
    fn pinned_approval_must_match_current_grant_hash() {
        let root = temp_store_root("approval-hash-mismatch");
        let grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        let changed_grant = sample_grant(Some(vec!["cred.presentation".to_owned()]));
        let original_hash = grant_hash(&grant);
        let changed_hash = grant_hash(&changed_grant);
        let store = RecordStore::new(&root);
        store
            .append_grant_approval(&sample_approval(
                &grant,
                &original_hash,
                "approved",
                "approval-1",
            ))
            .unwrap();

        let err = require_approved_grant(
            Some(root.clone()),
            &changed_grant,
            &changed_hash,
            Some("approval-1"),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match current grant hash"));

        cleanup(root);
    }

    #[test]
    fn witness_adapter_accepts_signed_attestation() {
        ensure_witness_signed_attestation(&sample_witness_attestation()).unwrap();
    }

    #[test]
    fn witness_adapter_rejects_other_artifacts() {
        let err = ensure_witness_signed_attestation(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "cred.presentation",
            "attestation": {},
            "signatures": {}
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("expected artifact_type witness.signed_attestation"));
    }

    #[test]
    fn witness_adapter_rejects_incomplete_attestation() {
        let err = ensure_witness_signed_attestation(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "witness.signed_attestation",
            "attestation": {}
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("witness.signed_attestation missing signatures"));
    }

    #[test]
    fn freebird_adapter_accepts_check_request() {
        ensure_freebird_check_request(&sample_freebird_check_request()).unwrap();
    }

    #[test]
    fn freebird_adapter_rejects_consuming_verify_request() {
        let err = ensure_freebird_check_request(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "freebird.verify_request",
            "token_b64": "AQIDBAUGBwgJCgsMDQ4PEA"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("non-consuming and rejects freebird.verify_request"));
    }

    #[test]
    fn freebird_adapter_rejects_invalid_token_shape() {
        let err = ensure_freebird_check_request(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "freebird.check_request",
            "token_b64": "not=base64url"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("token_b64 must be non-empty base64url"));
    }

    #[test]
    fn matchlock_adapter_accepts_commitment() {
        ensure_matchlock_presentation_safe_artifact(&sample_matchlock_commitment()).unwrap();
    }

    #[test]
    fn matchlock_adapter_rejects_raw_match_token() {
        let err = ensure_matchlock_presentation_safe_artifact(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "matchlock.match_token",
            "pool_id": "test-pool",
            "domain": "matchlock-match-v1",
            "token": "bbfee0cd9a72d348a1a4dafee9ad8c055f02c79e0d341ff4aa425583030492bf"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("rejects raw matchlock.match_token durable records"));
    }

    #[test]
    fn matchlock_adapter_rejects_private_artifact_fields() {
        let err = ensure_matchlock_presentation_safe_artifact(&serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "matchlock.commitment",
            "pool_id": "test-pool",
            "commitment": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "private_key": "77076d0a7318a57d3c16c17251b26645c6c2f6929f0a4b5745a0435c9b7bd30d"
        }))
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("unexpected Matchlock artifact field"));
    }

    fn sample_witness_attestation() -> Value {
        serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "witness.signed_attestation",
            "attestation": {
                "tree_size": 1
            },
            "signatures": {
                "kind": "multisig",
                "signatures": [
                    {
                        "witness_id": "witness:local:1",
                        "signature": "11"
                    }
                ]
            }
        })
    }

    fn sample_freebird_check_request() -> Value {
        serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "freebird.check_request",
            "token_b64": "AQIDBAUGBwgJCgsMDQ4PEA"
        })
    }

    fn sample_matchlock_commitment() -> Value {
        serde_json::json!({
            "contract_version": "sophia/v1",
            "artifact_type": "matchlock.commitment",
            "pool_id": "test-pool",
            "commitment": "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            "hashes_raw_token_bytes": true
        })
    }

    #[test]
    fn store_enforced_max_uses_blocks_replay() {
        let root = temp_store_root("max-uses-enforcement");
        let store = RecordStore::new(&root);

        // Grant with max_uses = 1
        let mut grant = sample_grant(Some(vec!["witness.signed_attestation".to_owned()]));
        grant.constraints.max_uses = Some(1);
        let hash = grant_hash(&grant);

        // Approve the grant
        let approval = sample_approval(&grant, &hash, "approved", "approval-1");
        store.append_grant_approval(&approval).unwrap();

        let request = sample_request(Some("witness.signed_attestation"));
        let source = presentation_source_from_record(sample_record(), None).unwrap();

        // First presentation should succeed (0 prior uses)
        let first = build_presentation(PresentationBuild {
            request: request.clone(),
            source: source.clone(),
            grant: Some((grant.clone(), hash.clone())),
            approval_id: Some("approval-1".to_owned()),
            signing_key: None,
            now: Some(10),
            presentation_id: "presentation-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            store_path: Some(root.clone()),
        })
        .unwrap();
        assert_eq!(first.presentation_id, "presentation-1");

        // Second presentation under the same grant must fail (1 prior use, max 1)
        let err = build_presentation(PresentationBuild {
            request,
            source,
            grant: Some((grant, hash)),
            approval_id: Some("approval-1".to_owned()),
            signing_key: None,
            now: Some(10),
            presentation_id: "presentation-2".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            store_path: Some(root.clone()),
        })
        .unwrap_err();

        assert!(format!("{err:#}").contains("max_uses has been reached"));

        cleanup(root);
    }

    fn sample_record() -> cred_core::CredArtifactRecord {
        artifact_record(
            "record-1".to_owned(),
            "cred:local:test".to_owned(),
            "witness.signed_attestation".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            Some("examples/witness-signed-attestation.json".to_owned()),
            "selective".to_owned(),
            "local_encrypted".to_owned(),
            Some("app:witness:test".to_owned()),
            1,
            Some(vec!["witness".to_owned()]),
        )
    }

    fn sample_request(artifact_type: Option<&str>) -> CredActionRequest {
        CredActionRequest {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.action_request".to_owned(),
            request_id: "request-1".to_owned(),
            app_id: "app:prestige:test".to_owned(),
            grant_id: Some("grant-1".to_owned()),
            requested_at: 1,
            purpose: Some("test presentation".to_owned()),
            actions: vec![CredAction {
                kind: "witness.present_attestation".to_owned(),
                audience: None,
                semantic: None,
                artifact_type: artifact_type.map(str::to_owned),
                hash: None,
                payload_hash: None,
                pool_id: None,
                reason: None,
            }],
            app_signature: None,
        }
    }

    fn sample_grant(allowed_artifact_types: Option<Vec<String>>) -> CredPermissionGrant {
        CredPermissionGrant {
            contract_version: "sophia/v1".to_owned(),
            artifact_type: "cred.permission_grant".to_owned(),
            grant_id: "grant-1".to_owned(),
            cred_id: "cred:local:test".to_owned(),
            app_id: "app:prestige:test".to_owned(),
            app_pubkey: None,
            capabilities: vec!["witness.present_attestation".to_owned()],
            constraints: CredGrantConstraints {
                allowed_audiences: None,
                allowed_artifact_types,
                max_uses: None,
                expires_at: None,
                allow_export: None,
            },
            human_approval: "once".to_owned(),
            created_at: 1,
            cred_signature: None,
        }
    }

    fn social_graph_example(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name)
    }

    fn social_graph_request() -> CredActionRequest {
        serde_json::from_value(
            read_json(&social_graph_example(
                "social-graph-presentation-request.json",
            ))
            .unwrap(),
        )
        .unwrap()
    }

    fn social_graph_grant() -> CredPermissionGrant {
        serde_json::from_value(
            read_json(&social_graph_example("social-graph-permission-grant.json")).unwrap(),
        )
        .unwrap()
    }

    fn grant_hash(grant: &CredPermissionGrant) -> String {
        canonical_hash_hex(&serde_json::to_value(grant).unwrap()).unwrap()
    }

    fn sample_approval(
        grant: &CredPermissionGrant,
        grant_hash: &str,
        decision: &str,
        approval_id: &str,
    ) -> GrantApproval {
        GrantApproval::from_grant(
            grant,
            grant_hash.to_owned(),
            decision.to_owned(),
            approval_id.to_owned(),
            grant_review_summary(grant),
            grant_review_warnings(grant),
            None,
            None,
            None,
            2,
        )
    }

    fn temp_store_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cred-cli-{name}-{nanos}"))
    }

    fn cleanup(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }
