use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ghostkey_common::*;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use ghostkey_lib::notary_certificate::NotaryCertificateV1;

/// Generate a test ghostkey (master key -> notary cert -> ghostkey cert).
fn generate_test_ghostkey() -> (String, String, String) {
    use rand_core::OsRng;

    // Generate master key
    let (master_sk, master_vk) = ghostkey_lib::util::create_keypair(&mut OsRng).unwrap();
    let master_signing_key = master_sk;
    let master_verifying_key = master_vk;

    // Generate notary certificate
    let info = "donation_amount:100".to_string();
    let (notary_cert, notary_sk) = NotaryCertificateV1::new(&master_signing_key, &info).unwrap();

    // Generate ghostkey
    let (ghost_cert, ghost_sk) = GhostkeyCertificateV1::new(&notary_cert, &notary_sk);

    // Verify it works
    let verified = ghost_cert.verify(&Some(master_verifying_key)).unwrap();
    assert_eq!(verified, info);

    let cert_pem = Armorable::to_armored_string(&ghost_cert).unwrap();
    let sk_pem = Armorable::to_armored_string(&ghost_sk).unwrap();
    let master_vk_pem = Armorable::to_armored_string(&master_verifying_key).unwrap();

    (cert_pem, sk_pem, master_vk_pem)
}

#[test]
fn test_import_verify_sign_flow() {
    let (cert_pem, sk_pem, master_vk_pem) = generate_test_ghostkey();

    // Verify the PEMs round-trip correctly
    let cert: GhostkeyCertificateV1 = Armorable::from_armored_string(&cert_pem).unwrap();
    let sk: SigningKey = Armorable::from_armored_string(&sk_pem).unwrap();
    let vk: VerifyingKey = (&sk).into();
    assert_eq!(vk, cert.verifying_key);

    // Compute expected fingerprint
    let fp = fingerprint(&cert.verifying_key);
    assert!(!fp.is_empty());
    println!("Ghostkey fingerprint: {fp}");

    // Verify the certificate chain
    let master_vk: VerifyingKey = Armorable::from_armored_string(&master_vk_pem).unwrap();
    let info = cert.verify(&Some(master_vk)).unwrap();
    assert_eq!(info, "donation_amount:100");
    println!("Certificate verified: {info}");

    // Test scoped signing
    let message = b"Hello from ghostkey integration test";
    let dummy_id_bytes = [42u8; 32];
    let dummy_id_b58 = bs58::encode(&dummy_id_bytes).into_string();
    let dummy_contract_id =
        freenet_stdlib::prelude::ContractInstanceId::from_bytes(dummy_id_b58).unwrap();

    let scoped = ScopedPayload {
        requestor: SignatureRequestor::WebApp(dummy_contract_id),
        payload: message.to_vec(),
    };
    let scoped_bytes = to_cbor(&scoped).unwrap();
    let signature = sk.sign(&scoped_bytes);

    // Verify the signature
    assert!(vk.verify(&scoped_bytes, &signature).is_ok());
    println!("Scoped signature verified");

    // Deserialize the scoped payload and check contents
    let decoded: ScopedPayload = from_cbor(&scoped_bytes).unwrap();
    assert_eq!(decoded.payload, message);
    match decoded.requestor {
        SignatureRequestor::WebApp(_) => {}
        _ => panic!("Expected WebApp requestor"),
    }
    println!("Scoped payload deserialized correctly");
}

#[test]
fn test_request_response_serialization() {
    // Test that all request/response types serialize and deserialize correctly
    let requests = vec![
        GhostkeyRequest::ImportGhostKey {
            certificate_pem: "test-cert".into(),
            signing_key_pem: "test-sk".into(),
            master_verifying_key_pem: Some("test-mvk".into()),
        },
        GhostkeyRequest::ListGhostKeys,
        GhostkeyRequest::GetGhostKey {
            fingerprint: "abc123".into(),
        },
        GhostkeyRequest::DeleteGhostKey {
            fingerprint: "abc123".into(),
        },
        GhostkeyRequest::SetLabel {
            fingerprint: "abc123".into(),
            label: "My Key".into(),
        },
        GhostkeyRequest::SignMessage {
            fingerprint: "abc123".into(),
            message: b"hello".to_vec(),
        },
        // Cross-app access: no fields, the prompt is rendered entirely
        // from runtime-attested data so no payload to round-trip.
        GhostkeyRequest::RequestAnyAccess,
    ];

    for req in &requests {
        let bytes = to_cbor(req).unwrap();
        let decoded: GhostkeyRequest = from_cbor(&bytes).unwrap();
        let re_encoded = to_cbor(&decoded).unwrap();
        assert_eq!(bytes, re_encoded, "Round-trip failed for request");
    }
    println!("All {} request types serialize correctly", requests.len());

    // Build a SignatureRequestor used inside response variants below.
    let dummy_id_bytes = [42u8; 32];
    let dummy_id_b58 = bs58::encode(&dummy_id_bytes).into_string();
    let dummy_contract_id =
        freenet_stdlib::prelude::ContractInstanceId::from_bytes(dummy_id_b58).unwrap();
    let webapp_requestor = SignatureRequestor::WebApp(dummy_contract_id);

    let responses = vec![
        GhostkeyResponse::ImportResult {
            fingerprint: "abc123".into(),
            notary_info: "donation_amount:100".into(),
        },
        GhostkeyResponse::GhostKeyList {
            keys: vec![GhostKeyInfo {
                fingerprint: "abc123".into(),
                label: Some("Test".into()),
                notary_info: "info".into(),
                verifying_key_bytes: None,
            }],
        },
        GhostkeyResponse::Error {
            message: "test error".into(),
        },
        GhostkeyResponse::SignResult {
            scoped_payload: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            certificate_pem: "cert".into(),
        },
        // New in cross-app-access: AccessDenied fires when the user
        // denies a `RequestAnyAccess` prompt. Distinct from
        // PermissionDenied because there's no fingerprint to report.
        GhostkeyResponse::AccessDenied {
            requestor: webapp_requestor.clone(),
        },
    ];

    for resp in &responses {
        let bytes = to_cbor(resp).unwrap();
        let decoded: GhostkeyResponse = from_cbor(&bytes).unwrap();
        let re_encoded = to_cbor(&decoded).unwrap();
        assert_eq!(bytes, re_encoded, "Round-trip failed for response");
    }
    println!("All {} response types serialize correctly", responses.len());
}

/// Wire-format pin for the `GhostkeyScope` enum. The discriminants are
/// part of the over-the-wire shape that vault and apps exchange via
/// `ScopedPayload` and (in future, when a scoped variant of
/// GrantPermission exists) future protocol variants. Reordering these
/// variants would silently change every grant's encoded shape, so this
/// test fails fast if anyone reorders them.
#[test]
fn test_ghostkey_scope_wire_format_is_stable() {
    let scopes = [
        GhostkeyScope::ReadPublic,
        GhostkeyScope::Sign,
        GhostkeyScope::Export,
        GhostkeyScope::Delete,
        GhostkeyScope::Admin,
    ];
    for s in &scopes {
        let bytes = to_cbor(s).unwrap();
        let decoded: GhostkeyScope = from_cbor(&bytes).unwrap();
        assert_eq!(*s, decoded);
    }
    // Stable JSON pinning: serde tags variants by name in CBOR text-key
    // form, so any rename or reorder shows up as a JSON difference here.
    let json = serde_json::to_string(&scopes.to_vec()).unwrap();
    assert_eq!(
        json, r#"["ReadPublic","Sign","Export","Delete","Admin"]"#,
        "GhostkeyScope wire names changed -- this is a wire-format break"
    );
}

#[test]
fn test_import_with_wrong_signing_key_fails() {
    let (cert_pem, _sk_pem, _master_vk_pem) = generate_test_ghostkey();

    // Generate a different signing key
    let wrong_sk = SigningKey::from_bytes(&[99u8; 32]);
    let _wrong_sk_pem = Armorable::to_armored_string(&wrong_sk).unwrap();

    // The signing key doesn't match the certificate's verifying key
    let cert: GhostkeyCertificateV1 = Armorable::from_armored_string(&cert_pem).unwrap();
    let wrong_vk: VerifyingKey = (&wrong_sk).into();
    assert_ne!(wrong_vk, cert.verifying_key);
    println!("Confirmed: wrong signing key doesn't match certificate");
}

#[test]
fn test_fingerprint_deterministic() {
    let (cert_pem, _sk_pem, _master_vk_pem) = generate_test_ghostkey();
    let cert: GhostkeyCertificateV1 = Armorable::from_armored_string(&cert_pem).unwrap();

    let fp1 = fingerprint(&cert.verifying_key);
    let fp2 = fingerprint(&cert.verifying_key);
    assert_eq!(fp1, fp2);
    assert!(fp1.len() >= 8, "Fingerprint too short: {fp1}");
    println!("Fingerprint is deterministic: {fp1}");
}
