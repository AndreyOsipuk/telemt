use super::*;

fn users(secret: &str) -> HashMap<String, String> {
    HashMap::from([("alice".to_string(), secret.to_string())])
}

#[test]
fn shared_authority_rejects_registration_through_an_old_generation() {
    let authority = UserAdmissionAuthority::new();
    let secret = "00112233445566778899aabbccddeeff";
    authority.apply_config(&users(secret), &HashMap::new());
    let credential = credential_id_from_hex(secret).unwrap();

    assert!(authority.claim_authenticated("alice", credential).is_some());
    authority.stage_user("alice", secret, false).unwrap();

    assert!(authority.claim_authenticated("alice", credential).is_none());
}

#[test]
fn stale_credential_cannot_cross_delete_and_recreate() {
    let authority = UserAdmissionAuthority::new();
    let old_secret = "00112233445566778899aabbccddeeff";
    let new_secret = "ffeeddccbbaa99887766554433221100";
    authority.apply_config(&users(old_secret), &HashMap::new());
    let old_credential = credential_id_from_hex(old_secret).unwrap();
    let old_incarnation = authority
        .authenticated_incarnation("alice", old_credential)
        .unwrap();

    authority.delete_user("alice");
    let recreated = authority.stage_user("alice", new_secret, true).unwrap();

    assert!(recreated.incarnation > old_incarnation);
    assert!(
        authority
            .authenticated_incarnation("alice", old_credential)
            .is_none()
    );
}

#[test]
fn stale_candidate_cannot_overwrite_newer_mutation() {
    let authority = UserAdmissionAuthority::new();
    let secret = "00112233445566778899aabbccddeeff";
    authority.apply_config(&users(secret), &HashMap::new());
    let candidate_epoch = authority.epoch();
    authority.stage_user("alice", secret, false).unwrap();

    assert!(
        authority
            .apply_config_if_epoch(candidate_epoch, &users(secret), &HashMap::new())
            .is_none()
    );
    assert!(!authority.is_user_enabled("alice"));
}
