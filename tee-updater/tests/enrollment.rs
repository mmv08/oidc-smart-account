use std::collections::BTreeMap;
use tee_google_key_updater::{
    attestor_identity, enrollment_digest, verify_enrollment_evidence, EnrollmentEvidence,
    EnrollmentPolicy,
};

fn valid_policy_and_evidence() -> (EnrollmentPolicy, EnrollmentEvidence) {
    let mut private_key = [0_u8; 32];
    private_key[31] = 1;
    let (attestor, public_key) = attestor_identity(&private_key).unwrap();
    let challenge = [0x11_u8; 32];
    let policy_hash = [0x22_u8; 32];
    let updater = "0x1111111111111111111111111111111111111111";
    let user_data = enrollment_digest(
        "31337",
        updater,
        1,
        &format!("0x{}", hex::encode(policy_hash)),
        &attestor,
    )
    .unwrap();
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x30; 48]);
    pcrs.insert(1, vec![0x31; 48]);
    pcrs.insert(2, vec![0x32; 48]);
    pcrs.insert(3, vec![0x33; 48]);

    (
        EnrollmentPolicy {
            chain_id: "31337".to_owned(),
            updater: updater.to_owned(),
            attestor_epoch: 1,
            policy_hash,
            challenge,
            expected_pcrs: pcrs.clone(),
            now_seconds: 1_000,
            max_age_seconds: 300,
            max_future_skew_seconds: 30,
        },
        EnrollmentEvidence {
            timestamp_seconds: 950,
            public_key,
            user_data: user_data.to_vec(),
            nonce: challenge.to_vec(),
            pcrs,
        },
    )
}

#[test]
fn accepts_exact_fresh_enrollment_binding() {
    let (policy, evidence) = valid_policy_and_evidence();
    let verified = verify_enrollment_evidence(&policy, &evidence).unwrap();
    assert_eq!(
        verified.attestor,
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
}

#[test]
fn rejects_stale_future_or_mismatched_enrollment_evidence() {
    let (policy, evidence) = valid_policy_and_evidence();

    let mut stale = evidence.clone();
    stale.timestamp_seconds = 699;
    assert!(verify_enrollment_evidence(&policy, &stale).is_err());

    let mut future = evidence.clone();
    future.timestamp_seconds = 1_031;
    assert!(verify_enrollment_evidence(&policy, &future).is_err());

    let mut wrong_nonce = evidence.clone();
    wrong_nonce.nonce[0] ^= 1;
    assert!(verify_enrollment_evidence(&policy, &wrong_nonce).is_err());

    let mut wrong_user_data = evidence.clone();
    wrong_user_data.user_data[0] ^= 1;
    assert!(verify_enrollment_evidence(&policy, &wrong_user_data).is_err());

    let mut wrong_pcr = evidence;
    wrong_pcr.pcrs.get_mut(&0).unwrap()[0] ^= 1;
    assert!(verify_enrollment_evidence(&policy, &wrong_pcr).is_err());
}

#[test]
fn rejects_debug_or_missing_pcrs() {
    let (policy, mut evidence) = valid_policy_and_evidence();
    evidence.pcrs.insert(0, vec![0_u8; 48]);
    assert!(verify_enrollment_evidence(&policy, &evidence).is_err());

    let (mut policy, evidence) = valid_policy_and_evidence();
    policy.expected_pcrs.remove(&2);
    assert!(verify_enrollment_evidence(&policy, &evidence).is_err());

    let (policy, mut evidence) = valid_policy_and_evidence();
    evidence.pcrs.remove(&2);
    assert!(verify_enrollment_evidence(&policy, &evidence).is_err());
}
