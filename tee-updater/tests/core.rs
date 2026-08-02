use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tee_google_key_updater::{
    enrollment_policy_hash, key_set_digest, parse_fixed_hex, parse_google_jwks, sign_snapshot,
    GoogleKey, SigningContext,
};

fn modulus(fill: u8) -> [u8; 256] {
    let mut value = [fill; 256];
    value[0] |= 0x80;
    value[255] |= 1;
    value
}

fn jwk(kid: &str, modulus: &[u8; 256]) -> String {
    format!(
        r#"{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{}","e":"AQAB"}}"#,
        URL_SAFE_NO_PAD.encode(modulus)
    )
}

#[test]
fn parses_and_canonicalizes_google_rs256_keys() {
    let second = modulus(0x92);
    let first = modulus(0x81);
    let body = format!(
        r#"{{"keys":[{},{}]}}"#,
        jwk("z-key", &second),
        jwk("a-key", &first)
    );

    let parsed = parse_google_jwks(body.as_bytes()).unwrap();

    assert_eq!(parsed.len(), 2);
    assert!(parsed[0].kid_hash < parsed[1].kid_hash);
    assert_eq!(parsed[0].modulus.len(), 256);
    assert_ne!(parsed[0].kid_hash, parsed[1].kid_hash);
}

#[test]
fn signed_key_json_contains_only_contract_consumed_fields() {
    let key = GoogleKey::from_parts("human-readable-kid", modulus(0x81)).unwrap();
    let value = serde_json::to_value(key).unwrap();
    let object = value.as_object().unwrap();

    assert_eq!(object.len(), 2);
    assert!(object.contains_key("kidHash"));
    assert!(object.contains_key("modulus"));
    assert!(!object.contains_key("kid"));
}

#[test]
fn fixed_hex_parser_has_one_canonical_length_check() {
    assert_eq!(parse_fixed_hex::<2>("0x00ff").unwrap(), [0x00, 0xff]);
    assert_eq!(parse_fixed_hex::<2>("00ff").unwrap(), [0x00, 0xff]);
    assert!(parse_fixed_hex::<2>("0xff").is_err());
    assert!(parse_fixed_hex::<2>("0x00fg").is_err());
}

#[test]
fn measured_enrollment_policy_hash_matches_the_published_manifest() {
    assert_eq!(
        hex::encode(enrollment_policy_hash()),
        "94df64d6933fd4990ee72349d2d2080002dfc89f543494e543d2a119dcf4d537"
    );
}

#[test]
fn rejects_duplicate_security_fields_and_duplicate_kids() {
    let n = URL_SAFE_NO_PAD.encode(modulus(0x81));
    let duplicate_field = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"one","kid":"two","alg":"RS256","use":"sig","n":"{n}","e":"AQAB"}}]}}"#
    );
    assert!(parse_google_jwks(duplicate_field.as_bytes()).is_err());

    let key = jwk("same", &modulus(0x81));
    let duplicate_kid = format!(r#"{{"keys":[{key},{key}]}}"#);
    assert!(parse_google_jwks(duplicate_kid.as_bytes()).is_err());
}

#[test]
fn rejects_wrong_algorithm_exponent_and_non_2048_bit_modulus() {
    let n = URL_SAFE_NO_PAD.encode(modulus(0x81));
    let wrong_alg = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"one","alg":"RS512","use":"sig","n":"{n}","e":"AQAB"}}]}}"#
    );
    assert!(parse_google_jwks(wrong_alg.as_bytes()).is_err());

    let short_n = URL_SAFE_NO_PAD.encode([0x81_u8; 255]);
    let short = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"one","alg":"RS256","use":"sig","n":"{short_n}","e":"AQAB"}}]}}"#
    );
    assert!(parse_google_jwks(short.as_bytes()).is_err());

    let wrong_e = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"one","alg":"RS256","use":"sig","n":"{n}","e":"Aw"}}]}}"#
    );
    assert!(parse_google_jwks(wrong_e.as_bytes()).is_err());
}

#[test]
fn signs_contract_compatible_snapshot_with_expected_attestor() {
    let keys = vec![GoogleKey::from_parts("kid-1", modulus(0x81)).unwrap()];
    let context = SigningContext::new(
        "1",
        "0x1111111111111111111111111111111111111111",
        1,
        "0",
        1_700_000_000,
    )
    .unwrap();
    let mut private_key = [0_u8; 32];
    private_key[31] = 1;

    let snapshot = sign_snapshot(keys, context, &private_key).unwrap();

    assert_eq!(
        snapshot.attestor,
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
    assert_eq!(snapshot.signature.len(), 132);
    assert!(snapshot.signature.ends_with("1b") || snapshot.signature.ends_with("1c"));
    assert_eq!(snapshot.digest.len(), 66);
}

#[test]
fn eip712_digest_binds_every_contract_field() {
    let keys = vec![GoogleKey::from_parts("kid-1", modulus(0x81)).unwrap()];
    let base = SigningContext::new(
        "1",
        "0x1111111111111111111111111111111111111111",
        1,
        "0",
        1_700_000_000,
    )
    .unwrap();
    let digest = key_set_digest(&keys, &base);

    for changed in [
        SigningContext::new("2", &base.updater_hex(), 1, "0", base.fetched_at).unwrap(),
        SigningContext::new(
            "1",
            "0x2222222222222222222222222222222222222222",
            1,
            "0",
            base.fetched_at,
        )
        .unwrap(),
        SigningContext::new("1", &base.updater_hex(), 2, "0", base.fetched_at).unwrap(),
        SigningContext::new("1", &base.updater_hex(), 1, "1", base.fetched_at).unwrap(),
        SigningContext::new("1", &base.updater_hex(), 1, "0", base.fetched_at + 1).unwrap(),
    ] {
        assert_ne!(digest, key_set_digest(&keys, &changed));
    }
}
