use alloy_primitives::{B256, Bytes, FixedBytes, address, b256, bytes};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::SigningKey;
use tee_updater::http::{Url, body};
use tee_updater::{Attestation, Key, KeySet, check_attestation, parse_jwks};

/// Returns an RSA JWK with a 256-byte modulus and the other members in `members`.
fn jwk(kid: &str, members: &str) -> String {
    format!(
        r#"{{"kty":"RSA","kid":"{kid}","n":"{}",{members}}}"#,
        URL_SAFE_NO_PAD.encode([0xc1; 256])
    )
}

fn key(kid: &str, fill: u8) -> Key {
    Key {
        kid: kid.into(),
        modulus: Bytes::from(vec![fill; 256]),
    }
}

/// Returns the signing key with the private key 1.
fn key_one() -> SigningKey {
    SigningKey::from_slice(B256::with_last_byte(1).as_slice()).unwrap()
}

#[test]
fn keeps_only_keys_that_the_verifier_can_use() {
    assert!(parse_jwks(br#"{"keys":[]}"#).unwrap().is_empty());
    let body = format!(
        r#"{{"keys":[{},{},{},{},{},{}],"other":1}}"#,
        jwk("b", r#""alg":"RS256","use":"sig","e":"AQAB""#),
        // `alg` and `use` are optional.
        jwk("a", r#""e":"AQAB""#),
        jwk("rs512", r#""alg":"RS512","e":"AQAB""#),
        jwk("encryption", r#""use":"enc","e":"AQAB""#),
        jwk("exponent-3", r#""e":"Aw""#),
        r#"{"kty":"EC","kid":"ec","alg":"ES256","crv":"P-256","x":"AA","y":"AA"}"#,
    );

    let keys = parse_jwks(body.as_bytes()).unwrap();
    assert_eq!(keys, [key("a", 0xc1), key("b", 0xc1)]);
}

#[test]
fn rejects_jwks_that_is_not_valid_or_not_clear() {
    let duplicate_kid = format!(
        r#"{{"keys":[{},{}]}}"#,
        jwk("a", r#""e":"AQAB""#),
        jwk("a", r#""e":"AQAB""#)
    );
    let duplicate_member = format!(r#"{{"keys":[{}]}}"#, jwk("a", r#""e":"AQAB","kid":"b""#));
    for body in [
        &duplicate_kid,
        &duplicate_member,
        r#"{"keys":{}}"#,
        r#"{"keys":["#,
    ] {
        assert!(parse_jwks(body.as_bytes()).is_err(), "{body}");
    }
}

/// The Solidity test `test_digestMatchesRustUpdater` uses the same values.
#[test]
fn digest_and_signature_match_the_registry() {
    let key_set = KeySet {
        jwksUri: "https://issuer.example/jwks.json".into(),
        keys: vec![key("key-1", 0xc1), key("key-2", 0xd3)],
        fetchedAt: 1_700_000_000,
    };
    let registry = address!("0x1111111111111111111111111111111111111111");

    assert_eq!(
        key_set.digest(31_337, registry),
        b256!("0x4fe5221e4e43037a6991b326969306ffa1415717bc7e1580e7601075eb63d267")
    );
    let signed = key_set.sign(&key_one(), 31_337, registry);
    assert_eq!(
        signed.attestor,
        address!("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    );
    assert_eq!(
        signed.signature,
        bytes!(
            "0xa16daa7c6f7b20a1e903a2825c66139d14c49999e0b0ff7e947e85241d7d6140"
            "42c72b86c658a54698ac50e143cb16bdd6fe1272bdaf1d2ee9bb74c0f78ccc271b"
        )
    );
}

#[test]
fn accepts_only_attestation_of_expected_image_and_challenge() {
    let pcr0 = FixedBytes::repeat_byte(0xa0);
    let challenge = B256::repeat_byte(0x11);
    let attestation = Attestation {
        pcr0: pcr0.to_vec(),
        public_key: key_one()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        nonce: challenge.to_vec(),
    };
    assert_eq!(
        check_attestation(&attestation, pcr0, challenge).unwrap(),
        address!("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    );

    // Other image or other challenge.
    assert!(check_attestation(&attestation, FixedBytes::repeat_byte(0xff), challenge).is_err());
    assert!(check_attestation(&attestation, pcr0, B256::repeat_byte(0x22)).is_err());
    // A debug-mode enclave has a zero PCR0.
    let debug = Attestation {
        pcr0: vec![0; 48],
        ..attestation
    };
    assert!(check_attestation(&debug, FixedBytes::ZERO, challenge).is_err());
}

#[test]
fn reads_url_and_http_response() {
    assert_eq!(
        Url::parse("http://127.0.0.1:9000/jwks.json").unwrap(),
        Url {
            https: false,
            authority: "127.0.0.1:9000".into(),
            host: "127.0.0.1".into(),
            port: 9000,
            path: "/jwks.json".into()
        }
    );
    let google = Url::parse("https://www.googleapis.com").unwrap();
    assert_eq!(
        (google.https, google.port, google.path.as_str()),
        (true, 443, "/")
    );
    assert!(Url::parse("ftp://example.com/").is_err());
    assert!(Url::parse("https://example.com/a\r\nX: y").is_err());

    assert_eq!(body(b"HTTP/1.0 200 OK\r\nA: b\r\n\r\n{}").unwrap(), b"{}");
    assert!(body(b"HTTP/1.1 404 Not Found\r\n\r\n{}").is_err());
    assert!(body(b"HTTP/1.0 200 OK\r\n").is_err());
    // The parent can cut the response. A cut JWKS is not complete JSON.
    let cut = body(b"HTTP/1.0 200 OK\r\n\r\n{\"keys\":[").unwrap();
    assert!(parse_jwks(&cut).is_err());
}
