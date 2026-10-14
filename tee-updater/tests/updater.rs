use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::SigningKey;
use std::collections::BTreeMap;
use tee_updater::http::{Url, body};
use tee_updater::{Attestation, Key, check_attestation, key_set_digest, parse_jwks, sign_snapshot};

fn jwk(kid: &str, modulus: &[u8], e: &str) -> String {
    format!(
        r#"{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{}","e":"{e}"}}"#,
        URL_SAFE_NO_PAD.encode(modulus)
    )
}

#[test]
fn parses_jwks_and_sorts_keys_by_kid() {
    assert!(parse_jwks(br#"{"keys":[]}"#).unwrap().is_empty());
    let body = format!(
        r#"{{"keys":[{},{}],"other":1}}"#,
        jwk("b", &[0xd3; 256], "AQAB"),
        jwk("a", &[0xc1; 256], "AQAB")
    );

    let keys = parse_jwks(body.as_bytes()).unwrap();
    assert_eq!(
        keys,
        vec![
            Key {
                kid: "a".into(),
                modulus: vec![0xc1; 256]
            },
            Key {
                kid: "b".into(),
                modulus: vec![0xd3; 256]
            },
        ]
    );
}

#[test]
fn rejects_jwks_with_a_key_that_is_not_correct() {
    let mut even = [0xc1; 256];
    even[255] = 0xc0;
    let wrong = [
        jwk("a", &[0xc1; 256], "Aw"),
        jwk("a", &[0xc1; 255], "AQAB"),
        jwk("a", &[0x41; 256], "AQAB"),
        jwk("a", &even, "AQAB"),
        jwk("", &[0xc1; 256], "AQAB"),
        jwk("a", &[0xc1; 256], "AQAB").replace("RS256", "RS512"),
        jwk("a", &[0xc1; 256], "AQAB").replace(r#""use":"sig""#, r#""use":"enc""#),
        jwk("a", &[0xc1; 256], "AQAB").replace(r#""kid":"a""#, r#""kid":"a","kid":"b""#),
        format!(
            "{},{}",
            jwk("a", &[0xc1; 256], "AQAB"),
            jwk("a", &[0xd3; 256], "AQAB")
        ),
    ];
    for keys in wrong {
        assert!(
            parse_jwks(format!(r#"{{"keys":[{keys}]}}"#).as_bytes()).is_err(),
            "{keys}"
        );
    }
}

/// The Solidity test `test_digestMatchesRustUpdater` uses the same values.
#[test]
fn digest_and_signature_match_the_registry() {
    let keys = vec![
        Key {
            kid: "key-1".into(),
            modulus: vec![0xc1; 256],
        },
        Key {
            kid: "key-2".into(),
            modulus: vec![0xd3; 256],
        },
    ];
    let registry = "0x1111111111111111111111111111111111111111";
    let jwks_uri = "https://issuer.example/jwks.json";

    let digest = key_set_digest(31_337, &[0x11; 20], jwks_uri, &keys, 1_700_000_000);
    assert_eq!(
        hex::encode(digest),
        "4fe5221e4e43037a6991b326969306ffa1415717bc7e1580e7601075eb63d267"
    );

    let mut private_key = [0; 32];
    private_key[31] = 1;
    let key = SigningKey::from_slice(&private_key).unwrap();
    let snapshot = sign_snapshot(&key, 31_337, registry, jwks_uri, keys, 1_700_000_000).unwrap();
    assert_eq!(
        snapshot.attestor,
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
    assert_eq!(
        snapshot.signature,
        "0xa16daa7c6f7b20a1e903a2825c66139d14c49999e0b0ff7e947e85241d7d6140\
         42c72b86c658a54698ac50e143cb16bdd6fe1272bdaf1d2ee9bb74c0f78ccc271b"
    );
}

fn attestation() -> Attestation {
    let mut private_key = [0; 32];
    private_key[31] = 1;
    let public_key = SigningKey::from_slice(&private_key)
        .unwrap()
        .verifying_key()
        .to_sec1_point(false);
    Attestation {
        timestamp: 1_000,
        pcrs: BTreeMap::from([
            (0, vec![0xa0; 48]),
            (1, vec![0xa1; 48]),
            (2, vec![0xa2; 48]),
            (3, vec![0xa3; 48]),
        ]),
        public_key: public_key.as_bytes().to_vec(),
        nonce: vec![0x11; 32],
    }
}

#[test]
fn accepts_attestation_of_expected_image_and_challenge() {
    let pcrs = [[0xa0; 48], [0xa1; 48], [0xa2; 48]];
    let attestor = check_attestation(&attestation(), &pcrs, &[0x11; 32], 1_100, 300).unwrap();
    assert_eq!(attestor, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
}

#[test]
fn rejects_attestation_of_other_image_challenge_or_time() {
    let pcrs = [[0xa0; 48], [0xa1; 48], [0xa2; 48]];
    let check = |attestation: &Attestation, pcrs: &[[u8; 48]; 3], now: u64| {
        check_attestation(attestation, pcrs, &[0x11; 32], now, 300).is_err()
    };

    assert!(check(
        &attestation(),
        &[[0xa0; 48], [0xa1; 48], [0xff; 48]],
        1_100
    ));
    assert!(check(
        &attestation(),
        &[[0; 48], [0xa1; 48], [0xa2; 48]],
        1_100
    ));
    assert!(check(
        &Attestation {
            nonce: vec![0x22; 32],
            ..attestation()
        },
        &pcrs,
        1_100
    ));
    assert!(check(&attestation(), &pcrs, 1_301));
    assert!(check(&attestation(), &pcrs, 699));
}

#[test]
fn reads_url() {
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
    assert_eq!(
        Url::parse("https://www.googleapis.com/oauth2/v3/certs")
            .unwrap()
            .port,
        443
    );
    assert_eq!(
        Url::parse("https://example.com?key=1").unwrap().path,
        "/?key=1"
    );
    assert_eq!(Url::parse("https://example.com").unwrap().path, "/");
    for url in [
        "ftp://example.com/",
        "https://example.com/a\r\nX: y",
        "https:///jwks",
        "https://user@example.com/jwks",
        "https://example.com/jwks#fragment",
        "https://example.com:0/jwks",
        "https://example.com:+443/jwks",
        "https://example.com:443:80/jwks",
        "https://[::1]/jwks",
        "https://example.com\\other/jwks",
    ] {
        assert!(Url::parse(url).is_err(), "{url}");
    }
}

#[test]
fn requires_a_complete_http_body() {
    assert_eq!(
        body(b"HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\n{}").unwrap(),
        b"{}"
    );
    assert_eq!(body(b"HTTP/1.0 200 OK\r\n\r\n{}").unwrap(), b"{}");
    for response in [
        &b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\n"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length: +2\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length: -2\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length:\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length 2\r\n\r\n{}"[..],
        &b"HTTP/1.0 200 OK\r\nContent-Length : 3\r\n\r\n{}"[..],
        &b"HTTP/1.X 200 OK\r\nContent-Length: 2\r\n\r\n{}"[..],
    ] {
        assert!(
            body(response).is_err(),
            "{}",
            String::from_utf8_lossy(response)
        );
    }
    let incomplete = body(b"HTTP/1.0 200 OK\r\n\r\n{\"keys\":[").unwrap();
    assert!(parse_jwks(&incomplete).is_err());
}
