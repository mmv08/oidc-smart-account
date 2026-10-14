//! Shared code of the TEE updater: JWKS checks, snapshot signatures, and attestation checks.

pub mod http;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

/// One RSA key of the issuer. `JWKSRegistry.Key` has the same fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Key {
    pub kid: String,
    #[serde(serialize_with = "hex_0x")]
    pub modulus: Vec<u8>,
}

/// JWKS snapshot that the attestor signed. Anyone can send it to `JWKSRegistry.updateKeys`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub chain_id: u64,
    pub registry: String,
    pub jwks_uri: String,
    pub fetched_at: u64,
    pub keys: Vec<Key>,
    pub attestor: String,
    pub signature: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// The fields of one JWK. A duplicate field causes an error. The parser ignores other fields.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    n: String,
    e: String,
}

/// Reads a JWKS and returns its keys in the order of their `kid`.
///
/// Each key must be an RS256 signature key with the exponent 65537 and a 2048-bit modulus. If one
/// key is not correct, the function rejects the full JWKS. An empty JWKS gives an empty key set.
pub fn parse_jwks(body: &[u8]) -> Result<Vec<Key>> {
    let jwks: Jwks = serde_json::from_slice(body).context("JWKS is not valid")?;
    let mut keys = Vec::with_capacity(jwks.keys.len());
    for jwk in jwks.keys {
        let kid = jwk.kid;
        ensure!(
            jwk.kty == "RSA" && jwk.alg == "RS256" && jwk.key_use == "sig",
            "key {kid} is not an RS256 signature key"
        );
        ensure!(
            URL_SAFE_NO_PAD.decode(&jwk.e)? == [1, 0, 1],
            "key {kid} exponent is not 65537"
        );
        let modulus = URL_SAFE_NO_PAD.decode(&jwk.n)?;
        ensure!(
            modulus.len() == 256 && modulus[0] & 0x80 != 0 && modulus[255] & 1 == 1,
            "key {kid} modulus is not an odd 2048-bit number"
        );
        keys.push(Key { kid, modulus });
    }
    keys.sort_by(|a, b| a.kid.cmp(&b.kid));
    ensure!(
        keys.windows(2).all(|pair| pair[0].kid != pair[1].kid),
        "JWKS has a duplicate kid"
    );
    Ok(keys)
}

/// Returns the EIP-712 digest that `JWKSRegistry.hashKeySet` returns for the same values.
pub fn key_set_digest(
    chain_id: u64,
    registry: &[u8; 20],
    jwks_uri: &str,
    keys: &[Key],
    fetched_at: u64,
) -> [u8; 32] {
    let domain = keccak_words(&[
        keccak(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ),
        keccak(b"JWKSRegistry"),
        keccak(b"1"),
        word(chain_id),
        address_word(registry),
    ]);
    let key_hashes: Vec<u8> = keys
        .iter()
        .flat_map(|key| {
            keccak_words(&[
                keccak(b"Key(string kid,bytes modulus)"),
                keccak(key.kid.as_bytes()),
                keccak(&key.modulus),
            ])
        })
        .collect();
    let key_set = keccak_words(&[
        keccak(b"KeySet(string jwksUri,Key[] keys,uint64 fetchedAt)Key(string kid,bytes modulus)"),
        keccak(jwks_uri.as_bytes()),
        keccak(&key_hashes),
        word(fetched_at),
    ]);
    keccak(&[&[0x19, 0x01][..], &domain, &key_set].concat())
}

/// Signs a JWKS snapshot with the attestor key.
pub fn sign_snapshot(
    key: &SigningKey,
    chain_id: u64,
    registry: &str,
    jwks_uri: &str,
    keys: Vec<Key>,
    fetched_at: u64,
) -> Result<Snapshot> {
    let registry = parse_address(registry)?;
    let digest = key_set_digest(chain_id, &registry, jwks_uri, &keys, fetched_at);
    let (signature, recovery_id) = key.sign_prehash_recoverable(&digest);
    let mut signature = signature.to_bytes().to_vec();
    signature.push(27 + recovery_id.to_byte());
    Ok(Snapshot {
        chain_id,
        registry: format!("0x{}", hex::encode(registry)),
        jwks_uri: jwks_uri.to_owned(),
        fetched_at,
        keys,
        attestor: address(key.verifying_key()),
        signature: format!("0x{}", hex::encode(signature)),
    })
}

/// Returns the Ethereum address of a secp256k1 public key.
pub fn address(key: &VerifyingKey) -> String {
    let point = key.to_sec1_point(false);
    format!("0x{}", hex::encode(&keccak(&point.as_bytes()[1..])[12..]))
}

/// Values of a Nitro attestation document that `check_attestation` examines.
pub struct Attestation {
    /// Platform configuration registers: the measurements of the enclave image.
    pub pcrs: BTreeMap<u16, Vec<u8>>,
    /// Public key of the attestor, as SEC1 bytes.
    pub public_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Returns the attestor address if the attestation is for the expected enclave image and the
/// expected challenge.
///
/// Before you call this function, verify the AWS signature of the document. The challenge must be
/// new and random. Thus the document is new, and an old document cannot be used again.
pub fn check_attestation(
    attestation: &Attestation,
    expected_pcrs: &[[u8; 48]; 3],
    challenge: &[u8; 32],
) -> Result<String> {
    for (index, expected) in expected_pcrs.iter().enumerate() {
        // A debug-mode enclave has zero PCRs. Its memory is not protected.
        ensure!(
            expected.iter().any(|byte| *byte != 0),
            "PCR{index} must not be zero"
        );
        ensure!(
            attestation.pcrs.get(&(index as u16)).map(Vec::as_slice) == Some(expected.as_slice()),
            "PCR{index} is not the expected value"
        );
    }
    ensure!(
        attestation.nonce == challenge.as_slice(),
        "attestation nonce is not the challenge"
    );
    let key = VerifyingKey::from_sec1_bytes(&attestation.public_key)
        .context("attestation public key is not a secp256k1 key")?;
    Ok(address(&key))
}

/// Parses a 20-byte address with the `0x` prefix.
pub fn parse_address(value: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .context("address has no 0x prefix")?,
    )?;
    bytes.try_into().ok().context("address is not 20 bytes")
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn keccak_words(words: &[[u8; 32]]) -> [u8; 32] {
    keccak(&words.concat())
}

fn word(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(address);
    word
}

fn hex_0x<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}
