use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use k256::ecdsa::SigningKey;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::time::Duration;
use thiserror::Error;

pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
pub const MAX_JWKS_BYTES: usize = 64 * 1024;
pub const MAX_KEYS: usize = 8;
pub const MAX_KID_BYTES: usize = 128;

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const KEY_TYPE: &str = "GoogleKey(bytes32 kidHash,bytes modulus)";
const KEY_SET_TYPE: &str =
    "GoogleKeySet(bytes32 keysHash,uint64 fetchedAt,uint64 attestorEpoch,uint256 nonce)";
const DOMAIN_NAME: &str = "TEEGoogleKeyUpdater";
const DOMAIN_VERSION: &str = "1";
const ENROLLMENT_TYPE: &str = "TEEGoogleKeyUpdaterEnrollment(uint256 chainId,address updater,uint64 attestorEpoch,bytes32 policyHash,address attestor)";
pub const ENROLLMENT_POLICY: &[u8] = include_bytes!("../policy/google-jwks-policy-v1.json");

pub fn enrollment_policy_hash() -> [u8; 32] {
    Sha256::digest(ENROLLMENT_POLICY).into()
}

#[derive(Debug, Error)]
pub enum UpdaterError {
    #[error("JWKS response exceeds {MAX_JWKS_BYTES} bytes")]
    OversizedJwks,
    #[error("invalid JWKS JSON: {0}")]
    InvalidJson(String),
    #[error("JWKS must contain between 1 and {MAX_KEYS} keys")]
    InvalidKeyCount,
    #[error("invalid Google JWK: {0}")]
    InvalidJwk(String),
    #[error("duplicate Google key identifier")]
    DuplicateKid,
    #[error("invalid unsigned integer: {0}")]
    InvalidUint(String),
    #[error("invalid Ethereum address")]
    InvalidAddress,
    #[error("expected {0} bytes of hexadecimal data")]
    InvalidFixedHex(usize),
    #[error("invalid secp256k1 application key")]
    InvalidApplicationKey,
    #[error("failed to sign EIP-712 snapshot")]
    SigningFailed,
    #[error("Google JWKS fetch failed: {0}")]
    Network(String),
    #[error("invalid Nitro enrollment evidence: {0}")]
    InvalidEnrollment(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleKey {
    #[serde(serialize_with = "serialize_bytes32")]
    pub kid_hash: [u8; 32],
    #[serde(serialize_with = "serialize_bytes")]
    pub modulus: Vec<u8>,
}

impl GoogleKey {
    pub fn from_parts(kid: &str, modulus: [u8; 256]) -> Result<Self, UpdaterError> {
        validate_kid(kid)?;
        validate_modulus(&modulus)?;
        Ok(Self {
            kid_hash: keccak(kid.as_bytes()),
            modulus: modulus.to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningContext {
    pub chain_id: [u8; 32],
    pub updater: [u8; 20],
    pub attestor_epoch: u64,
    pub nonce: [u8; 32],
    pub fetched_at: u64,
}

impl SigningContext {
    pub fn new(
        chain_id: &str,
        updater: &str,
        attestor_epoch: u64,
        nonce: &str,
        fetched_at: u64,
    ) -> Result<Self, UpdaterError> {
        Ok(Self {
            chain_id: parse_u256(chain_id)?,
            updater: parse_address(updater)?,
            attestor_epoch,
            nonce: parse_u256(nonce)?,
            fetched_at,
        })
    }

    pub fn updater_hex(&self) -> String {
        format!("0x{}", hex::encode(self.updater))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedSnapshot {
    pub protocol: &'static str,
    pub endpoint: &'static str,
    pub chain_id: String,
    pub updater: String,
    pub attestor_epoch: u64,
    pub nonce: String,
    pub fetched_at: u64,
    pub keys: Vec<GoogleKey>,
    pub digest: String,
    pub attestor: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentPolicy {
    pub chain_id: String,
    pub updater: String,
    pub attestor_epoch: u64,
    pub policy_hash: [u8; 32],
    pub challenge: [u8; 32],
    pub expected_pcrs: BTreeMap<u16, Vec<u8>>,
    pub now_seconds: u64,
    pub max_age_seconds: u64,
    pub max_future_skew_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentEvidence {
    pub timestamp_seconds: u64,
    pub public_key: Vec<u8>,
    pub user_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub pcrs: BTreeMap<u16, Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedEnrollment {
    pub attestor: String,
    pub timestamp_seconds: u64,
}

pub fn verify_enrollment_evidence(
    policy: &EnrollmentPolicy,
    evidence: &EnrollmentEvidence,
) -> Result<VerifiedEnrollment, UpdaterError> {
    if policy.max_age_seconds == 0
        || evidence
            .timestamp_seconds
            .saturating_add(policy.max_age_seconds)
            < policy.now_seconds
        || evidence.timestamp_seconds
            > policy
                .now_seconds
                .saturating_add(policy.max_future_skew_seconds)
    {
        return Err(UpdaterError::InvalidEnrollment(
            "attestation timestamp is outside the enrollment window".to_owned(),
        ));
    }
    if evidence.nonce.as_slice() != policy.challenge {
        return Err(UpdaterError::InvalidEnrollment(
            "attestation nonce does not match the one-use challenge".to_owned(),
        ));
    }
    for required in [0_u16, 1, 2] {
        if !policy.expected_pcrs.contains_key(&required) {
            return Err(UpdaterError::InvalidEnrollment(format!(
                "enrollment policy does not pin required PCR{required}"
            )));
        }
    }
    for (index, expected) in &policy.expected_pcrs {
        if expected.len() != 48 || expected.iter().all(|byte| *byte == 0) {
            return Err(UpdaterError::InvalidEnrollment(format!(
                "invalid expected PCR{index}"
            )));
        }
        if evidence.pcrs.get(index) != Some(expected) {
            return Err(UpdaterError::InvalidEnrollment(format!(
                "PCR{index} does not match the approved measurement"
            )));
        }
    }

    let attestor = attestor_from_public_key(&evidence.public_key)?;
    let expected_user_data = enrollment_digest(
        &policy.chain_id,
        &policy.updater,
        policy.attestor_epoch,
        &format!("0x{}", hex::encode(policy.policy_hash)),
        &attestor,
    )?;
    if evidence.user_data.as_slice() != expected_user_data {
        return Err(UpdaterError::InvalidEnrollment(
            "attestation user_data does not bind the approved deployment policy".to_owned(),
        ));
    }
    Ok(VerifiedEnrollment {
        attestor,
        timestamp_seconds: evidence.timestamp_seconds,
    })
}

pub fn attestor_from_public_key(public_key: &[u8]) -> Result<String, UpdaterError> {
    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| UpdaterError::InvalidApplicationKey)?;
    let canonical = verifying_key.to_encoded_point(false);
    if canonical.as_bytes() != public_key {
        return Err(UpdaterError::InvalidApplicationKey);
    }
    Ok(attestor_hex(public_key))
}

pub fn attestor_identity(private_key: &[u8; 32]) -> Result<(String, Vec<u8>), UpdaterError> {
    let signing_key =
        SigningKey::from_slice(private_key).map_err(|_| UpdaterError::InvalidApplicationKey)?;
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes().to_vec();
    Ok((attestor_hex(&public_key_bytes), public_key_bytes))
}

pub fn enrollment_digest(
    chain_id: &str,
    updater: &str,
    attestor_epoch: u64,
    policy_hash: &str,
    attestor: &str,
) -> Result<[u8; 32], UpdaterError> {
    Ok(keccak_words(&[
        keccak(ENROLLMENT_TYPE.as_bytes()),
        parse_u256(chain_id)?,
        address_word(parse_address(updater)?),
        u64_word(attestor_epoch),
        parse_bytes32(policy_hash)?,
        address_word(parse_address(attestor)?),
    ]))
}

pub fn sign_snapshot(
    keys: Vec<GoogleKey>,
    context: SigningContext,
    private_key: &[u8; 32],
) -> Result<SignedSnapshot, UpdaterError> {
    let signing_key =
        SigningKey::from_slice(private_key).map_err(|_| UpdaterError::InvalidApplicationKey)?;
    let digest = key_set_digest(&keys, &context);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|_| UpdaterError::SigningFailed)?;

    let mut ethereum_signature = [0_u8; 65];
    ethereum_signature[..64].copy_from_slice(&signature.to_bytes());
    ethereum_signature[64] = recovery_id.to_byte() + 27;

    let public_key = signing_key.verifying_key().to_encoded_point(false);

    Ok(SignedSnapshot {
        protocol: "tee-google-key-updater-v1",
        endpoint: GOOGLE_JWKS_URL,
        chain_id: word_hex(context.chain_id),
        updater: context.updater_hex(),
        attestor_epoch: context.attestor_epoch,
        nonce: word_hex(context.nonce),
        fetched_at: context.fetched_at,
        keys,
        digest: format!("0x{}", hex::encode(digest)),
        attestor: attestor_hex(public_key.as_bytes()),
        signature: format!("0x{}", hex::encode(ethereum_signature)),
    })
}

pub fn fetch_google_jwks() -> Result<Vec<GoogleKey>, UpdaterError> {
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| UpdaterError::Network(error.to_string()))?;
    let mut response = client
        .get(GOOGLE_JWKS_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|error| UpdaterError::Network(error.to_string()))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(UpdaterError::Network(format!(
            "unexpected HTTP status {}",
            response.status()
        )));
    }
    if response.url().as_str() != GOOGLE_JWKS_URL {
        return Err(UpdaterError::Network("unexpected response URL".to_owned()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
    {
        return Err(UpdaterError::OversizedJwks);
    }

    let mut body = Vec::new();
    response
        .by_ref()
        .take(MAX_JWKS_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| UpdaterError::Network(error.to_string()))?;
    if body.len() > MAX_JWKS_BYTES {
        return Err(UpdaterError::OversizedJwks);
    }
    parse_google_jwks(&body)
}

pub fn parse_google_jwks(body: &[u8]) -> Result<Vec<GoogleKey>, UpdaterError> {
    if body.len() > MAX_JWKS_BYTES {
        return Err(UpdaterError::OversizedJwks);
    }
    let raw: RawJwks = serde_json::from_slice(body)
        .map_err(|error| UpdaterError::InvalidJson(error.to_string()))?;
    if raw.keys.is_empty() || raw.keys.len() > MAX_KEYS {
        return Err(UpdaterError::InvalidKeyCount);
    }

    let mut keys = Vec::with_capacity(raw.keys.len());
    for raw_key in raw.keys {
        let kid = required(raw_key.kid, "missing kid")?;
        validate_kid(&kid)?;
        if required(raw_key.kty, "missing kty")? != "RSA" {
            return Err(invalid("kty must be RSA"));
        }
        if required(raw_key.alg, "missing alg")? != "RS256" {
            return Err(invalid("alg must be RS256"));
        }
        if required(raw_key.key_use, "missing use")? != "sig" {
            return Err(invalid("use must be sig"));
        }

        let exponent = decode_canonical_base64url(&required(raw_key.exponent, "missing e")?)?;
        if exponent.as_slice() != [0x01, 0x00, 0x01] {
            return Err(invalid("RSA exponent must be 65537"));
        }
        let modulus = decode_canonical_base64url(&required(raw_key.modulus, "missing n")?)?;
        validate_modulus(&modulus)?;

        keys.push(GoogleKey {
            kid_hash: keccak(kid.as_bytes()),
            modulus,
        });
    }

    keys.sort_unstable_by_key(|key| key.kid_hash);
    if keys
        .windows(2)
        .any(|pair| pair[0].kid_hash == pair[1].kid_hash)
    {
        return Err(UpdaterError::DuplicateKid);
    }
    Ok(keys)
}

pub fn key_set_digest(keys: &[GoogleKey], context: &SigningContext) -> [u8; 32] {
    let domain_typehash = keccak(DOMAIN_TYPE.as_bytes());
    let name_hash = keccak(DOMAIN_NAME.as_bytes());
    let version_hash = keccak(DOMAIN_VERSION.as_bytes());
    let domain_separator = keccak_words(&[
        domain_typehash,
        name_hash,
        version_hash,
        context.chain_id,
        address_word(context.updater),
    ]);

    let key_typehash = keccak(KEY_TYPE.as_bytes());
    let mut encoded_key_hashes = Vec::with_capacity(keys.len() * 32);
    for key in keys {
        let key_hash = keccak_words(&[key_typehash, key.kid_hash, keccak(&key.modulus)]);
        encoded_key_hashes.extend_from_slice(&key_hash);
    }
    let keys_hash = keccak(&encoded_key_hashes);

    let key_set_typehash = keccak(KEY_SET_TYPE.as_bytes());
    let struct_hash = keccak_words(&[
        key_set_typehash,
        keys_hash,
        u64_word(context.fetched_at),
        u64_word(context.attestor_epoch),
        context.nonce,
    ]);

    let mut eip191 = [0_u8; 66];
    eip191[0] = 0x19;
    eip191[1] = 0x01;
    eip191[2..34].copy_from_slice(&domain_separator);
    eip191[34..].copy_from_slice(&struct_hash);
    keccak(&eip191)
}

fn validate_kid(kid: &str) -> Result<(), UpdaterError> {
    if kid.is_empty() || kid.len() > MAX_KID_BYTES {
        return Err(invalid("kid length is outside policy"));
    }
    Ok(())
}

fn validate_modulus(modulus: &[u8]) -> Result<(), UpdaterError> {
    if modulus.len() != 256 {
        return Err(invalid("RSA modulus must be exactly 256 bytes"));
    }
    if modulus[0] & 0x80 == 0 {
        return Err(invalid("RSA modulus is not mathematically 2048-bit"));
    }
    if modulus[255] & 1 == 0 {
        return Err(invalid("RSA modulus must be odd"));
    }
    Ok(())
}

fn decode_canonical_base64url(value: &str) -> Result<Vec<u8>, UpdaterError> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid("non-canonical Base64URL"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid("invalid Base64URL"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(invalid("non-canonical Base64URL"));
    }
    Ok(decoded)
}

fn required<T>(value: Option<T>, message: &'static str) -> Result<T, UpdaterError> {
    value.ok_or_else(|| invalid(message))
}

fn invalid(message: impl Into<String>) -> UpdaterError {
    UpdaterError::InvalidJwk(message.into())
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn attestor_hex(uncompressed_public_key: &[u8]) -> String {
    let hash = keccak(&uncompressed_public_key[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

fn keccak_words(words: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for word in words {
        hasher.update(word);
    }
    hasher.finalize().into()
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(value: [u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&value);
    word
}

fn parse_address(value: &str) -> Result<[u8; 20], UpdaterError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(UpdaterError::InvalidAddress)?;
    if raw.len() != 40 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdaterError::InvalidAddress);
    }
    let decoded = hex::decode(raw).map_err(|_| UpdaterError::InvalidAddress)?;
    let mut address = [0_u8; 20];
    address.copy_from_slice(&decoded);
    Ok(address)
}

pub fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], UpdaterError> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != N * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdaterError::InvalidFixedHex(N));
    }
    let decoded = hex::decode(raw).map_err(|_| UpdaterError::InvalidFixedHex(N))?;
    let mut output = [0_u8; N];
    output.copy_from_slice(&decoded);
    Ok(output)
}

fn parse_bytes32(value: &str) -> Result<[u8; 32], UpdaterError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(UpdaterError::InvalidAddress)?;
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdaterError::InvalidAddress);
    }
    let decoded = hex::decode(raw).map_err(|_| UpdaterError::InvalidAddress)?;
    let mut output = [0_u8; 32];
    output.copy_from_slice(&decoded);
    Ok(output)
}

fn parse_u256(value: &str) -> Result<[u8; 32], UpdaterError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UpdaterError::InvalidUint(value.to_owned()));
    }
    let mut output = [0_u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        let mut carry = digit as u16;
        for byte in output.iter_mut().rev() {
            let next = (*byte as u16) * 10 + carry;
            *byte = next as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err(UpdaterError::InvalidUint(value.to_owned()));
        }
    }
    Ok(output)
}

fn word_hex(value: [u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

fn serialize_bytes32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{}", hex::encode(value)))
}

fn serialize_bytes<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{}", hex::encode(value)))
}

#[derive(Debug)]
struct RawJwks {
    keys: Vec<RawJwk>,
}

impl<'de> Deserialize<'de> for RawJwks {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawJwksVisitor;
        impl<'de> Visitor<'de> for RawJwksVisitor {
            type Value = RawJwks;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JWKS object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut keys = None;
                while let Some(field) = map.next_key::<String>()? {
                    if field == "keys" {
                        if keys.is_some() {
                            return Err(de::Error::duplicate_field("keys"));
                        }
                        keys = Some(map.next_value()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(RawJwks {
                    keys: keys.ok_or_else(|| de::Error::missing_field("keys"))?,
                })
            }
        }
        deserializer.deserialize_map(RawJwksVisitor)
    }
}

#[derive(Debug, Default)]
struct RawJwk {
    kty: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    key_use: Option<String>,
    modulus: Option<String>,
    exponent: Option<String>,
}

impl<'de> Deserialize<'de> for RawJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawJwkVisitor;
        impl<'de> Visitor<'de> for RawJwkVisitor {
            type Value = RawJwk;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a Google RSA JWK object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut output = RawJwk::default();
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "kty" => set_once(&mut output.kty, &mut map, "kty")?,
                        "kid" => set_once(&mut output.kid, &mut map, "kid")?,
                        "alg" => set_once(&mut output.alg, &mut map, "alg")?,
                        "use" => set_once(&mut output.key_use, &mut map, "use")?,
                        "n" => set_once(&mut output.modulus, &mut map, "n")?,
                        "e" => set_once(&mut output.exponent, &mut map, "e")?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(output)
            }
        }
        deserializer.deserialize_map(RawJwkVisitor)
    }
}

fn set_once<'de, M>(
    slot: &mut Option<String>,
    map: &mut M,
    field: &'static str,
) -> Result<(), M::Error>
where
    M: MapAccess<'de>,
{
    if slot.is_some() {
        return Err(de::Error::duplicate_field(field));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}
