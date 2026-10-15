//! Shared code of the TEE updater. It reads the JWKS, signs key sets, and examines attestations.

pub mod http;

use alloy_primitives::{Address, B256, Bytes, FixedBytes};
use alloy_sol_types::{SolStruct, eip712_domain, sol};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

sol! {
    /// One RSA key of the issuer, as in the `JWKSRegistry` contract.
    #[derive(Debug, PartialEq, Eq, Serialize)]
    struct Key {
        string kid;
        bytes modulus;
    }

    /// The EIP-712 struct that the attestor signs, as in the `JWKSRegistry` contract.
    #[derive(Debug, Serialize)]
    struct KeySet {
        string jwksUri;
        Key[] keys;
        uint64 fetchedAt;
    }
}

/// A key set that the attestor signed. Anyone can send it to the registry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeySet {
    pub chain_id: u64,
    pub registry: Address,
    #[serde(flatten)]
    pub key_set: KeySet,
    pub attestor: Address,
    pub signature: Bytes,
}

impl KeySet {
    /// Returns the EIP-712 digest that `JWKSRegistry.hashKeySet` returns for this key set.
    pub fn digest(&self, chain_id: u64, registry: Address) -> B256 {
        self.eip712_signing_hash(&eip712_domain! {
            name: "JWKSRegistry",
            version: "1",
            chain_id: chain_id,
            verifying_contract: registry,
        })
    }

    /// Signs the key set with the attestor key for one registry on one chain.
    pub fn sign(self, key: &SigningKey, chain_id: u64, registry: Address) -> SignedKeySet {
        let digest = self.digest(chain_id, registry);
        let (signature, recovery_id) = key.sign_prehash_recoverable(digest.as_slice());
        let mut signature = signature.to_bytes().to_vec();
        signature.push(27 + recovery_id.to_byte());
        SignedKeySet {
            chain_id,
            registry,
            key_set: self,
            attestor: address(key.verifying_key()),
            signature: signature.into(),
        }
    }
}

/// Response of the enclave to an `attest` request.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    /// Nitro attestation document (COSE_Sign1) that AWS signs.
    pub attestation_document: Bytes,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// The JWK members that the updater reads. It does not read other members. A duplicate member
/// causes an error.
#[derive(Deserialize)]
struct Jwk {
    kty: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// Reads a JWKS and returns its RS256 signature keys, in the order of their `kid`.
///
/// The verifier can use only RSA keys for RS256 signatures with the exponent 65537. The function
/// keeps only these keys. As RFC 7517 recommends, other keys do not cause an error. A duplicate
/// `kid` causes an error.
pub fn parse_jwks(body: &[u8]) -> Result<Vec<Key>> {
    let jwks: Jwks = serde_json::from_slice(body).context("JWKS is not valid")?;
    let mut keys = BTreeMap::new();
    for jwk in jwks.keys {
        if jwk.kty.as_deref() == Some("RSA")
            && matches!(jwk.alg.as_deref(), None | Some("RS256"))
            && matches!(jwk.key_use.as_deref(), None | Some("sig"))
            && jwk.e.as_deref() == Some("AQAB")
            && let Some(kid) = jwk.kid
            && let Some(Ok(modulus)) = jwk.n.map(|n| URL_SAFE_NO_PAD.decode(n))
        {
            ensure!(
                keys.insert(kid, modulus).is_none(),
                "JWKS has a duplicate kid"
            );
        }
    }
    Ok(keys
        .into_iter()
        .map(|(kid, modulus)| Key {
            kid,
            modulus: modulus.into(),
        })
        .collect())
}

/// Returns the Ethereum address of a secp256k1 public key.
pub fn address(key: &VerifyingKey) -> Address {
    Address::from_raw_public_key(&key.to_sec1_point(false).as_bytes()[1..])
}

/// Values of a Nitro attestation document that `check_attestation` examines.
pub struct Attestation {
    /// PCR0: the measurement of the full enclave image.
    pub pcr0: Vec<u8>,
    /// Public key of the attestor, as SEC1 bytes.
    pub public_key: Vec<u8>,
    /// The challenge that the enclave put in the document.
    pub nonce: Vec<u8>,
}

/// Returns the attestor address if the attestation is for the expected enclave image and the
/// expected challenge.
///
/// Before you call this function, examine the AWS signature of the document. The challenge must be
/// new and random. Thus the document is new, and nobody can use an old document again.
pub fn check_attestation(
    attestation: &Attestation,
    expected_pcr0: FixedBytes<48>,
    challenge: B256,
) -> Result<Address> {
    // A debug-mode enclave has a zero PCR0, and the parent instance can read its memory.
    ensure!(!expected_pcr0.is_zero(), "PCR0 must not be zero");
    ensure!(
        attestation.pcr0 == expected_pcr0.as_slice(),
        "PCR0 is not the expected value"
    );
    ensure!(
        attestation.nonce == challenge.as_slice(),
        "attestation nonce is not the challenge"
    );
    let key = VerifyingKey::from_sec1_bytes(&attestation.public_key)
        .context("attestation public key is not a secp256k1 key")?;
    Ok(address(&key))
}
