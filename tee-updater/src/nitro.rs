//! Requests to the Nitro Secure Module (NSM) of the enclave.

use anyhow::{Context, Result, anyhow, bail};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;
use serde_cbor::Value;

/// Returns an attestation document (COSE_Sign1) that AWS signs. It contains the enclave
/// measurements (PCRs), the time, and the optional public key and nonce.
pub fn attestation_document(public_key: Option<&[u8]>, nonce: Option<&[u8]>) -> Result<Vec<u8>> {
    match request(Request::Attestation {
        user_data: None,
        nonce: nonce.map(|value| ByteBuf::from(value.to_vec())),
        public_key: public_key.map(|value| ByteBuf::from(value.to_vec())),
    })? {
        Response::Attestation { document } => Ok(document),
        response => bail!("NSM attestation failed: {response:?}"),
    }
}

/// Returns 32 random bytes from the NSM for the attestor key.
pub fn random() -> Result<[u8; 32]> {
    match request(Request::GetRandom)? {
        Response::GetRandom { random } => random
            .get(..32)
            .context("NSM returned fewer than 32 random bytes")?
            .try_into()
            .map_err(Into::into),
        response => bail!("NSM random request failed: {response:?}"),
    }
}

fn request(request: Request) -> Result<Response> {
    let fd = nsm_init();
    if fd < 0 {
        bail!("cannot open /dev/nsm");
    }
    let response = nsm_process_request(fd, request);
    nsm_exit(fd);
    Ok(response)
}

/// Returns the current time in Unix seconds. The time comes from a new attestation document,
/// because the parent instance cannot change it.
pub fn time() -> Result<u64> {
    let document = attestation_document(None, None)?;
    let cose = match serde_cbor::from_slice(&document)? {
        Value::Tag(_, value) => *value,
        value => value,
    };
    let Value::Array(parts) = cose else {
        bail!("NSM document is not COSE_Sign1")
    };
    let Some(Value::Bytes(payload)) = parts.get(2) else {
        bail!("NSM document has no payload")
    };
    let document = AttestationDoc::from_binary(payload).map_err(|error| anyhow!("{error:?}"))?;
    Ok(document.timestamp / 1000)
}
