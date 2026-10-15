//! Examines the response of an `attest` request and prints the attestor address.
//!
//! Run this tool on a trusted computer, before you set the attestor in the registry.

use alloy_primitives::{B256, FixedBytes};
use anyhow::{Context, Result};
use clap::Parser;
use nitro_attest::UnparsedAttestationDoc;
use std::path::PathBuf;
use tee_updater::{AttestResponse, Attestation, check_attestation};
use time::OffsetDateTime;

#[derive(Parser)]
struct Args {
    /// JSON file with the response of the `attest` request.
    #[arg(long)]
    response: PathBuf,
    /// The 32-byte random challenge that you sent in the `attest` request, as hex.
    #[arg(long)]
    challenge: B256,
    /// Expected PCR0 of the enclave image (from `nitro-cli build-enclave`), as hex.
    #[arg(long)]
    pcr0: FixedBytes<48>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let response: AttestResponse = serde_json::from_slice(&std::fs::read(&args.response)?)?;

    // This examines the COSE signature, and the certificate chain to the AWS Nitro root
    // certificate at the current time.
    let mut document = UnparsedAttestationDoc::from(&response.attestation_document[..])
        .parse_and_verify(OffsetDateTime::now_utc())?;
    let attestation = Attestation {
        // `nitro_attest` removes zero PCRs. Thus a debug-mode enclave has no PCR0 here.
        pcr0: document
            .pcrs
            .remove(&0)
            .map(|pcr| pcr.value)
            .unwrap_or_default(),
        public_key: document
            .public_key
            .context("document has no public key")?
            .into_vec(),
        nonce: document.nonce.context("document has no nonce")?.into_vec(),
    };

    println!(
        "{}",
        check_attestation(&attestation, args.pcr0, args.challenge)?
    );
    Ok(())
}
