//! Verifies the response of an `attest` request and prints the attestor address.
//!
//! Run this tool outside the enclave, before you set the attestor in the registry.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Parser;
use nitro_attest::UnparsedAttestationDoc;
use tee_updater::{Attestation, check_attestation};
use time::OffsetDateTime;

#[derive(Parser)]
struct Args {
    /// JSON file with the response of the `attest` request.
    #[arg(long)]
    response: String,
    /// The 32-byte random challenge that you sent in the `attest` request, as hex.
    #[arg(long)]
    challenge: String,
    /// Expected PCR0, PCR1, and PCR2 of the enclave image (`nitro-cli describe-eif`), as hex.
    #[arg(long)]
    pcr0: String,
    #[arg(long)]
    pcr1: String,
    #[arg(long)]
    pcr2: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let response: serde_json::Value = serde_json::from_slice(&std::fs::read(&args.response)?)?;
    let document = STANDARD.decode(
        response["attestationDocument"]
            .as_str()
            .context("response has no attestationDocument")?,
    )?;

    // This verifies the COSE signature and the certificate chain to the AWS Nitro root certificate.
    let document = UnparsedAttestationDoc::from(document.as_slice())
        .parse_and_verify(OffsetDateTime::now_utc())?;
    let attestation = Attestation {
        pcrs: document
            .pcrs
            .into_iter()
            .map(|(index, digest)| (index, digest.value))
            .collect(),
        public_key: document
            .public_key
            .context("document has no public key")?
            .into_vec(),
        nonce: document.nonce.context("document has no nonce")?.into_vec(),
    };
    let expected_pcrs = [pcr(&args.pcr0)?, pcr(&args.pcr1)?, pcr(&args.pcr2)?];
    let challenge: [u8; 32] = hex::decode(args.challenge.trim_start_matches("0x"))?
        .try_into()
        .ok()
        .context("challenge is not 32 bytes")?;

    println!(
        "{}",
        check_attestation(&attestation, &expected_pcrs, &challenge)?
    );
    Ok(())
}

fn pcr(value: &str) -> Result<[u8; 48]> {
    let bytes = hex::decode(value.trim_start_matches("0x"))?;
    bytes.try_into().ok().context("PCR is not 48 bytes")
}
