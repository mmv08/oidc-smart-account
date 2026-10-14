//! Verifies the response of an `attest` request and prints the attestor address.
//!
//! Run this tool outside the enclave, before you set the attestor in the registry.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use nitro_attest::UnparsedAttestationDoc;
use std::time::{SystemTime, UNIX_EPOCH};
use tee_updater::{check_attestation, Attestation};
use time::OffsetDateTime;

#[derive(Parser)]
struct Args {
    /// JSON file with the response of the `attest` request.
    #[arg(long)]
    response: String,
    /// Challenge that you sent in the `attest` request, as hex.
    #[arg(long)]
    challenge: String,
    /// Expected PCR0, PCR1, and PCR2 of the enclave image (`nitro-cli describe-eif`), as hex.
    #[arg(long)]
    pcr0: String,
    #[arg(long)]
    pcr1: String,
    #[arg(long)]
    pcr2: String,
    /// Maximum difference between the attestation time and now, in seconds.
    #[arg(long, default_value_t = 300)]
    max_age: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let response: serde_json::Value = serde_json::from_slice(&std::fs::read(&args.response)?)?;
    let document = STANDARD.decode(
        response["attestationDocument"]
            .as_str()
            .context("response has no attestationDocument")?,
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // This verifies the COSE signature and the certificate chain to the AWS Nitro root certificate.
    let document = UnparsedAttestationDoc::from(document.as_slice())
        .parse_and_verify(OffsetDateTime::from_unix_timestamp(now.try_into()?)?)?;
    let attestation = Attestation {
        timestamp: document.timestamp.unix_timestamp().try_into()?,
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
    let challenge = hex::decode(args.challenge.trim_start_matches("0x"))?;

    println!(
        "{}",
        check_attestation(&attestation, &expected_pcrs, &challenge, now, args.max_age)?
    );
    Ok(())
}

fn pcr(value: &str) -> Result<[u8; 48]> {
    let bytes = hex::decode(value.trim_start_matches("0x"))?;
    bytes.try_into().ok().context("PCR is not 48 bytes")
}
