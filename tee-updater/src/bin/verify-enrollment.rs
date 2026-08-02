use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use nitro_attest::UnparsedAttestationDoc;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
use tee_google_key_updater::{
    parse_fixed_hex, verify_enrollment_evidence, EnrollmentEvidence, EnrollmentPolicy,
};
use time::OffsetDateTime;

const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

#[derive(Parser)]
#[command(about = "Verify AWS Nitro attestation and the TEE updater enrollment binding")]
struct Args {
    /// Raw COSE document, Base64 document, or JSON output from the enclave `enroll` command.
    #[arg(long)]
    document: String,
    #[arg(long)]
    chain_id: String,
    #[arg(long)]
    updater: String,
    #[arg(long)]
    attestor_epoch: u64,
    #[arg(long)]
    policy_hash: String,
    #[arg(long)]
    challenge: String,
    /// Expected measurement as INDEX=96_HEX_DIGITS. PCR0, PCR1 and PCR2 are mandatory.
    #[arg(long = "pcr", required = true)]
    pcrs: Vec<String>,
    #[arg(long, default_value_t = 300)]
    max_age_seconds: u64,
    #[arg(long, default_value_t = 30)]
    max_future_skew_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    protocol: &'static str,
    certificate_chain_verified: bool,
    attestor: String,
    timestamp_seconds: u64,
    pcrs: BTreeMap<u16, String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let document = read_document(&args.document)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("verifier clock is before Unix epoch")?
        .as_secs();
    let verification_time = OffsetDateTime::from_unix_timestamp(
        now.try_into().context("verifier time does not fit i64")?,
    )?;

    // This verifies the COSE signature, certificate signatures and validity, and the embedded
    // AWS Nitro root fingerprint before any application policy is evaluated.
    let attestation = UnparsedAttestationDoc::from(document.as_slice())
        .parse_and_verify(verification_time)
        .context("AWS Nitro certificate-chain or COSE verification failed")?;
    let timestamp_seconds = attestation
        .timestamp
        .unix_timestamp()
        .try_into()
        .context("attestation timestamp is before Unix epoch")?;
    let evidence_pcrs = attestation
        .pcrs
        .iter()
        .map(|(index, digest)| (*index, digest.value.clone()))
        .collect::<BTreeMap<_, _>>();
    let evidence = EnrollmentEvidence {
        timestamp_seconds,
        public_key: attestation
            .public_key
            .context("attestation document does not contain the application public key")?
            .into_vec(),
        user_data: attestation
            .user_data
            .context("attestation document does not contain enrollment user_data")?
            .into_vec(),
        nonce: attestation
            .nonce
            .context("attestation document does not contain the enrollment challenge")?
            .into_vec(),
        pcrs: evidence_pcrs.clone(),
    };
    let policy = EnrollmentPolicy {
        chain_id: args.chain_id,
        updater: args.updater,
        attestor_epoch: args.attestor_epoch,
        policy_hash: parse_fixed_hex::<32>(&args.policy_hash).context("invalid policy hash")?,
        challenge: parse_fixed_hex::<32>(&args.challenge).context("invalid challenge")?,
        expected_pcrs: parse_pcrs(&args.pcrs)?,
        now_seconds: now,
        max_age_seconds: args.max_age_seconds,
        max_future_skew_seconds: args.max_future_skew_seconds,
    };
    let verified = verify_enrollment_evidence(&policy, &evidence)?;
    let pcrs = evidence_pcrs
        .into_iter()
        .map(|(index, value)| (index, format!("0x{}", hex::encode(value))))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&Output {
            protocol: "tee-google-key-enrollment-verification-v1",
            certificate_chain_verified: true,
            attestor: verified.attestor,
            timestamp_seconds: verified.timestamp_seconds,
            pcrs,
        })?
    );
    Ok(())
}

fn read_document(path: &str) -> Result<Vec<u8>> {
    let file = File::open(path).context("failed to open attestation document")?;
    let bytes = read_bounded(file, MAX_DOCUMENT_BYTES)?;
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        let encoded = value
            .get("attestationDocument")
            .and_then(serde_json::Value::as_str)
            .context("JSON does not contain a string attestationDocument")?;
        return STANDARD
            .decode(encoded)
            .context("attestationDocument is not canonical Base64");
    }
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if let Ok(decoded) = STANDARD.decode(text.trim()) {
            return Ok(decoded);
        }
    }
    Ok(bytes)
}

fn read_bounded(mut input: impl Read, max_bytes: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read attestation document")?;
    if bytes.len() > max_bytes {
        bail!("attestation document exceeds {max_bytes} bytes");
    }
    Ok(bytes)
}

fn parse_pcrs(values: &[String]) -> Result<BTreeMap<u16, Vec<u8>>> {
    let mut output = BTreeMap::new();
    for value in values {
        let (index, digest) = value
            .split_once('=')
            .context("PCR must use INDEX=HEX format")?;
        let index: u16 = index.parse().context("invalid PCR index")?;
        let digest = parse_fixed_hex::<48>(digest).context("invalid SHA-384 PCR digest")?;
        if output.insert(index, digest.to_vec()).is_some() {
            bail!("duplicate PCR{index}");
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::read_bounded;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_stops_after_limit_plus_one() {
        assert_eq!(
            read_bounded(Cursor::new(vec![1_u8; 4]), 4).unwrap().len(),
            4
        );
        assert!(read_bounded(Cursor::new(vec![1_u8; 5]), 4).is_err());
    }
}
