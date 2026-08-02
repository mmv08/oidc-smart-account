mod kms;
mod nitro;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Parser, Subcommand};
use kms::{KmsCredentials, ProvisionedKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tee_google_key_updater::{
    attestor_identity, enrollment_digest, enrollment_policy_hash, fetch_google_jwks,
    parse_fixed_hex, sign_snapshot, SignedSnapshot, SigningContext,
};
use vsock::{VsockListener, VMADDR_CID_ANY};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "tee-google-key-updater")]
#[command(about = "Fetch, validate and sign Google's OIDC key set inside AWS Nitro")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a 32-byte application key through attested AWS KMS GenerateDataKey.
    Provision {
        #[arg(long)]
        kms_key_id: String,
        #[command(flatten)]
        kms: KmsArgs,
    },
    /// Fetch Google's pinned JWKS endpoint and emit a signed onchain snapshot.
    FetchSign {
        #[command(flatten)]
        context: ContextArgs,
        #[command(flatten)]
        key: KeyArgs,
        /// Development only: use the process clock instead of the NSM attestation timestamp.
        #[arg(long, default_value_t = false)]
        unsafe_system_time: bool,
    },
    /// Produce an AWS attestation document binding a challenge and policy to the application key.
    Enroll {
        #[command(flatten)]
        context: EnrollmentArgs,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Run the production enclave request server over AF_VSOCK.
    Serve {
        #[arg(long, default_value_t = 5000)]
        port: u32,
    },
}

#[derive(Clone, Args)]
struct ContextArgs {
    #[arg(long)]
    chain_id: String,
    #[arg(long)]
    updater: String,
    #[arg(long)]
    attestor_epoch: u64,
    #[arg(long)]
    nonce: String,
}

#[derive(Clone, Args)]
struct EnrollmentArgs {
    #[arg(long)]
    chain_id: String,
    #[arg(long)]
    updater: String,
    #[arg(long)]
    attestor_epoch: u64,
    /// Fresh 32-byte challenge from the enrollment ceremony.
    #[arg(long)]
    challenge: String,
}

#[derive(Clone, Args)]
struct KeyArgs {
    /// File containing the Base64 KMS CiphertextBlob from `provision`.
    #[arg(long, conflicts_with = "unsafe_private_key_hex")]
    kms_ciphertext_file: Option<String>,
    /// Development only. Refused unless --allow-unsafe-local-key is also present.
    #[arg(long, conflicts_with = "kms_ciphertext_file")]
    unsafe_private_key_hex: Option<Zeroizing<String>>,
    #[arg(long, requires = "unsafe_private_key_hex", default_value_t = false)]
    allow_unsafe_local_key: bool,
    #[command(flatten)]
    kms: KmsArgs,
}

#[derive(Clone, Args)]
struct KmsArgs {
    #[arg(long, env = "AWS_REGION")]
    aws_region: Option<String>,
    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    aws_access_key_id: Option<Zeroizing<String>>,
    #[arg(long, env = "AWS_SECRET_ACCESS_KEY")]
    aws_secret_access_key: Option<Zeroizing<String>>,
    #[arg(long, env = "AWS_SESSION_TOKEN")]
    aws_session_token: Option<Zeroizing<String>>,
    #[arg(long, default_value_t = 8000)]
    kms_proxy_port: u16,
    #[arg(long, default_value = "/app/kmstool_enclave_cli")]
    kmstool: String,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ServerRequest {
    Provision {
        kms_key_id: String,
        aws_region: String,
        aws_access_key_id: Zeroizing<String>,
        aws_secret_access_key: Zeroizing<String>,
        aws_session_token: Zeroizing<String>,
    },
    FetchSign {
        chain_id: String,
        updater: String,
        attestor_epoch: u64,
        nonce: String,
        kms_ciphertext: String,
        aws_region: String,
        aws_access_key_id: Zeroizing<String>,
        aws_secret_access_key: Zeroizing<String>,
        aws_session_token: Zeroizing<String>,
    },
    Enroll {
        chain_id: String,
        updater: String,
        attestor_epoch: u64,
        challenge: String,
        kms_ciphertext: String,
        aws_region: String,
        aws_access_key_id: Zeroizing<String>,
        aws_secret_access_key: Zeroizing<String>,
        aws_session_token: Zeroizing<String>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerError<'a> {
    ok: bool,
    error: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvisionOutput {
    protocol: &'static str,
    attestor: String,
    kms_ciphertext: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentOutput {
    protocol: &'static str,
    chain_id: String,
    updater: String,
    attestor_epoch: u64,
    policy_hash: String,
    challenge: String,
    attestor: String,
    public_key: String,
    user_data: String,
    attestation_document: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Provision { kms_key_id, kms } => provision(&kms_key_id, kms),
        Command::FetchSign {
            context,
            key,
            unsafe_system_time,
        } => fetch_sign(context, key, unsafe_system_time),
        Command::Enroll { context, key } => enroll(context, key),
        Command::Serve { port } => serve(port),
    }
}

fn provision(kms_key_id: &str, kms: KmsArgs) -> Result<()> {
    print_json(&provision_output(kms_key_id, &kms_credentials(kms)?)?)
}

fn fetch_sign(context: ContextArgs, key: KeyArgs, unsafe_system_time: bool) -> Result<()> {
    let private_key = load_key(key)?;
    let fetched_at = if unsafe_system_time {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs()
    } else {
        nitro::trusted_time_seconds()?
    };
    print_json(&fetch_signed_snapshot(context, &private_key, fetched_at)?)
}

fn enroll(context: EnrollmentArgs, key: KeyArgs) -> Result<()> {
    let private_key = load_key(key)?;
    print_json(&enrollment_output(context, &private_key)?)
}

fn provision_output(kms_key_id: &str, credentials: &KmsCredentials) -> Result<ProvisionOutput> {
    let ProvisionedKey {
        ciphertext,
        private_key,
    } = credentials.generate_key(kms_key_id)?;
    let (attestor, _) = attestor_identity(&private_key)?;
    Ok(ProvisionOutput {
        protocol: "tee-google-key-provision-v1",
        attestor,
        kms_ciphertext: ciphertext,
    })
}

fn fetch_signed_snapshot(
    context: ContextArgs,
    private_key: &[u8; 32],
    fetched_at: u64,
) -> Result<SignedSnapshot> {
    let keys = fetch_google_jwks()?;
    let signing_context = SigningContext::new(
        &context.chain_id,
        &context.updater,
        context.attestor_epoch,
        &context.nonce,
        fetched_at,
    )?;
    Ok(sign_snapshot(keys, signing_context, private_key)?)
}

fn enrollment_output(context: EnrollmentArgs, private_key: &[u8; 32]) -> Result<EnrollmentOutput> {
    let (attestor, public_key) = attestor_identity(private_key)?;
    let policy_hash = format!("0x{}", hex::encode(enrollment_policy_hash()));
    let user_data = enrollment_digest(
        &context.chain_id,
        &context.updater,
        context.attestor_epoch,
        &policy_hash,
        &attestor,
    )?;
    let challenge = parse_fixed_hex::<32>(&context.challenge).context("invalid challenge")?;
    let document = nitro::attestation_document(&public_key, &user_data, &challenge)?;
    Ok(EnrollmentOutput {
        protocol: "tee-google-key-enrollment-v1",
        chain_id: context.chain_id,
        updater: context.updater,
        attestor_epoch: context.attestor_epoch,
        policy_hash,
        challenge: format!("0x{}", hex::encode(challenge)),
        attestor,
        public_key: format!("0x{}", hex::encode(public_key)),
        user_data: format!("0x{}", hex::encode(user_data)),
        attestation_document: STANDARD.encode(document),
    })
}

fn serve(port: u32) -> Result<()> {
    const PARENT_CID: u32 = 3;
    const MAX_REQUEST_BYTES: usize = 64 * 1024;

    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
        .context("failed to bind enclave request server")?;
    loop {
        let (mut stream, peer) = listener
            .accept()
            .context("failed to accept parent request")?;
        if peer.cid() != PARENT_CID {
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(60)))?;
        let mut body = Zeroizing::new(Vec::new());
        Read::take(&mut stream, (MAX_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .context("failed to read enclave request")?;

        let response = if body.len() > MAX_REQUEST_BYTES {
            serde_json::to_vec(&ServerError {
                ok: false,
                error: "request exceeds 64 KiB",
            })?
        } else {
            match serde_json::from_slice::<ServerRequest>(&body)
                .context("invalid or unsupported enclave request")
                .and_then(handle_server_request)
            {
                Ok(value) => serde_json::to_vec(&value)?,
                Err(error) => {
                    let message = format!("{error:#}");
                    serde_json::to_vec(&ServerError {
                        ok: false,
                        error: &message,
                    })?
                }
            }
        };
        stream
            .write_all(&response)
            .context("failed to write enclave response")?;
    }
}

fn handle_server_request(request: ServerRequest) -> Result<serde_json::Value> {
    match request {
        ServerRequest::Provision {
            kms_key_id,
            aws_region,
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
        } => {
            let credentials = server_credentials(
                aws_region,
                aws_access_key_id,
                aws_secret_access_key,
                aws_session_token,
            );
            Ok(serde_json::to_value(provision_output(
                &kms_key_id,
                &credentials,
            )?)?)
        }
        ServerRequest::FetchSign {
            chain_id,
            updater,
            attestor_epoch,
            nonce,
            kms_ciphertext,
            aws_region,
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
        } => {
            let private_key = server_credentials(
                aws_region,
                aws_access_key_id,
                aws_secret_access_key,
                aws_session_token,
            )
            .decrypt_key(&kms_ciphertext)?;
            let fetched_at = nitro::trusted_time_seconds()?;
            Ok(serde_json::to_value(fetch_signed_snapshot(
                ContextArgs {
                    chain_id,
                    updater,
                    attestor_epoch,
                    nonce,
                },
                &private_key,
                fetched_at,
            )?)?)
        }
        ServerRequest::Enroll {
            chain_id,
            updater,
            attestor_epoch,
            challenge,
            kms_ciphertext,
            aws_region,
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
        } => {
            let private_key = server_credentials(
                aws_region,
                aws_access_key_id,
                aws_secret_access_key,
                aws_session_token,
            )
            .decrypt_key(&kms_ciphertext)?;
            Ok(serde_json::to_value(enrollment_output(
                EnrollmentArgs {
                    chain_id,
                    updater,
                    attestor_epoch,
                    challenge,
                },
                &private_key,
            )?)?)
        }
    }
}

fn server_credentials(
    region: String,
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
) -> KmsCredentials {
    KmsCredentials {
        region,
        proxy_port: 8000,
        access_key_id,
        secret_access_key,
        session_token,
        binary: "/app/kmstool_enclave_cli".to_owned(),
    }
}

fn load_key(args: KeyArgs) -> Result<Zeroizing<[u8; 32]>> {
    let KeyArgs {
        kms_ciphertext_file,
        unsafe_private_key_hex,
        allow_unsafe_local_key,
        kms,
    } = args;
    if let Some(path) = kms_ciphertext_file {
        let ciphertext = fs::read_to_string(path).context("failed to read KMS ciphertext file")?;
        return kms_credentials(kms)?.decrypt_key(ciphertext.trim());
    }
    if let Some(value) = unsafe_private_key_hex {
        if !allow_unsafe_local_key {
            bail!("unsafe local key requires --allow-unsafe-local-key");
        }
        let parsed = parse_fixed_hex::<32>(&value).context("invalid unsafe private key")?;
        return Ok(Zeroizing::new(parsed));
    }
    bail!("provide --kms-ciphertext-file or an explicitly enabled unsafe local key")
}

fn kms_credentials(args: KmsArgs) -> Result<KmsCredentials> {
    Ok(KmsCredentials {
        region: required(args.aws_region, "AWS region")?,
        proxy_port: args.kms_proxy_port,
        access_key_id: required(args.aws_access_key_id, "AWS access key ID")?,
        secret_access_key: required(args.aws_secret_access_key, "AWS secret access key")?,
        session_token: required(args.aws_session_token, "AWS session token")?,
        binary: args.kmstool,
    })
}

fn required<T>(value: Option<T>, name: &str) -> Result<T> {
    value.with_context(|| format!("missing {name}"))
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod server_tests {
    use super::ServerRequest;
    use zeroize::Zeroizing;

    fn assert_zeroizing(_: &Zeroizing<String>) {}

    #[test]
    fn accepts_only_narrow_production_server_operations() {
        let request = r#"{
            "operation":"fetchSign",
            "chainId":"31337",
            "updater":"0x1111111111111111111111111111111111111111",
            "attestorEpoch":1,
            "nonce":"0",
            "kmsCiphertext":"ciphertext",
            "awsRegion":"eu-central-1",
            "awsAccessKeyId":"access",
            "awsSecretAccessKey":"secret",
            "awsSessionToken":"token"
        }"#;
        assert!(serde_json::from_str::<ServerRequest>(request).is_ok());

        let unsafe_request = request.replace(
            "\"kmsCiphertext\":\"ciphertext\"",
            "\"kmsCiphertext\":\"ciphertext\",\"unsafePrivateKey\":\"01\"",
        );
        assert!(serde_json::from_str::<ServerRequest>(&unsafe_request).is_err());
        assert!(serde_json::from_str::<ServerRequest>(r#"{"operation":"shell"}"#).is_err());

        let parent_selected_policy = r#"{
            "operation":"enroll",
            "chainId":"31337",
            "updater":"0x1111111111111111111111111111111111111111",
            "attestorEpoch":1,
            "policyHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "challenge":"0x0000000000000000000000000000000000000000000000000000000000000000",
            "kmsCiphertext":"ciphertext",
            "awsRegion":"eu-central-1",
            "awsAccessKeyId":"access",
            "awsSecretAccessKey":"secret",
            "awsSessionToken":"token"
        }"#;
        assert!(serde_json::from_str::<ServerRequest>(parent_selected_policy).is_err());
    }

    #[test]
    fn deserializes_credentials_directly_into_zeroizing_owners() {
        let request = serde_json::from_str::<ServerRequest>(
            r#"{
                "operation":"provision",
                "kmsKeyId":"alias/test",
                "awsRegion":"eu-central-1",
                "awsAccessKeyId":"access",
                "awsSecretAccessKey":"secret",
                "awsSessionToken":"token"
            }"#,
        )
        .unwrap();

        let ServerRequest::Provision {
            aws_access_key_id,
            aws_secret_access_key,
            aws_session_token,
            ..
        } = request
        else {
            panic!("wrong operation");
        };
        assert_zeroizing(&aws_access_key_id);
        assert_zeroizing(&aws_secret_access_key);
        assert_zeroizing(&aws_session_token);
    }
}
