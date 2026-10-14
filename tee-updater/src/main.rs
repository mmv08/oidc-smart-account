mod nitro;

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tee_updater::http::{self, Url};
use tee_updater::{address, parse_jwks, sign_snapshot};
use vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

/// The parent instance always has this vsock context ID.
const PARENT_CID: u32 = 3;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Gets the JWKS of an OIDC issuer and signs it for the JWKSRegistry contract.
#[derive(Parser)]
enum Command {
    /// Local mode: gets the JWKS over TCP and signs it with the key that you give.
    Sign {
        #[arg(long)]
        jwks_uri: String,
        #[arg(long)]
        chain_id: u64,
        /// Address of the JWKSRegistry contract.
        #[arg(long)]
        registry: String,
        /// Attestor private key as hex. Use this mode only for tests and demos.
        #[arg(long)]
        private_key: String,
    },
    /// Enclave mode: makes a new attestor key and answers requests from the parent instance.
    Serve {
        /// vsock port for requests.
        #[arg(long, default_value_t = 5000)]
        port: u32,
        /// vsock port of the parent proxy to the JWKS host.
        #[arg(long, default_value_t = 8443)]
        proxy_port: u32,
    },
}

/// A request from the parent instance. The connection holds one JSON request.
#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Request {
    /// Returns a Nitro attestation document that contains the attestor public key.
    Attest { challenge: String },
    /// Gets the JWKS through the parent proxy and returns a signed snapshot.
    Sign {
        jwks_uri: String,
        chain_id: u64,
        registry: String,
    },
}

fn main() -> Result<()> {
    match Command::parse() {
        Command::Sign {
            jwks_uri,
            chain_id,
            registry,
            private_key,
        } => {
            let key = SigningKey::from_slice(&hex::decode(private_key.trim_start_matches("0x"))?)
                .context("private key is not a 32-byte secp256k1 key")?;
            let url = Url::parse(&jwks_uri)?;
            let fetched_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let stream = TcpStream::connect((url.host.as_str(), url.port))?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            let keys = parse_jwks(&http::get(&url, stream)?)?;
            let snapshot = sign_snapshot(&key, chain_id, &registry, &jwks_uri, keys, fetched_at)?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
            Ok(())
        }
        Command::Serve { port, proxy_port } => serve(port, proxy_port),
    }
}

/// Answers one request at a time. The attestor key stays in the enclave memory. A restart makes a
/// new key, and the owner must set it in the registry again.
fn serve(port: u32, proxy_port: u32) -> Result<()> {
    let key = SigningKey::random(&mut OsRng);
    println!("attestor {}", address(key.verifying_key()));
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)?;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let response = handle(&key, proxy_port, &mut stream)
            .unwrap_or_else(|error| json!({ "error": format!("{error:#}") }));
        let _ = stream.write_all(response.to_string().as_bytes());
    }
    Ok(())
}

fn handle(key: &SigningKey, proxy_port: u32, stream: &mut VsockStream) -> Result<Value> {
    stream.set_read_timeout(Some(TIMEOUT))?;
    let mut request = Vec::new();
    stream.take(MAX_REQUEST_BYTES).read_to_end(&mut request)?;
    match serde_json::from_slice(&request)? {
        Request::Attest { challenge } => {
            let public_key = key.verifying_key().to_encoded_point(false);
            let challenge = hex::decode(challenge.trim_start_matches("0x"))?;
            let document =
                nitro::attestation_document(Some(public_key.as_bytes()), Some(&challenge))?;
            Ok(json!({
                "attestor": address(key.verifying_key()),
                "attestationDocument": STANDARD.encode(document),
            }))
        }
        Request::Sign {
            jwks_uri,
            chain_id,
            registry,
        } => {
            let url = Url::parse(&jwks_uri)?;
            ensure!(url.https, "the enclave gets the JWKS only over https");
            // Take the time before the request. A slow parent can only make the snapshot look older.
            let fetched_at = nitro::time()?;
            let proxy = VsockStream::connect(&VsockAddr::new(PARENT_CID, proxy_port))?;
            proxy.set_read_timeout(Some(TIMEOUT))?;
            let keys = parse_jwks(&http::get(&url, proxy)?)?;
            Ok(serde_json::to_value(sign_snapshot(
                key, chain_id, &registry, &jwks_uri, keys, fetched_at,
            )?)?)
        }
    }
}
