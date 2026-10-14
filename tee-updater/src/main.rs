mod nitro;

use alloy_primitives::{Address, B256, Bytes};
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser};
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tee_updater::http::{self, Url};
use tee_updater::{AttestResponse, KeySet, SignedKeySet, address, parse_jwks};
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

/// The parent instance always has this vsock context ID.
const PARENT_CID: u32 = 3;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Gets the JWKS of an OIDC issuer and signs it for the JWKSRegistry contract.
#[derive(Parser)]
enum Command {
    /// Local mode: gets the JWKS over TCP and signs it with the key that you give.
    Sign {
        #[command(flatten)]
        request: SignRequest,
        /// Attestor private key as hex. Use this mode only for tests and demos.
        #[arg(long)]
        private_key: B256,
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
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    /// Returns a Nitro attestation document that contains the attestor public key.
    Attest { challenge: Bytes },
    /// Gets the JWKS through the parent proxy and returns a signed key set.
    Sign(SignRequest),
}

/// The JWKS to get, and the registry that the signature is for.
#[derive(Args, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignRequest {
    /// URI of the issuer JWKS. It must be the same as the URI of the registry.
    #[arg(long)]
    jwks_uri: String,
    /// ID of the chain of the registry.
    #[arg(long)]
    chain_id: u64,
    /// Address of the JWKSRegistry contract.
    #[arg(long)]
    registry: Address,
}

impl SignRequest {
    /// Gets the JWKS over `stream` and signs it. `fetched_at` is the time before the request.
    fn sign(
        self,
        key: &SigningKey,
        url: &Url,
        stream: impl Read + Write,
        fetched_at: u64,
    ) -> Result<SignedKeySet> {
        let key_set = KeySet {
            jwksUri: self.jwks_uri,
            keys: parse_jwks(&http::get(url, stream, fetched_at)?)?,
            fetchedAt: fetched_at,
        };
        Ok(key_set.sign(key, self.chain_id, self.registry))
    }
}

fn main() -> Result<()> {
    match Command::parse() {
        Command::Sign {
            request,
            private_key,
        } => {
            let key = SigningKey::from_slice(private_key.as_slice())
                .context("private key is not a valid secp256k1 key")?;
            let url = Url::parse(&request.jwks_uri)?;
            let fetched_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let stream = TcpStream::connect((url.host.as_str(), url.port))?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            let signed = request.sign(&key, &url, stream, fetched_at)?;
            println!("{}", serde_json::to_string_pretty(&signed)?);
            Ok(())
        }
        Command::Serve { port, proxy_port } => serve(port, proxy_port),
    }
}

/// Answers one request at a time. The attestor key stays in the enclave memory. A restart makes a
/// new key, and the owner must set it in the registry again.
fn serve(port: u32, proxy_port: u32) -> Result<()> {
    let key = SigningKey::from_slice(&nitro::random()?)?;
    println!("attestor {}", address(key.verifying_key()));
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)?;
    for mut stream in listener.incoming().flatten() {
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
    let response = match serde_json::from_slice(&request)? {
        Request::Attest { challenge } => {
            let public_key = key.verifying_key().to_sec1_point(false);
            let document =
                nitro::attestation_document(Some(public_key.as_bytes()), Some(&challenge))?;
            serde_json::to_value(AttestResponse {
                attestation_document: document.into(),
            })?
        }
        Request::Sign(request) => {
            let url = Url::parse(&request.jwks_uri)?;
            ensure!(url.https, "the enclave gets the JWKS only over https");
            // Take the time before the request. A slow parent can only make the key set look older.
            let fetched_at = nitro::time()?;
            let proxy = VsockStream::connect(&VsockAddr::new(PARENT_CID, proxy_port))?;
            proxy.set_read_timeout(Some(TIMEOUT))?;
            serde_json::to_value(request.sign(key, &url, proxy, fetched_at)?)?
        }
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::Request;

    #[test]
    fn reads_requests_of_the_parent() {
        let attest: Request =
            serde_json::from_str(r#"{"operation":"attest","challenge":"0x0102"}"#).unwrap();
        assert!(matches!(attest, Request::Attest { challenge } if challenge[..] == [1, 2]));
        let sign: Request = serde_json::from_str(
            r#"{"operation":"sign","jwksUri":"https://a.example/jwks","chainId":1,"registry":"0x1111111111111111111111111111111111111111"}"#,
        )
        .unwrap();
        assert!(matches!(sign, Request::Sign(request) if request.chain_id == 1));

        for request in [
            r#"{"operation":"attest","challenge":"0x01","extra":1}"#,
            r#"{"operation":"sign","jwksUri":"https://a.example/jwks","chainId":1,"registry":"0x1111111111111111111111111111111111111111","extra":1}"#,
            r#"{"operation":"other"}"#,
        ] {
            assert!(
                serde_json::from_str::<Request>(request).is_err(),
                "{request}"
            );
        }
    }
}
