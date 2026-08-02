use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::process::Command;
use zeroize::Zeroizing;

pub struct KmsCredentials {
    pub region: String,
    pub proxy_port: u16,
    pub access_key_id: Zeroizing<String>,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Zeroizing<String>,
    pub binary: String,
}

pub struct ProvisionedKey {
    pub ciphertext: String,
    pub private_key: Zeroizing<[u8; 32]>,
}

impl KmsCredentials {
    pub fn generate_key(&self, key_id: &str) -> Result<ProvisionedKey> {
        let output = self.run("genkey", &["--key-id", key_id, "--key-spec", "AES-256"])?;
        let output = std::str::from_utf8(&output)
            .context("kmstool_enclave_cli returned non-UTF-8 output")?;
        let ciphertext = prefixed_line(output, "CIPHERTEXT: ")?.to_owned();
        let private_key = decode_private_key(prefixed_line(output, "PLAINTEXT: ")?)?;
        Ok(ProvisionedKey {
            ciphertext,
            private_key,
        })
    }

    pub fn decrypt_key(&self, ciphertext: &str) -> Result<Zeroizing<[u8; 32]>> {
        let output = self.run("decrypt", &["--ciphertext", ciphertext])?;
        let output = std::str::from_utf8(&output)
            .context("kmstool_enclave_cli returned non-UTF-8 output")?;
        decode_private_key(prefixed_line(output, "PLAINTEXT: ")?)
    }

    fn run(&self, operation: &str, args: &[&str]) -> Result<Zeroizing<Vec<u8>>> {
        let proxy_port = self.proxy_port.to_string();
        let output = Command::new(&self.binary)
            .arg(operation)
            .args([
                "--region",
                &self.region,
                "--proxy-port",
                &proxy_port,
                "--aws-access-key-id",
                &self.access_key_id,
                "--aws-secret-access-key",
                &self.secret_access_key,
                "--aws-session-token",
                &self.session_token,
            ])
            .args(args)
            .output()
            .with_context(|| format!("failed to execute {}", self.binary))?;
        let stdout = Zeroizing::new(output.stdout);
        let _stderr = Zeroizing::new(output.stderr);
        if !output.status.success() {
            bail!("kmstool_enclave_cli failed with status {}", output.status);
        }
        Ok(stdout)
    }
}

fn prefixed_line<'a>(output: &'a str, prefix: &str) -> Result<&'a str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .filter(|value| !value.is_empty())
        .with_context(|| format!("kmstool_enclave_cli output omitted {prefix}"))
}

fn decode_private_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .context("kmstool_enclave_cli returned invalid Base64")?,
    );
    if decoded.len() != 32 {
        bail!("KMS data key is not 32 bytes");
    }
    let mut private_key = Zeroizing::new([0_u8; 32]);
    private_key.copy_from_slice(&decoded);
    Ok(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kmstool_output_without_logging_plaintext() {
        let encoded = STANDARD.encode([7_u8; 32]);
        let output =
            Zeroizing::new(format!("CIPHERTEXT: encrypted\nPLAINTEXT: {encoded}\n").into_bytes());
        assert_eq!(
            prefixed_line(std::str::from_utf8(&output).unwrap(), "CIPHERTEXT: ").unwrap(),
            "encrypted"
        );
        assert_eq!(*decode_private_key(&encoded).unwrap(), [7_u8; 32]);
    }

    #[test]
    fn kmstool_stdout_has_a_zeroizing_owner() {
        fn require_zeroizing_bytes(_: &Zeroizing<Vec<u8>>) {}

        let output = Zeroizing::new(b"PLAINTEXT: secret\n".to_vec());
        require_zeroizing_bytes(&output);
        assert_eq!(
            prefixed_line(std::str::from_utf8(&output).unwrap(), "PLAINTEXT: ").unwrap(),
            "secret"
        );
    }
}
