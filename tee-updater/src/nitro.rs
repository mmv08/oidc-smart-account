#[cfg(feature = "nitro")]
mod implementation {
    use anyhow::{bail, Context, Result};
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;
    use serde_cbor::Value;

    struct Nsm(i32);

    impl Nsm {
        fn open() -> Result<Self> {
            let descriptor = nsm_init();
            if descriptor < 0 {
                bail!("failed to open /dev/nsm");
            }
            Ok(Self(descriptor))
        }

        fn attest(
            &self,
            public_key: Option<&[u8]>,
            user_data: Option<&[u8]>,
            nonce: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            let response = nsm_process_request(
                self.0,
                Request::Attestation {
                    user_data: user_data.map(|value| ByteBuf::from(value.to_vec())),
                    nonce: nonce.map(|value| ByteBuf::from(value.to_vec())),
                    public_key: public_key.map(|value| ByteBuf::from(value.to_vec())),
                },
            );
            match response {
                Response::Attestation { document } => Ok(document),
                Response::Error(error) => bail!("NSM attestation failed: {error:?}"),
                _ => bail!("NSM returned an unexpected response"),
            }
        }
    }

    impl Drop for Nsm {
        fn drop(&mut self) {
            nsm_exit(self.0);
        }
    }

    pub fn attestation_document(
        public_key: &[u8],
        user_data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        Nsm::open()?.attest(Some(public_key), Some(user_data), Some(nonce))
    }

    pub fn trusted_time_seconds() -> Result<u64> {
        let document = Nsm::open()?.attest(None, None, None)?;
        let outer: Value =
            serde_cbor::from_slice(&document).context("invalid NSM COSE document")?;
        let sign1 = match outer {
            Value::Tag(_, inner) => *inner,
            value => value,
        };
        let payload = match sign1 {
            Value::Array(values) if values.len() == 4 => match values.into_iter().nth(2) {
                Some(Value::Bytes(bytes)) => bytes,
                _ => bail!("NSM COSE payload is not bytes"),
            },
            _ => bail!("NSM document is not COSE_Sign1"),
        };
        let payload: Value =
            serde_cbor::from_slice(&payload).context("invalid NSM attestation payload")?;
        let fields = match payload {
            Value::Map(fields) => fields,
            _ => bail!("NSM attestation payload is not a map"),
        };
        let timestamp_ms = fields
            .into_iter()
            .find_map(|(key, value)| match (key, value) {
                (Value::Text(key), Value::Integer(value)) if key == "timestamp" => Some(value),
                _ => None,
            })
            .context("NSM attestation omitted timestamp")?;
        let timestamp_ms = u64::try_from(timestamp_ms).context("invalid NSM timestamp")?;
        Ok(timestamp_ms / 1000)
    }
}

#[cfg(feature = "nitro")]
pub use implementation::{attestation_document, trusted_time_seconds};

#[cfg(not(feature = "nitro"))]
pub fn trusted_time_seconds() -> anyhow::Result<u64> {
    anyhow::bail!("Nitro time requires a binary built with --features nitro")
}

#[cfg(not(feature = "nitro"))]
pub fn attestation_document(
    _public_key: &[u8],
    _user_data: &[u8],
    _nonce: &[u8],
) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("Nitro attestation requires a binary built with --features nitro")
}
