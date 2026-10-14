//! Minimal HTTP/1.0 client. It sends one GET request over a stream that the caller opens: a TCP
//! connection on a host, or a vsock connection to the parent proxy in the enclave.

use anyhow::{bail, ensure, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;

/// Maximum size of a response, with its headers.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Parts of an `https://` or `http://` URL.
#[derive(Debug, PartialEq, Eq)]
pub struct Url {
    pub https: bool,
    /// `host` or `host:port`, as in the URL. The request sends it in the `Host` header.
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(url: &str) -> Result<Self> {
        ensure!(
            url.bytes().all(|byte| byte.is_ascii_graphic()),
            "URL has a space or a control character"
        );
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            bail!("URL must start with https:// or http://");
        };
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, port.parse().context("URL port is not valid")?),
            None => (authority, if https { 443 } else { 80 }),
        };
        ensure!(!host.is_empty(), "URL has no host");
        Ok(Self {
            https,
            authority: authority.to_owned(),
            host: host.to_owned(),
            port,
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            },
        })
    }
}

/// Sends `GET url` over `stream` and returns the body of a `200` response.
///
/// For `https`, TLS runs over `stream`. The server certificate must be valid for the URL host
/// in the Mozilla root store. Thus the party that opens the stream cannot change the response.
pub fn get(url: &Url, stream: impl Read + Write) -> Result<Vec<u8>> {
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nAccept: application/json\r\n\r\n",
        url.path, url.authority
    );
    let response = if url.https {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connection =
            ClientConnection::new(Arc::new(config), ServerName::try_from(url.host.clone())?)?;
        exchange(StreamOwned::new(connection, stream), &request)?
    } else {
        exchange(stream, &request)?
    };
    body(&response)
}

/// Returns the body of an HTTP response if its status is `200`.
pub fn body(response: &[u8]) -> Result<Vec<u8>> {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("HTTP response has no end of headers")?;
    let head = std::str::from_utf8(&response[..end]).context("HTTP headers are not UTF-8")?;
    let status = head.lines().next().unwrap_or_default();
    ensure!(
        status.starts_with("HTTP/1.") && status.split(' ').nth(1) == Some("200"),
        "HTTP status is not 200: {status}"
    );
    Ok(response[end + 4..].to_vec())
}

/// Writes the request and reads the response until the server closes the connection.
fn exchange(mut stream: impl Read + Write, request: &str) -> Result<Vec<u8>> {
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut response = Vec::new();
    match stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
    {
        Ok(_) => {}
        // Many servers (Google too) close TLS without `close_notify`. This is safe here: a cut
        // response is not complete JSON, thus `parse_jwks` rejects it.
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.into()),
    }
    ensure!(
        response.len() as u64 <= MAX_RESPONSE_BYTES,
        "HTTP response is too large"
    );
    Ok(response)
}
