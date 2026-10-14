//! Minimal HTTP/1.0 client. It sends one GET request over a stream that the caller opens: a TCP
//! connection on a host, or a vsock connection to the parent proxy in the enclave.

use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::{sync::Arc, time::Duration};

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
        ensure!(
            !rest.contains(['#', '\\']),
            "URL has a fragment or a backslash"
        );
        let (authority, path) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
        ensure!(!authority.contains('@'), "URL has credentials");
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => {
                ensure!(
                    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
                    "URL port is not valid"
                );
                (host, port.parse().context("URL port is not valid")?)
            }
            None => (authority, if https { 443 } else { 80 }),
        };
        ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte)),
            "URL host must be a DNS name or an IPv4 address"
        );
        ensure!(port != 0, "URL port is zero");
        Ok(Self {
            https,
            authority: authority.to_owned(),
            host: host.to_owned(),
            port,
            path: if path.is_empty() {
                "/".to_owned()
            } else if path.starts_with('?') {
                format!("/{path}")
            } else {
                path.to_owned()
            },
        })
    }
}

/// Sends `GET url` over `stream` and returns the body of a `200` response.
///
/// For `https`, TLS runs over `stream`. The server certificate must be valid for the URL host
/// in the Mozilla root store at `now` (Unix seconds). In the enclave, use NSM time.
/// Checks `Content-Length` if present. Transfer encoding is not supported.
pub fn get(url: &Url, stream: impl Read + Write, now: u64) -> Result<Vec<u8>> {
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nAccept: application/json\r\n\r\n",
        url.path, url.authority
    );
    let response = if url.https {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = ClientConfig::builder_with_details(
            Arc::new(rustls::crypto::ring::default_provider()),
            Arc::new(FetchTime(UnixTime::since_unix_epoch(Duration::from_secs(
                now,
            )))),
        )
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

/// Returns the complete body of an HTTP response if its status is `200`.
pub fn body(response: &[u8]) -> Result<Vec<u8>> {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("HTTP response has no end of headers")?;
    let head = std::str::from_utf8(&response[..end]).context("HTTP headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split(' ');
    ensure!(
        matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) && parts.next() == Some("200"),
        "HTTP status is not 200: {status}"
    );
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').context("HTTP header is not valid")?;
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)),
            "HTTP header name is not valid"
        );
        ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "HTTP transfer encoding is not supported"
        );
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(
                content_length.is_none(),
                "HTTP has duplicate Content-Length"
            );
            let value = value.trim();
            ensure!(
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                "HTTP Content-Length is not valid"
            );
            content_length = Some(value.parse::<usize>()?);
        }
    }
    let body = &response[end + 4..];
    ensure!(
        content_length.is_none_or(|length| length == body.len()),
        "HTTP body length does not match Content-Length"
    );
    Ok(body.to_vec())
}

/// Uses the snapshot time for the TLS certificate check.
#[derive(Debug)]
struct FetchTime(UnixTime);

impl TimeProvider for FetchTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.0)
    }
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
        // Some servers omit TLS close_notify. Check Content-Length if present.
        // parse_jwks rejects incomplete JSON. For a valid JWKS, a complete JSON prefix
        // differs only in trailing whitespace.
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.into()),
    }
    ensure!(
        response.len() as u64 <= MAX_RESPONSE_BYTES,
        "HTTP response is too large"
    );
    Ok(response)
}
