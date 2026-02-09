//! A platform-agnostic HTTPS 1.0 server using the blocking API.

use mbedtls_rs::blocking::io::{Read, Write};
use mbedtls_rs::blocking::Session;
use mbedtls_rs::{SessionConfig, SessionError, TlsReference};

use log::{info, warn};

#[path = "certs.rs"]
mod certs;

pub fn reply<T>(
    tls: TlsReference<'_>,
    socket: T,
    mtls: bool,
    buf: &mut [u8],
) -> Result<(), SessionError>
where
    T: Read + Write,
{
    info!("Creating TLS session");

    let mut session = Session::new(
        tls,
        socket,
        &SessionConfig::Server(certs::server_conf(mtls)),
    )?;

    info!("Waiting for GET request from client");

    let mut offset = 0;

    let headers_end = loop {
        let len = session.read(&mut buf[offset..])?;
        if len == 0 {
            warn!("Unexpected EOF");
            break None;
        }

        offset += len;

        if let Some(headers_end) = buf[..offset].windows(4).position(|s| s == b"\r\n\r\n") {
            // End of HTTP headers
            break Some(headers_end + 4);
        }
    };

    if let Some(headers_end) = headers_end {
        info!(
            "Replying to request:\n{}",
            core::str::from_utf8(&buf[..headers_end]).unwrap_or("???")
        );

        session.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: Close\r\n\r\nHello from mbedtls-rs!\r\n")?;
    } else {
        info!("No valid HTTP request received");
    }

    session.close()?;

    info!("Done");

    Ok(())
}
