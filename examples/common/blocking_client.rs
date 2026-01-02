//! A platform-agnostic HTTPS 1.0 request-response client using the blocking API.

use core::ffi::CStr;

use esp_mbedtls::blocking::io::{Read, Write};
use esp_mbedtls::blocking::Session;
use esp_mbedtls::{SessionConfig, TlsError, TlsReference};

use log::info;

#[path = "certs.rs"]
mod certs;

/// Perform a simple HTTPS 1.0 GET request and print the response to the log.
///
/// # Arguments:
/// - `tls`: A reference to the TLS context.
/// - `socket`: The underlying socket implementing `Read` and `Write`.
/// - `server_name_cstr`: The server name as a C string.
/// - `server_path`: The path to request from the server.
/// - `mtls`: Whether to use mutual TLS authentication.
/// - `buf`: A buffer to read the response into.
pub fn request<T>(
    tls: TlsReference<'_>,
    socket: T,
    server_name_cstr: &CStr,
    server_path: &str,
    mtls: bool,
    buf: &mut [u8],
) -> Result<(), TlsError>
where
    T: Read + Write,
{
    let server_name = server_name_cstr.to_str().unwrap();

    info!("Creating TLS session");

    let mut session = Session::new(
        tls,
        socket,
        &SessionConfig::Client(certs::client_conf(mtls, Some(server_name_cstr))),
    )?;

    info!("Requesting GET {} from server", server_path);

    session.write_all(b"GET ")?;
    session.write_all(server_path.as_bytes())?;
    session.write_all(b" HTTP/1.0\r\nHost: ")?;
    session.write_all(server_name.as_bytes())?;
    session.write_all(b"\r\n\r\n")?;

    info!("Reading response\nHTTP RESPONSE START >>>>>>>>");

    loop {
        let len = session.read(buf)?;
        if len == 0 {
            break;
        }

        info!("{}", core::str::from_utf8(&buf[..len]).unwrap_or("???"));
    }

    info!("\nHTTP RESPONSE END <<<<<<<<");

    session.close()?;

    info!("Done");

    Ok(())
}
