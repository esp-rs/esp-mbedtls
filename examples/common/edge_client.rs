//! Example of an HTTPS client implemented with the `edge-http` crate.
//! Demonstrates the usage of the `edge-nal` `TcpConnect` trait implementation in `mbedtls-rs`.

use core::ffi::CStr;
use core::net::SocketAddr;

use edge_http::io::client::Connection;
use edge_http::Method;

use mbedtls_rs::io::Read;
use mbedtls_rs::nal::{AddrType, Dns, TcpConnect};
use mbedtls_rs::{Tls, TlsConnector};

use log::info;

#[path = "certs.rs"]
mod certs;

pub async fn request<T, D>(
    tls: &Tls<'_>,
    tcp: T,
    dns: D,
    buf: &mut [u8],
    server_name_cstr: &CStr,
    server_path: &str,
    mtls: bool,
) where
    T: TcpConnect,
    D: Dns,
{
    let (response_buf, buf) = buf.split_at_mut(256);

    let server_name = server_name_cstr.to_str().unwrap();

    info!("Resolving server {}", server_name);

    let ip_addr = dns
        .get_host_by_name(server_name, AddrType::IPv4)
        .await
        .unwrap();
    let socket_addr = SocketAddr::new(ip_addr, 443);

    info!("Using socket addr {}", socket_addr);

    let tls_connector = TlsConnector::new(
        tls.reference(),
        tcp,
        &certs::client_conf(mtls, Some(server_name_cstr)),
    );

    info!("Creating HTTPS connection");

    let mut conn = Connection::<_, 32>::new(buf, &tls_connector, socket_addr);

    info!("Requesting GET {} from server", server_path);

    conn.initiate_request(false, Method::Get, server_path, &[("Host", server_name)])
        .await
        .unwrap();

    info!("Request sent, awaiting response");

    conn.initiate_response().await.unwrap();

    info!("Response Headers: {}", conn.headers().unwrap());

    info!("Reading response body\nHTTP RESPONSE START >>>>>>>>");

    loop {
        let len = conn.read(response_buf).await.unwrap();
        if len == 0 {
            break;
        }

        info!(
            "{}",
            core::str::from_utf8(&response_buf[..len]).unwrap_or("???")
        );
    }

    info!("\nHTTP RESPONSE END <<<<<<<<");

    conn.close().await.unwrap();
}
