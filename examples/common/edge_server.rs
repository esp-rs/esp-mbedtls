//! Example of an HTTPS server implemented with the `edge-http` crate.
//! Demonstrates the usage of the `edge-nal` `TcpAccept` trait implementation in `esp-mbedtls`.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use edge_http::io::server::{Connection, Handler, Server};
use edge_http::io::Error;
use edge_http::Method;

use esp_mbedtls::io::{Read, Write};
use esp_mbedtls::nal::{TcpBind, WithTimeout};
use esp_mbedtls::{Tls, TlsAcceptor};

#[path = "certs.rs"]
mod certs;

pub async fn run<const HANDLERS: usize, const BUF: usize, const HEADERS: usize, T>(
    tls: &Tls<'_>,
    tcp: T,
    server: &mut Server<HANDLERS, BUF, HEADERS>,
) where
    T: TcpBind,
{
    // First, create a raw TCP acceptor on port 8443
    let tcp_acceptor = tcp
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443))
        .await
        .unwrap();

    // Next, layer the esp-mbedtls TLS stack on top of it
    let tls_acceptor = TlsAcceptor::new(tls.reference(), tcp_acceptor, &certs::server_conf(false));

    // Finally, run the HTTP server on top of the TLS acceptor
    server
        .run(
            Some(15 * 1000),
            WithTimeout::new(15_000, tls_acceptor),
            HttpHandler,
        )
        .await
        .unwrap();
}

struct HttpHandler;

impl Handler for HttpHandler {
    type Error<E>
        = Error<E>
    where
        E: core::fmt::Debug;

    async fn handle<T, const N: usize>(
        &self,
        _task_id: impl core::fmt::Display + Copy,
        connection: &mut Connection<'_, T, N>,
    ) -> Result<(), Self::Error<T::Error>>
    where
        T: Read + Write,
    {
        println!("Got new connection");
        let headers = connection.headers()?;

        if headers.method != Method::Get {
            connection
                .initiate_response(405, Some("Method Not Allowed"), &[])
                .await?;
        } else if headers.path != "/" {
            connection
                .initiate_response(404, Some("Not Found"), &[])
                .await?;
        } else {
            connection
                .initiate_response(200, Some("OK"), &[("Content-Type", "text/plain")])
                .await?;

            connection
                .write_all(b"Hello from esp-mbedtls, edge-http and edge-nal!")
                .await?;
        }

        Ok(())
    }
}
