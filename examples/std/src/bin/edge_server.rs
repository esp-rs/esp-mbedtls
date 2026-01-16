//! Example of an HTTPS server, using the `edge-nal` support in `esp-mbedtls`.
//!
//! This example runs a simple HTTPS server that answers with a fixed text message to all HTTP GET / requests.
//!
//! Since the server certificates are self-signed, the easiest way to test is with:
//! ```sh
//! curl -k https://localhost:8443/
//! ```
//!
//! Alternatively, accept the self-signed certificate warning in the browser.

use edge_http::io::server::Server;

use esp_mbedtls::Tls;

use log::info;

#[path = "../bootstrap.rs"]
mod bootstrap;
#[path = "../../../common/std_rng.rs"]
mod rng;
#[path = "../../../common/edge_server.rs"]
mod server;

type DemoServer = Server<2, 2048, 20>;

fn main() {
    bootstrap::bootstrap();

    let mut server = Box::new(DemoServer::new());

    bootstrap::block_on(Box::pin(run(&mut server)));
}

async fn run(server: &mut DemoServer) {
    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    let mut tls = Tls::new(&mut rng).unwrap();

    tls.set_debug(1);

    server::run(&tls, edge_nal_std::Stack::new(), server, 8443).await;
}
