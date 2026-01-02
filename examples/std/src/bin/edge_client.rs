//! Example of a client connection to a server, using the `edge-nal` support in `esp-mbedtls`.
//!
//! This example connects to `https://httpbin.org/ip` and then to `https://certauth.cryptomix.com/json/` (mTLS)
//! and performs a simple HTTPS 1.1 GET request to each.

use esp_mbedtls::Tls;

use log::info;

#[path = "../../../common/edge_client.rs"]
mod client;
#[path = "../../../common/std_rng.rs"]
mod rng;

fn main() {
    env_logger::init();

    async_io::block_on(run());
}

async fn run() {
    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    let mut tls = Tls::new(&mut rng).unwrap();

    tls.set_debug(0);

    let stack = edge_nal_std::Stack::new();

    for (index, (server_name_cstr, server_path, mtls)) in [
        (c"httpbin.org", "/ip", false),
        (c"certauth.cryptomix.com", "/json/", true),
    ]
    .into_iter()
    .enumerate()
    {
        info!(
            "\n\n\n\nREQUEST {}, MTLS: {} =============================",
            index, mtls
        );

        client::request(
            &tls,
            stack,
            stack,
            &mut [0; 4096],
            server_name_cstr,
            server_path,
            mtls,
        )
        .await;
    }
}
