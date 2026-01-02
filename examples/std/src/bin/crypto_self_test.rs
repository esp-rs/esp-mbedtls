//! Run crypto self tests to ensure their functionnality

use std::time::Instant;

use esp_mbedtls::Tls;

use log::info;

#[path = "../../../common/std_rng.rs"]
mod rng;

fn main() {
    env_logger::init();

    info!("Initializing TLS");

    let mut rng = rng::StdRng;
    let mut tls = Tls::new(&mut rng).unwrap();

    tls.set_debug(1);

    info!("Running TLS crypto self tests...");

    info!("TESTS OUTPUT >>>>>>>>");

    for test in enumset::EnumSet::all() {
        println!("Testing {:?}", test);

        let before = Instant::now();

        tls.self_test(test, true);

        println!("Took {:?}", before.elapsed());
    }

    info!("<<<<<<<< TESTS OUTPUT");
    info!("Done");
}
