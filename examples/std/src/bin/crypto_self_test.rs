//! Run crypto self tests to ensure their functionnality

use std::time::Instant;

use esp_mbedtls::sys::self_test::MbedtlsSelfTest;

use log::{error, info};

fn main() {
    env_logger::init();

    info!("Running MbedTLS self tests...");

    info!("TESTS OUTPUT >>>>>>>>");

    for mut test in enumset::EnumSet::<MbedtlsSelfTest>::all() {
        println!("Testing {:?}", test);

        let before = Instant::now();

        if !test.run(false) {
            error!("Self-test {:?} failed!", test);
        }

        println!("Took {:?}", before.elapsed());
    }

    info!("<<<<<<<< TESTS OUTPUT");
    info!("Done");
}
