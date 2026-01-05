//! Run crypto self tests to ensure their functionnality

use std::time::Instant;

use esp_mbedtls::sys::self_test::MbedtlsSelfTest;

use log::info;

fn main() {
    env_logger::init();

    info!("Running MbedTLS self tests...");

    info!("TESTS OUTPUT >>>>>>>>");

    for mut test in enumset::EnumSet::<MbedtlsSelfTest>::all() {
        println!("Testing {:?}", test);

        let before = Instant::now();

        test.run(false);

        println!("Took {:?}", before.elapsed());
    }

    info!("<<<<<<<< TESTS OUTPUT");
    info!("Done");
}
