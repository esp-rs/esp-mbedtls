//! Run crypto self tests to ensure their functionality

use std::time::Instant;

use mbedtls_rs::sys::self_test::MbedtlsSelfTest;

use log::{error, info};

fn main() {
    #[cfg(not(target_os = "espidf"))]
    env_logger::init();
    #[cfg(target_os = "espidf")]
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("Running MbedTLS self tests...");

    info!("TESTS OUTPUT >>>>>>>>");

    for mut test in enumset::EnumSet::<MbedtlsSelfTest>::all() {
        info!("Testing {:?}", test);

        let before = Instant::now();

        if !test.run(true) {
            error!("Self-test {:?} failed!", test);
        }

        info!("Took {:?}", before.elapsed());
    }

    run_ecdsa_bench();

    info!("<<<<<<<< TESTS OUTPUT");
    info!("Done");
}

/// The production-shaped ECDSA P-256 benchmark: fresh group per operation,
/// sign and verify timed separately (see `EcdsaP256Bench`).
fn run_ecdsa_bench() {
    use mbedtls_rs::sys::self_test::EcdsaP256Bench;

    const ITERS: u32 = 10;

    use rand::Rng as _;

    let mut rng = |buf: &mut [u8]| rand::rng().fill_bytes(buf);

    let Some(mut bench) = EcdsaP256Bench::new(&mut rng) else {
        error!("ECDSA-P256 bench setup failed!");
        return;
    };

    for (name, mut op) in [
        (
            "sign",
            Box::new(|b: &mut EcdsaP256Bench| b.sign()) as Box<dyn FnMut(&mut _) -> bool>,
        ),
        ("verify", Box::new(|b: &mut EcdsaP256Bench| b.verify())),
    ] {
        let before = Instant::now();

        for _ in 0..ITERS {
            if !op(&mut bench) {
                error!("ECDSA-P256 {name} failed!");
                return;
            }
        }

        info!("ECDSA-P256 {name}: {:?}/op", before.elapsed() / ITERS);
    }
}
