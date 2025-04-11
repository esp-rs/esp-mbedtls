//! Run crypto self tests to ensure their functionnality
#![no_std]
#![no_main]

#[doc(hidden)]
pub use esp_hal as hal;

use esp_alloc as _;
use esp_backtrace as _;
use esp_mbedtls::Tls;
use esp_println::{logger::init_logger, println};

/// Only used for ROM functions
#[allow(unused_imports)]
use esp_wifi::init;
use hal::{clock::CpuClock, main, rng::Rng, timer::timg::TimerGroup};

pub fn cycles() -> u64 {
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    {
        esp_hal::xtensa_lx::timer::get_cycle_count() as u64
    }

    #[cfg(not(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3")))]
    {
        use esp_hal::timer::systimer::{SystemTimer, Unit};
        SystemTimer::unit_value(Unit::Unit0)
    }
}

#[main]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    // Init ESP-WIFI heap for malloc
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 115 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let _init = init(
        timg0.timer0,
        Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
    )
    .unwrap();

    let mut tls = Tls::new(peripherals.SHA)
        .unwrap()
        .with_hardware_rsa(peripherals.RSA);

    tls.set_debug(1);

    // | Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |
    // |----------------|-------------------|-------------------|---------------------------|
    // | SHA-1          |      3,390,785    |         896,889   |           3.78            |
    // | SHA-224        |      8,251,799    |         898,344   |           9.19            |
    // | SHA-256        |      8,237,932    |         901,709   |           9.14            |
    // | SHA-384        |     13,605,806    |         799,532   |           17.02           |
    // | SHA-512        |     13,588,104    |         801,556   |           16.95           |

    for test in enumset::EnumSet::all() {
        println!("Testing {:?}", test);

        let before = cycles();

        tls.self_test(test, true);

        let after = cycles();

        println!("Took {:?} cycles", after.checked_sub(before));
    }

    // HW Crypto:
    // Testing RSA
    // INFO -   RSA key validation:
    // INFO - passed
    //   PKCS#1 encryption :
    // INFO - passed
    //   PKCS#1 decryption :
    // INFO - passed
    // INFO -   PKCS#1 data sign  :
    // INFO - passed
    //   PKCS#1 sig. verify:
    // INFO - passed
    // INFO - 10
    // INFO - pre_cal 16377170
    // INFO -   MPI test #1 (mul_mpi):
    // INFO - passed
    // INFO -   MPI test #2 (div_mpi):
    // INFO - passed
    // INFO -   MPI test #3 (exp_mod):
    // INFO - passed
    // INFO -   MPI test #4 (inv_mod):
    // INFO - passed
    // INFO -   MPI test #5 (simple gcd):
    // INFO - passed
    // INFO - 10
    // INFO - post_cal 17338357
    // Took 961187 cycles
    // Done

    // SW Crypto:
    // Testing RSA
    // INFO -   RSA key validation:
    // INFO - passed
    //   PKCS#1 encryption :
    // INFO - passed
    //   PKCS#1 decryption :
    // INFO - passed
    // INFO -   PKCS#1 data sign  :
    // INFO - passed
    //   PKCS#1 sig. verify:
    // INFO - passed
    // INFO - 10
    // INFO - pre_cal 19067376
    // INFO -   MPI test #1 (mul_mpi):
    // INFO - passed
    // INFO -   MPI test #2 (div_mpi):
    // INFO - passed
    // INFO -   MPI test #3 (exp_mod):
    // INFO - passed
    // INFO -   MPI test #4 (inv_mod):
    // INFO - passed
    // INFO -   MPI test #5 (simple gcd):
    // INFO - passed
    // INFO - 10
    // INFO - post_cal 20393146
    // Took 1325770 cycles
    // Done

    println!("Done");

    #[allow(clippy::empty_loop)]
    loop {}
}
