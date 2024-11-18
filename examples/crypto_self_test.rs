//! Run crypto self tests to ensure their functionnality
#![no_std]
#![no_main]

#[doc(hidden)]
pub use esp_hal as hal;

use esp_alloc as _;
use esp_backtrace as _;
use esp_mbedtls::{set_debug, Tls};
use esp_println::{logger::init_logger, println};

/// Only used for ROM functions
#[allow(unused_imports)]
use esp_wifi::{init, EspWifiInitFor};
use hal::{prelude::*, rng::Rng, timer::timg::TimerGroup};

use log::warn;

pub fn cycles() -> u64 {
    #[cfg(feature = "esp32")]
    {
        esp_hal::xtensa_lx::timer::get_cycle_count() as u64
    }

    #[cfg(not(feature = "esp32"))]
    {
        esp_hal::timer::systimer::SystemTimer::now()
    }
}

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    // Init ESP-WIFI heap for malloc
    let peripherals = esp_hal::init({
        let mut config = esp_hal::Config::default();
        config.cpu_clock = CpuClock::max();
        config
    });

    esp_alloc::heap_allocator!(115 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let _init = init(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
    )
    .unwrap();

    let _tls = Tls::new()
        .with_hardware_sha(peripherals.SHA)
        .with_hardware_rsa(peripherals.RSA);

    set_debug(1);

    // println!("Testing AES");
    // unsafe {
    //     esp_mbedtls::mbedtls_aes_self_test(1i32);
    // }
    // println!("Testing MD5");
    // unsafe {
    //     esp_mbedtls::mbedtls_md5_self_test(1i32);
    // }
    println!("Testing RSA");
    unsafe {
        esp_mbedtls::mbedtls_rsa_self_test(1i32);
    }
    println!("Testing SHA");

    // | Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |
    // |----------------|-------------------|-------------------|---------------------------|
    // | SHA-1          |      3,390,785    |         896,889   |           3.78            |
    // | SHA-224        |      8,251,799    |         898,344   |           9.19            |
    // | SHA-256        |      8,237,932    |         901,709   |           9.14            |
    // | SHA-384        |     13,605,806    |         799,532   |           17.02           |
    // | SHA-512        |     13,588,104    |         801,556   |           16.95           |

    unsafe {
        let before = cycles();
        esp_mbedtls::mbedtls_sha1_self_test(1i32);
        let after = cycles();
        warn!("SHA 1 took {} cycles", after - before);
        #[cfg(not(feature = "esp32"))]
        let before = cycles();
        esp_mbedtls::mbedtls_sha224_self_test(1i32);
        let after = cycles();
        warn!("SHA 224 took {} cycles", after - before);
        let before = cycles();
        esp_mbedtls::mbedtls_sha256_self_test(1i32);
        let after = cycles();
        warn!("SHA 256 took {} cycles", after - before);
        let before = cycles();
        esp_mbedtls::mbedtls_sha384_self_test(1i32);
        let after = cycles();
        warn!("SHA 384 took {} cycles", after - before);
        let before = cycles();
        esp_mbedtls::mbedtls_sha512_self_test(1i32);
        let after = cycles();
        warn!("SHA 512 took {} cycles", after - before);

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

        // esp_mbedtls::mbedtls_mpi_self_test(1i32);
    }

    println!("Done");

    loop {}
}
