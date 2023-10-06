//! Run crypto self tests to ensure their functionnality
#![no_std]
#![no_main]

#[doc(hidden)]
#[cfg(feature = "esp32")]
pub use esp32_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32c3")]
pub use esp32c3_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s2")]
pub use esp32s2_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s3")]
pub use esp32s3_hal as hal;

use esp_backtrace as _;
use esp_mbedtls::set_debug;
use esp_println::{logger::init_logger, println};

/// Only used for ROM functions
#[allow(unused_imports)]
use esp_wifi::{initialize, EspWifiInitFor};
use hal::{clock::ClockControl, peripherals::Peripherals, prelude::*, Rng};

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    // Init ESP-WIFI heap for malloc
    let peripherals = Peripherals::take();
    #[cfg(feature = "esp32")]
    let mut system = peripherals.DPORT.split();
    #[cfg(not(feature = "esp32"))]
    #[allow(unused_mut)]
    let mut system = peripherals.SYSTEM.split();
    let clocks = ClockControl::max(system.clock_control).freeze();

    #[cfg(feature = "esp32c3")]
    let timer = hal::systimer::SystemTimer::new(peripherals.SYSTIMER).alarm0;
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    let timer = hal::timer::TimerGroup::new(peripherals.TIMG1, &clocks).timer0;
    let _ = initialize(
        EspWifiInitFor::Wifi,
        timer,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    set_debug(0);

    // println!("Testing AES");
    // unsafe {
    //     esp_mbedtls::mbedtls_aes_self_test(1i32);
    // }
    // println!("Testing MD5");
    // unsafe {
    //     esp_mbedtls::mbedtls_md5_self_test(1i32);
    // }
    // println!("Testing RSA");
    // unsafe {
    //     esp_mbedtls::mbedtls_rsa_self_test(1i32);
    // }
    println!("Testing SHA");
    unsafe {
        // esp_mbedtls::mbedtls_sha1_self_test(1i32);
        #[cfg(not(feature = "esp32"))]
        esp_mbedtls::mbedtls_sha224_self_test(1i32);
        esp_mbedtls::mbedtls_sha256_self_test(1i32);
        // esp_mbedtls::mbedtls_sha384_self_test(1i32);
        esp_mbedtls::mbedtls_sha512_self_test(1i32);
    }

    println!("Done");

    loop {}
}
