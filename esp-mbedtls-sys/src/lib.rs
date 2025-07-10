#![no_std]

// For `malloc`, `calloc` and `free` which are provided by `esp-wifi` on baremetal
#[cfg(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32s2",
    feature = "esp32s3"
))]
use esp_wifi as _;

#[cfg(not(target_os = "espidf"))]
mod c_types;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
pub mod bindings {
    #[cfg(all(
        not(target_os = "espidf"),
        not(any(
            feature = "esp32",
            feature = "esp32c3",
            feature = "esp32c6",
            feature = "esp32s2",
            feature = "esp32s3"
        ))
    ))]
    include!(env!("ESP_MBEDTLS_SYS_GENERATED_BINDINGS_FILE"));

    // This and below are necessary because of https://github.com/rust-lang/cargo/issues/10358
    #[cfg(feature = "esp32")]
    include!("include/esp32.rs");

    #[cfg(feature = "esp32c3")]
    include!("include/esp32c3.rs");

    #[cfg(feature = "esp32c6")]
    include!("include/esp32c3.rs");

    #[cfg(feature = "esp32s2")]
    include!("include/esp32s2.rs");

    #[cfg(feature = "esp32s3")]
    include!("include/esp32s3.rs");

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
