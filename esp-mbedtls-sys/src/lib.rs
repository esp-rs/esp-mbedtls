//! Raw bindings to the MbedTLS library

#![no_std]
#![allow(clippy::uninlined_format_args)]

pub use bindings::*;
pub use error::*;

#[cfg(not(target_os = "espidf"))]
mod c_types;
mod error;
mod extra_impls;

#[allow(clippy::all)]
#[allow(unnecessary_transmutes)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(rustdoc::all)]
#[allow(dead_code)]
mod bindings {
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
    include!("include/esp32c6.rs");

    #[cfg(feature = "esp32s2")]
    include!("include/esp32s2.rs");

    #[cfg(feature = "esp32s3")]
    include!("include/esp32s3.rs");

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
