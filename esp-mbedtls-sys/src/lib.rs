//! Raw bindings to the MbedTLS library

#![no_std]
#![allow(clippy::uninlined_format_args)]
#![allow(unknown_lints)]

pub use bindings::*;
pub use error::*;

pub(crate) mod fmt;

mod error;
#[cfg(not(target_os = "espidf"))]
mod extra_impls; // TODO: Figure out if we still need this

#[cfg(not(target_os = "espidf"))]
pub mod accel;
#[cfg(not(target_os = "espidf"))]
pub mod hook;
pub mod self_test;
#[cfg(all(feature = "time", not(target_os = "espidf")))]
pub mod time;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unnecessary_transmutes,
    clippy::all
)]
mod bindings {
    #[cfg(not(target_os = "espidf"))]
    include!(env!("ESP_MBEDTLS_SYS_BINDINGS_FILE"));

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
