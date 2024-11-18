#![no_std]

#[cfg(not(target_os = "espidf"))]
mod c_types;

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
pub mod bindings {
    #[cfg(not(target_os = "espidf"))]
    include!(env!("ESP_MBEDTLS_SYS_GENERATED_BINDINGS_FILE"));

    #[cfg(target_os = "espidf")]
    pub use esp_idf_sys::*;
}
