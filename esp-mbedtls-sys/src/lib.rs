#![no_std]

pub mod c_types;

#[cfg(not(target_os = "espidf"))]
pub mod bindings {
    include_str!(env!("ESP_MBEDTLS_SYS_BINDINGS"));
}

#[cfg(target_os = "espidf")]
pub mod bindings {
    pub use esp_idf_sys::*;
}
