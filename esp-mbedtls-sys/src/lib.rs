#![no_std]

pub mod c_types;

pub mod bindings {
    pub use super::bindings0::*;
}

#[cfg(any(target_os = "none", not(target_os = "espidf")))]
#[cfg_attr(all(not(target_os = "none"), not(target_os = "espidf")), path = "include/host.rs")]
#[cfg_attr(all(target_os = "none", feature = "esp32"), path = "include/esp32.rs")]
#[cfg_attr(all(target_os = "none", feature = "esp32c3"), path = "include/esp32c3.rs")]
#[cfg_attr(all(target_os = "none", feature = "esp32s2"), path = "include/esp32s2.rs")]
#[cfg_attr(all(target_os = "none", feature = "esp32s3"), path = "include/esp32s3.rs")]
mod bindings0;

#[cfg(target_os = "espidf")]
mod bindings0 {
    pub use esp_idf_sys::*;
}
