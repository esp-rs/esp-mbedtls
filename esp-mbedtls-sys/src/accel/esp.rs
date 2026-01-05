//! ESP32XX hardware acceleration modules based on the baremetal `esp-hal` crate.

pub mod digest;
#[cfg(not(feature = "accel-esp32c2"))]
pub mod exp_mod;
