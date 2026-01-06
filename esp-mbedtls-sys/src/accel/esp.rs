//! ESP32XX hardware acceleration modules based on the baremetal `esp-hal` crate.

pub mod digest;
#[cfg(not(any(feature = "accel-esp32c2", feature = "nohook-exp-mod")))]
pub mod exp_mod;
