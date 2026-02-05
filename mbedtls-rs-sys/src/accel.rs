//! Hardware acceleration modules for MbedTLS.
//!
//! These modules are platform-specific.

#[cfg(any(
    feature = "accel-esp32",
    feature = "accel-esp32c2",
    feature = "accel-esp32c3",
    feature = "accel-esp32c6",
    feature = "accel-esp32h2",
    feature = "accel-esp32s2",
    feature = "accel-esp32s3",
))]
pub mod esp;
