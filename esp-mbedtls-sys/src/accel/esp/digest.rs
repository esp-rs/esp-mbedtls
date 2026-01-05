//! Digest implementations using ESP32 hardware acceleration.

use crate::hook::digest::{MbedtlsSha1, MbedtlsSha256, RustCryptoDigest};

/// SHA-1 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha1 impl that implements the RustCrypto `Digest` trait.
pub type EspSha1 = RustCryptoDigest<esp_hal::sha::Sha1Context>;
/// SHA-224 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha224 impl that implements the RustCrypto `Digest` trait.
#[cfg(not(any(feature = "accel-esp32")))]
pub type EspSha224 = RustCryptoDigest<esp_hal::sha::Sha224Context>;
/// SHA-256 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha256 impl that implements the RustCrypto `Digest` trait.
pub type EspSha256 = RustCryptoDigest<esp_hal::sha::Sha256Context>;
/// SHA-384 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha384 impl that implements the RustCrypto `Digest` trait.
#[cfg(any(
    feature = "accel-esp32",
    feature = "accel-esp32s2",
    feature = "accel-esp32s3"
))]
pub type EspSha384 = RustCryptoDigest<esp_hal::sha::Sha384Context>;
/// SHA-512 digest implementation using ESP32 hardware acceleration.
///
/// Essentially, a specialization of the `RustCryptoDigest` MbedTLS hook
/// for the `esp-hal`-specific hardware accelerated sha512 impl that implements the RustCrypto `Digest` trait.
#[cfg(any(
    feature = "accel-esp32",
    feature = "accel-esp32s2",
    feature = "accel-esp32s3"
))]
pub type EspSha512 = RustCryptoDigest<esp_hal::sha::Sha512Context>;

impl MbedtlsSha1 for EspSha1 {}
#[cfg(not(any(feature = "accel-esp32")))]
impl crate::hook::digest::MbedtlsSha224 for EspSha224 {}
impl MbedtlsSha256 for EspSha256 {}
#[cfg(any(
    feature = "accel-esp32",
    feature = "accel-esp32s2",
    feature = "accel-esp32s3"
))]
impl crate::hook::digest::MbedtlsSha384 for EspSha384 {}
#[cfg(any(
    feature = "accel-esp32",
    feature = "accel-esp32s2",
    feature = "accel-esp32s3"
))]
impl crate::hook::digest::MbedtlsSha512 for EspSha512 {}
