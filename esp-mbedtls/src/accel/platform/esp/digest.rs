use crate::accel::digest::{
    MbedtlsSha1, MbedtlsSha224, MbedtlsSha256, MbedtlsSha384, MbedtlsSha512, RustCryptoDigest,
};

pub type EspSha1 = RustCryptoDigest<esp_hal::sha::Sha1Context>;
pub type EspSha224 = RustCryptoDigest<esp_hal::sha::Sha224Context>;
pub type EspSha256 = RustCryptoDigest<esp_hal::sha::Sha256Context>;
pub type EspSha384 = RustCryptoDigest<esp_hal::sha::Sha384Context>;
pub type EspSha512 = RustCryptoDigest<esp_hal::sha::Sha512Context>;

impl MbedtlsSha1 for EspSha1 {}
impl MbedtlsSha224 for EspSha224 {}
impl MbedtlsSha256 for EspSha256 {}
impl MbedtlsSha384 for EspSha384 {}
impl MbedtlsSha512 for EspSha512 {}
