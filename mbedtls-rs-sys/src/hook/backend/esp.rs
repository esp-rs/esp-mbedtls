//! ESP32XX hardware acceleration modules based on the baremetal `esp-hal` crate.

#[cfg(not(feature = "esp32c2"))]
pub mod aes;
pub mod digest;
#[cfg(all(
    any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ),
    feature = "alg-ecp"
))]
pub mod ecc;
#[cfg(not(any(feature = "esp32c2", feature = "nohook-exp-mod")))]
pub mod exp_mod;
// esp32c5: LP_TIMER driver not yet wired in esp-hal v1.1, so `Rtc::current_time_us`
// and `Rtc::set_current_time_us` are unavailable. Re-enable once esp-hal lands the
// c5 LP_TIMER driver.
#[cfg(all(feature = "hook-wall-clock", not(feature = "esp32c5")))]
pub mod wall_clock;

#[cfg(not(feature = "esp32"))]
pub static SHA1: digest::EspSha1 = digest::EspSha1::new();
#[cfg(not(feature = "esp32"))]
pub static SHA224: digest::EspSha224 = digest::EspSha224::new();
#[cfg(not(feature = "esp32"))]
pub static SHA256: digest::EspSha256 = digest::EspSha256::new();
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub static SHA384: digest::EspSha384 = digest::EspSha384::new();
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
pub static SHA512: digest::EspSha512 = digest::EspSha512::new();
#[cfg(not(any(feature = "esp32c2", feature = "nohook-exp-mod")))]
pub static EXP_MOD: exp_mod::EspExpMod = exp_mod::EspExpMod::new();
#[cfg(not(feature = "esp32c2"))]
pub static AES: aes::EspAes = aes::EspAes::new();
#[cfg(all(
    any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ),
    feature = "alg-ecp"
))]
pub static ECC: ecc::EspEcc = ecc::EspEcc::new();

/// Marker cfg helpers (keep the per-chip peripheral sets in one place):
///
/// | Chip     | SHA | RSA | AES | ECC |
/// |----------|-----|-----|-----|-----|
/// | esp32    |  -  |  x  |  x  |  -  |
/// | esp32s2  |  x  |  x  |  x  |  -  |
/// | esp32s3  |  x  |  x  |  x  |  -  |
/// | esp32c2  |  x  |  -  |  -  |  x  |
/// | esp32c3  |  x  |  x  |  x  |  -  |
/// | esp32c5  |  x  |  x  |  x  |  x  |
/// | esp32c6  |  x  |  x  |  x  |  x  |
/// | esp32h2  |  x  |  x  |  x  |  x  |
///
/// (SHA is present on the esp32 too, but its peripheral is not supported by
/// the `esp-hal` SHA work-queue backend.)
pub struct EspAccel<'d> {
    #[cfg(not(feature = "esp32"))]
    sha: esp_hal::sha::ShaBackend<'d>,
    #[cfg(not(feature = "esp32c2"))]
    rsa: esp_hal::rsa::RsaBackend<'d>,
    #[cfg(not(feature = "esp32c2"))]
    aes: esp_hal::aes::AesBackend<'d>,
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    ecc: esp_hal::ecc::EccBackend<'d>,
}

impl<'d> EspAccel<'d> {
    /// Create a new `EspAccel` instance (ESP32-C5/C6/H2 variant)
    #[cfg(any(feature = "esp32c5", feature = "esp32c6", feature = "esp32h2"))]
    pub fn new(
        sha: esp_hal::peripherals::SHA<'d>,
        rsa: esp_hal::peripherals::RSA<'d>,
        aes: esp_hal::peripherals::AES<'d>,
        ecc: esp_hal::peripherals::ECC<'d>,
    ) -> Self {
        Self {
            sha: esp_hal::sha::ShaBackend::new(sha),
            rsa: esp_hal::rsa::RsaBackend::new(rsa),
            aes: esp_hal::aes::AesBackend::new(aes),
            ecc: esp_hal::ecc::EccBackend::new(ecc, esp_hal::ecc::Config::default()),
        }
    }

    /// Create a new `EspAccel` instance (ESP32-S2/S3/C3 variant)
    #[cfg(any(feature = "esp32s2", feature = "esp32s3", feature = "esp32c3"))]
    pub fn new(
        sha: esp_hal::peripherals::SHA<'d>,
        rsa: esp_hal::peripherals::RSA<'d>,
        aes: esp_hal::peripherals::AES<'d>,
    ) -> Self {
        Self {
            sha: esp_hal::sha::ShaBackend::new(sha),
            rsa: esp_hal::rsa::RsaBackend::new(rsa),
            aes: esp_hal::aes::AesBackend::new(aes),
        }
    }

    /// Create a new `EspAccel` instance (ESP32 variant)
    #[cfg(feature = "esp32")]
    pub fn new(rsa: esp_hal::peripherals::RSA<'d>, aes: esp_hal::peripherals::AES<'d>) -> Self {
        Self {
            rsa: esp_hal::rsa::RsaBackend::new(rsa),
            aes: esp_hal::aes::AesBackend::new(aes),
        }
    }

    /// Create a new `EspAccel` instance (ESP32-C2 variant)
    #[cfg(feature = "esp32c2")]
    pub fn new(sha: esp_hal::peripherals::SHA<'d>, ecc: esp_hal::peripherals::ECC<'d>) -> Self {
        Self {
            sha: esp_hal::sha::ShaBackend::new(sha),
            ecc: esp_hal::ecc::EccBackend::new(ecc, esp_hal::ecc::Config::default()),
        }
    }

    #[must_use]
    pub fn start(&mut self) -> EspAccelQueue<'_, 'd> {
        EspAccelQueue::new(self)
    }
}

pub struct EspAccelQueue<'a, 'd> {
    #[cfg(not(feature = "esp32"))]
    _sha_queue: esp_hal::sha::ShaWorkQueueDriver<'a, 'd>,
    #[cfg(not(feature = "esp32c2"))]
    _rsa_queue: esp_hal::rsa::RsaWorkQueueDriver<'a, 'd>,
    #[cfg(not(feature = "esp32c2"))]
    _aes_queue: esp_hal::aes::AesWorkQueueDriver<'a, 'd>,
    #[cfg(any(
        feature = "esp32c2",
        feature = "esp32c5",
        feature = "esp32c6",
        feature = "esp32h2"
    ))]
    _ecc_queue: esp_hal::ecc::EccWorkQueueDriver<'a, 'd>,
}

impl<'a, 'd> EspAccelQueue<'a, 'd> {
    fn new(accel: &'a mut EspAccel<'d>) -> Self {
        #[cfg(not(feature = "esp32"))]
        let sha_queue = accel.sha.start();
        #[cfg(not(feature = "esp32c2"))]
        let rsa_queue = accel.rsa.start();
        #[cfg(not(feature = "esp32c2"))]
        let aes_queue = accel.aes.start();
        #[cfg(any(
            feature = "esp32c2",
            feature = "esp32c5",
            feature = "esp32c6",
            feature = "esp32h2"
        ))]
        let ecc_queue = accel.ecc.start();

        #[cfg(not(any(feature = "esp32", feature = "nohook-sha1")))]
        unsafe {
            crate::hook::digest::hook_sha1(Some(&SHA1));
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha224(Some(&SHA224));
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha256(Some(&SHA256));
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha384(Some(&SHA384));
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha512(Some(&SHA512));
        }
        #[cfg(all(not(feature = "esp32c2"), not(feature = "nohook-exp-mod")))]
        unsafe {
            crate::hook::exp_mod::hook_exp_mod(Some(&EXP_MOD));
        }
        #[cfg(all(
            not(feature = "esp32c2"),
            feature = "alg-aes",
            not(feature = "nohook-aes")
        ))]
        unsafe {
            crate::hook::aes::hook_aes(Some(&AES));
        }
        #[cfg(all(
            any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ),
            feature = "alg-ecp",
            not(feature = "nohook-ecp-mul")
        ))]
        unsafe {
            crate::hook::ecp::hook_ecp_mul(Some(&ECC));
        }
        #[cfg(all(
            any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ),
            feature = "alg-ecp",
            not(feature = "nohook-ecp-verify")
        ))]
        unsafe {
            crate::hook::ecp::hook_ecp_verify(Some(&ECC));
        }

        Self {
            #[cfg(not(feature = "esp32"))]
            _sha_queue: sha_queue,
            #[cfg(not(feature = "esp32c2"))]
            _rsa_queue: rsa_queue,
            #[cfg(not(feature = "esp32c2"))]
            _aes_queue: aes_queue,
            #[cfg(any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ))]
            _ecc_queue: ecc_queue,
        }
    }
}

impl Drop for EspAccelQueue<'_, '_> {
    fn drop(&mut self) {
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha1")))]
        unsafe {
            crate::hook::digest::hook_sha1(None);
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha224(None);
        }
        #[cfg(not(any(feature = "esp32", feature = "nohook-sha256")))]
        unsafe {
            crate::hook::digest::hook_sha256(None);
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha384(None);
        }
        #[cfg(all(
            any(feature = "esp32s2", feature = "esp32s3"),
            not(feature = "nohook-sha512")
        ))]
        unsafe {
            crate::hook::digest::hook_sha512(None);
        }
        #[cfg(all(not(feature = "esp32c2"), not(feature = "nohook-exp-mod")))]
        unsafe {
            crate::hook::exp_mod::hook_exp_mod(None);
        }
        #[cfg(all(
            not(feature = "esp32c2"),
            feature = "alg-aes",
            not(feature = "nohook-aes")
        ))]
        unsafe {
            crate::hook::aes::hook_aes(None);
        }
        #[cfg(all(
            any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ),
            feature = "alg-ecp",
            not(feature = "nohook-ecp-mul")
        ))]
        unsafe {
            crate::hook::ecp::hook_ecp_mul(None);
        }
        #[cfg(all(
            any(
                feature = "esp32c2",
                feature = "esp32c5",
                feature = "esp32c6",
                feature = "esp32h2"
            ),
            feature = "alg-ecp",
            not(feature = "nohook-ecp-verify")
        ))]
        unsafe {
            crate::hook::ecp::hook_ecp_verify(None);
        }
    }
}
