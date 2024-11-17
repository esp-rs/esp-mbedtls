#[doc(hidden)]
pub use esp_hal as hal;
use hal::{
    peripheral::Peripheral,
    peripherals::{RSA, SHA},
    rsa::Rsa,
    sha::Sha,
};

use core::cell::RefCell;
use core::ffi::CStr;
use core::mem::size_of;
use critical_section::Mutex;

#[cfg(all(target_os = "none", any(feature = "esp32c3", feature = "esp32s2", feature = "esp32s3")))]
mod bignum;
#[cfg(all(target_os = "none", not(feature = "esp32")))]
mod sha;

/// Hold the RSA peripheral for cryptographic operations.
///
/// This is initialized when `with_hardware_rsa()` is called on a [Session] and is set back to None
/// when the session that called `with_hardware_rsa()` is dropped.
///
/// Note: Due to implementation constraints, this session and every other session will use the
/// hardware accelerated RSA driver until the session called with this function is dropped.
static mut RSA_REF: Option<Rsa<esp_hal::Blocking>> = None;

/// Hold the SHA peripheral for cryptographic operations.
static SHARED_SHA: Mutex<RefCell<Option<Sha<'static>>>> = Mutex::new(RefCell::new(None));

impl<'d> Crypto<'d> {
    pub fn with_hardware_sha(self, sha: impl Peripheral<P = SHA> + 'd) -> Self {
        critical_section::with(|cs| {
            SHARED_SHA
                .borrow_ref_mut(cs)
                .replace(unsafe { core::mem::transmute(Sha::new(sha)) })
        });

        self
    }

    /// Enable the use of the hardware accelerated RSA peripheral for the [Session].
    ///
    /// Note: Due to implementation constraints, this session and every other session will use the
    /// hardware accelerated RSA driver until the session called with this function is dropped.
    ///
    /// # Arguments
    ///
    /// * `rsa` - The RSA peripheral from the HAL
    pub fn with_hardware_rsa(mut self, rsa: impl Peripheral<P = RSA> + 'd) -> Self {
        unsafe { RSA_REF = core::mem::transmute(Some(Rsa::new(rsa))) }
        self
    }
}

impl Drop for Crypto {
    fn drop(&mut self) {
        RSA_REF = core::mem::transmute(None::<RSA>);
        critical_section::with(|cs| SHARED_SHA.borrow_ref_mut(cs).take());
    }
}
