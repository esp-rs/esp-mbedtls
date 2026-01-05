//! SHA-1 digest algorithm hook for mbedtls

use core::ops::Deref;

use super::MbedtlsDigest;

/// Trait representing a custom (hooked) MbedTLS SHA-1 algorithm
pub trait MbedtlsSha1: MbedtlsDigest {}

impl<T: Deref> MbedtlsSha1 for T where T::Target: MbedtlsSha1 {}

/// Hook the SHA-1 algorithm
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use SHA-1, and ensure that the
///   `sha1` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-sha1"))]
pub unsafe fn hook_sha1(sha1: Option<&'static (dyn MbedtlsSha1 + Send + Sync)>) {
    critical_section::with(|cs| {
        alt::SHA1.borrow(cs).set(sha1);
    });
}

#[cfg(not(feature = "nohook-sha1"))]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar};

    use critical_section::Mutex;

    use crate::hook::digest::{
        digest_clone, digest_finish, digest_free, digest_init, digest_starts, digest_update,
        MbedtlsDigest, RustCryptoDigest,
    };
    use crate::hook::WorkArea;
    use crate::mbedtls_sha1_context;

    use super::MbedtlsSha1;

    type RustCryptoSha1 = RustCryptoDigest<sha1::Sha1>;

    impl MbedtlsSha1 for RustCryptoSha1 {}

    pub(crate) static SHA1: Mutex<Cell<Option<&(dyn MbedtlsSha1 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    pub(crate) static SHA1_RUST_CRYPTO: RustCryptoSha1 = RustCryptoSha1::new();

    #[inline(always)]
    fn algo<'a>() -> &'a dyn MbedtlsDigest {
        if let Some(sha1) = critical_section::with(|cs| SHA1.borrow(cs).get()) {
            sha1
        } else {
            &SHA1_RUST_CRYPTO
        }
    }

    impl WorkArea for mbedtls_sha1_context {
        fn area(&self) -> &[u8] {
            &self.work_area
        }

        fn area_mut(&mut self) -> &mut [u8] {
            &mut self.work_area
        }
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_init(ctx: *mut mbedtls_sha1_context) {
        digest_init(algo(), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_free(ctx: *mut mbedtls_sha1_context) {
        digest_free(algo(), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_clone(
        dst: *mut mbedtls_sha1_context,
        src: *const mbedtls_sha1_context,
    ) {
        digest_clone(algo(), src, dst);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_starts(ctx: *mut mbedtls_sha1_context) -> c_int {
        digest_starts(algo(), ctx)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_update(
        ctx: *mut mbedtls_sha1_context,
        input: *const c_uchar,
        ilen: usize,
    ) -> c_int {
        digest_update(algo(), ctx, input, ilen)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha1_finish(
        ctx: *mut mbedtls_sha1_context,
        output: *mut c_uchar,
    ) -> c_int {
        digest_finish(algo(), ctx, output)
    }
}
