use core::ops::Deref;

use super::MbedtlsDigest;

/// Trait representing a custom (hooked) MbedTLS SHA-512 algorithm
pub trait MbedtlsSha512: MbedtlsDigest {}
/// Trait representing a custom (hooked) MbedTLS SHA-384 algorithm
pub trait MbedtlsSha384: MbedtlsDigest {}

impl<T: Deref> MbedtlsSha512 for T where T::Target: MbedtlsSha512 {}
impl<T: Deref> MbedtlsSha384 for T where T::Target: MbedtlsSha384 {}

/// Hook the SHA512 implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use SHA-512 or SHA-384, and ensure that the
///   `sha512` or `sha384` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-sha512"))]
pub unsafe fn hook_sha512(sha512: Option<&'static (dyn MbedtlsSha512 + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if sha512.is_some() {
            debug!("SHA-512 hook: added custom/HW accelerated impl");
        } else {
            debug!("SHA-512 hook: removed");
        }

        alt::SHA512.borrow(cs).set(sha512);
    });
}

/// Hook the SHA384 implementation used by MbedTLS
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use SHA-384, and ensure that the
///   `sha384` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-sha512"))]
pub unsafe fn hook_sha384(sha384: Option<&'static (dyn MbedtlsSha384 + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if sha384.is_some() {
            debug!("SHA-384 hook: added custom/HW accelerated impl");
        } else {
            debug!("SHA-384 hook: removed");
        }

        alt::SHA384.borrow(cs).set(sha384);
    });
}

#[cfg(not(feature = "nohook-sha512"))]
mod alt {
    use core::cell::Cell;
    use core::ffi::{c_int, c_uchar};

    use critical_section::Mutex;

    use crate::hook::digest::{
        digest_clone, digest_finish, digest_free, digest_init, digest_starts, digest_update,
        MbedtlsDigest, RustCryptoDigest,
    };
    use crate::hook::{RawWorkArea, WorkAreaMemory};
    use crate::mbedtls_sha512_context;

    use super::{MbedtlsSha384, MbedtlsSha512};

    type RustCryptoSha512 = RustCryptoDigest<sha2::Sha512>;
    type RustCryptoSha384 = RustCryptoDigest<sha2::Sha384>;

    impl MbedtlsSha512 for RustCryptoSha512 {}
    impl MbedtlsSha384 for RustCryptoSha384 {}

    // The work area must be able to host the fallback's state at *any* runtime
    // offset (up to 15 bytes of emplacement waste at under-aligned opaque storage — see `sha256.rs` for the
    // full rationale).
    const _: () = assert!(
        core::mem::size_of::<Option<sha2::Sha512>>() + 16
            <= crate::MBEDTLS_SHA512_ALT_WORK_AREA_SIZE as usize,
        "The RustCrypto SHA-512 state does not fit the SHA-512 hook work area"
    );
    const _: () = assert!(
        core::mem::size_of::<Option<sha2::Sha384>>() + 16
            <= crate::MBEDTLS_SHA512_ALT_WORK_AREA_SIZE as usize,
        "The RustCrypto SHA-384 state does not fit the SHA-512 hook work area"
    );

    pub(crate) static SHA512: Mutex<Cell<Option<&(dyn MbedtlsSha512 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA512_RUST_CRYPTO: RustCryptoSha512 = RustCryptoSha512::new();

    pub(crate) static SHA384: Mutex<Cell<Option<&(dyn MbedtlsSha384 + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    static SHA384_RUST_CRYPTO: RustCryptoSha384 = RustCryptoSha384::new();

    /// Read `is384` via raw field projection — `ctx` may be under-aligned
    /// (see `RawWorkArea`), so no reference to the struct may be formed; the
    /// `u8` field itself is loadable at any address.
    #[inline(always)]
    fn is384(ctx: *const mbedtls_sha512_context) -> u8 {
        unsafe { core::ptr::addr_of!((*ctx).is384).read() }
    }

    #[inline(always)]
    fn set_is384(ctx: *mut mbedtls_sha512_context, value: u8) {
        unsafe { core::ptr::addr_of_mut!((*ctx).is384).write(value) }
    }

    #[inline(always)]
    fn algo<'a>(ctx: *const mbedtls_sha512_context) -> &'a dyn MbedtlsDigest {
        if is384(ctx) != 0 {
            if let Some(sha) = critical_section::with(|cs| SHA384.borrow(cs).get()) {
                sha
            } else {
                &SHA384_RUST_CRYPTO
            }
        } else if let Some(sha) = critical_section::with(|cs| SHA512.borrow(cs).get()) {
            sha
        } else {
            &SHA512_RUST_CRYPTO
        }
    }

    impl RawWorkArea for mbedtls_sha512_context {
        unsafe fn work_area<'a>(ctx: *const Self) -> &'a WorkAreaMemory {
            unsafe { &*core::ptr::addr_of!((*ctx).work_area) }
        }

        unsafe fn work_area_mut<'a>(ctx: *mut Self) -> &'a mut WorkAreaMemory {
            unsafe { &mut *core::ptr::addr_of_mut!((*ctx).work_area) }
        }
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha512_init(ctx: *mut mbedtls_sha512_context) {
        set_is384(ctx, 0);

        digest_init(algo(ctx), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha512_free(ctx: *mut mbedtls_sha512_context) {
        // MbedTLS contract: `mbedtls_sha512_free(NULL)` is documented as valid
        // (see `digest_free` in `mbedtls-rs-sys/src/hook/digest.rs` for the
        // full call-path rationale). Null-check before `algo(ctx)` because that
        // helper dereferences `ctx` to read `is384`.
        if ctx.is_null() {
            return;
        }
        digest_free(algo(ctx), ctx);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha512_clone(
        dst: *mut mbedtls_sha512_context,
        src: *const mbedtls_sha512_context,
    ) {
        if is384(src) != is384(dst) {
            digest_free(algo(dst), dst);

            set_is384(dst, is384(src));
            digest_init(algo(dst), dst);
        }

        digest_clone(algo(src), src, dst);
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha512_starts(
        ctx: *mut mbedtls_sha512_context,
        is384: c_int,
    ) -> c_int {
        if is384 != self::is384(ctx) as _ {
            digest_free(algo(ctx), ctx);

            set_is384(ctx, is384 as _);
            digest_init(algo(ctx), ctx);
        }

        digest_starts(algo(ctx), ctx)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha512_update(
        ctx: *mut mbedtls_sha512_context,
        input: *const c_uchar,
        ilen: usize,
    ) -> c_int {
        digest_update(algo(ctx), ctx, input, ilen)
    }

    #[no_mangle]
    unsafe extern "C" fn mbedtls_sha512_finish(
        ctx: *mut mbedtls_sha512_context,
        output: *mut c_uchar,
    ) -> c_int {
        digest_finish(algo(ctx), ctx, output)
    }
}
