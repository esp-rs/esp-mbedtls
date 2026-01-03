use core::cell::Cell;
use core::ffi::{c_int, c_uchar};
use core::ops::Deref;

use critical_section::Mutex;

use esp_mbedtls_sys::mbedtls_sha512_context;

use crate::accel::{digest::RustCryptoDigest, WorkArea};

use super::{
    digest_clone, digest_finish, digest_free, digest_init, digest_starts, digest_update,
    MbedtlsDigest,
};

pub trait MbedtlsSha512: MbedtlsDigest {}
pub trait MbedtlsSha384: MbedtlsDigest {}

impl<T: Deref> MbedtlsSha512 for T where T::Target: MbedtlsSha512 {}
impl<T: Deref> MbedtlsSha384 for T where T::Target: MbedtlsSha384 {}

type RustCryptoSha512 = RustCryptoDigest<sha2::Sha512>;
type RustCryptoSha384 = RustCryptoDigest<sha2::Sha384>;

impl MbedtlsSha512 for RustCryptoSha512 {}
impl MbedtlsSha384 for RustCryptoSha384 {}

pub(crate) static SHA512: Mutex<Cell<Option<&(dyn MbedtlsSha512 + Send + Sync)>>> =
    Mutex::new(Cell::new(None));
static SHA512_RUST_CRYPTO: RustCryptoSha512 = RustCryptoSha512::new();

pub(crate) static SHA384: Mutex<Cell<Option<&(dyn MbedtlsSha384 + Send + Sync)>>> =
    Mutex::new(Cell::new(None));
static SHA384_RUST_CRYPTO: RustCryptoSha384 = RustCryptoSha384::new();

#[inline(always)]
fn algo<'a>(ctx: *const mbedtls_sha512_context) -> &'a dyn MbedtlsDigest {
    algo_for(unsafe { (*ctx).is384 } != 0)
}

#[inline(always)]
fn algo_for<'a>(sha224: bool) -> &'a dyn MbedtlsDigest {
    if sha224 {
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

impl WorkArea for mbedtls_sha512_context {
    fn area(&self) -> &[u8] {
        &self.work_area
    }

    fn area_mut(&mut self) -> &mut [u8] {
        &mut self.work_area
    }
}

#[no_mangle]
unsafe extern "C" fn mbedtls_sha512_init(ctx: *mut mbedtls_sha512_context) {
    digest_init(algo_for(false), ctx);
    unsafe {
        (*ctx).is384 = 0;
    }
}

#[no_mangle]
unsafe extern "C" fn mbedtls_sha512_free(ctx: *mut mbedtls_sha512_context) {
    digest_free(algo(ctx), ctx);
}

#[no_mangle]
unsafe extern "C" fn mbedtls_sha512_clone(
    dst: *mut mbedtls_sha512_context,
    src: *const mbedtls_sha512_context,
) {
    digest_clone(algo(src), src, dst);
}

#[no_mangle]
unsafe extern "C" fn mbedtls_sha512_starts(
    ctx: *mut mbedtls_sha512_context,
    is384: c_int,
) -> c_int {
    let ctx = unsafe { &mut *ctx };

    if (is384 != 0) != (ctx.is384 != 0) {
        digest_init(algo_for(is384 != 0), ctx);
        ctx.is384 = if is384 != 0 { 1 } else { 0 };
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
