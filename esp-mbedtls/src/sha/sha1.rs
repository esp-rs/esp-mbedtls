use core::ffi::{c_int, c_uchar};

use esp_hal::sha::Digest;
use esp_hal::sha::Sha1;

#[repr(C)]
pub struct mbedtls_sha1_context {
    hasher: *mut Sha1<esp_hal::Blocking>,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_init(ctx: *mut mbedtls_sha1_context) {
    let hasher_mem = crate::calloc(1, core::mem::size_of::<Sha1<esp_hal::Blocking>>() as u32)
        as *mut Sha1<esp_hal::Blocking>;
    core::ptr::write(hasher_mem, Sha1::default());
    (*ctx).hasher = hasher_mem;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_free(ctx: *mut mbedtls_sha1_context) {
    if !ctx.is_null() && !(*ctx).hasher.is_null() {
        crate::free((*ctx).hasher as *const u8);
        (*ctx).hasher = core::ptr::null_mut();
    }
}

#[no_mangle]
pub extern "C" fn mbedtls_sha1_clone(
    _dts: *mut mbedtls_sha1_context,
    _src: *const mbedtls_sha1_context,
) {
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_starts(_ctx: *mut mbedtls_sha1_context) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_update(
    ctx: *mut mbedtls_sha1_context,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    let slice = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    (*ctx).hasher.as_mut().unwrap().update(&*slice);
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_finish(
    ctx: *mut mbedtls_sha1_context,
    output: *mut c_uchar,
) -> c_int {
    let hasher = core::ptr::replace((*ctx).hasher, Sha1::default());
    let data: [u8; 20] = hasher.finalize().into();
    core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    0
}
