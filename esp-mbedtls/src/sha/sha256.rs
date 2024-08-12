use core::ffi::{c_int, c_uchar};

use esp_hal::sha::{Digest, Sha224, Sha256};

#[repr(C)]
pub struct mbedtls_sha256_context {
    sha224_hasher: *mut Sha224<esp_hal::Blocking>,
    sha256_hasher: *mut Sha256<esp_hal::Blocking>,
    is224: c_int,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_init(ctx: *mut mbedtls_sha256_context) {
    let sha224_mem = crate::calloc(1, core::mem::size_of::<Sha224<esp_hal::Blocking>>() as u32)
        as *mut Sha224<esp_hal::Blocking>;
    let sha256_mem = crate::calloc(1, core::mem::size_of::<Sha256<esp_hal::Blocking>>() as u32)
        as *mut Sha256<esp_hal::Blocking>;
    (*ctx).sha224_hasher = sha224_mem;
    (*ctx).sha256_hasher = sha256_mem;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_free(ctx: *mut mbedtls_sha256_context) {
    if !ctx.is_null() {
        if !(*ctx).sha224_hasher.is_null() {
            crate::free((*ctx).sha224_hasher as *const u8);
            (*ctx).sha224_hasher = core::ptr::null_mut();
        }
        if !(*ctx).sha256_hasher.is_null() {
            crate::free((*ctx).sha256_hasher as *const u8);
            (*ctx).sha256_hasher = core::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_clone(
    dst: *mut mbedtls_sha256_context,
    src: *const mbedtls_sha256_context,
) {
    mbedtls_sha256_init(dst);
    core::ptr::copy((*src).sha224_hasher.clone(), (*dst).sha224_hasher, 1);
    core::ptr::copy((*src).sha256_hasher.clone(), (*dst).sha256_hasher, 1);
    (*dst).is224 = (*src).is224;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_starts(
    ctx: *mut mbedtls_sha256_context,
    is224: c_int,
) -> c_int {
    if is224 == 1 {
        (*ctx).is224 = 1;
        core::ptr::write((*ctx).sha224_hasher, Sha224::default());
    } else {
        core::ptr::write((*ctx).sha256_hasher, Sha256::default());
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_update(
    ctx: *mut mbedtls_sha256_context,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    let slice = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    if (*ctx).is224 == 1 {
        (*ctx).sha224_hasher.as_mut().unwrap().update(&*slice);
    } else {
        (*ctx).sha256_hasher.as_mut().unwrap().update(&*slice);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_finish(
    ctx: *mut mbedtls_sha256_context,
    output: *mut c_uchar,
) -> c_int {
    if (*ctx).is224 == 1 {
        let hasher = core::ptr::replace((*ctx).sha224_hasher, Sha224::default());
        let data: [u8; 28] = hasher.finalize().into();
        core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    } else {
        let hasher = core::ptr::replace((*ctx).sha256_hasher, Sha256::default());
        let data: [u8; 32] = hasher.finalize().into();
        core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    }
    0
}
