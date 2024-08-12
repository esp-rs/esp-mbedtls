use core::ffi::{c_int, c_uchar};

use esp_hal::sha::{Digest, Sha384, Sha512};

#[repr(C)]
pub struct mbedtls_sha512_context {
    sha384_hasher: *mut Sha384<esp_hal::Blocking>,
    sha512_hasher: *mut Sha512<esp_hal::Blocking>,
    is384: c_int,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_init(ctx: *mut mbedtls_sha512_context) {
    let sha384_mem = crate::calloc(1, core::mem::size_of::<Sha384<esp_hal::Blocking>>() as u32)
        as *mut Sha384<esp_hal::Blocking>;
    let sha512_mem = crate::calloc(1, core::mem::size_of::<Sha512<esp_hal::Blocking>>() as u32)
        as *mut Sha512<esp_hal::Blocking>;
    (*ctx).sha384_hasher = sha384_mem;
    (*ctx).sha512_hasher = sha512_mem;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_free(ctx: *mut mbedtls_sha512_context) {
    if !ctx.is_null() {
        if !(*ctx).sha384_hasher.is_null() {
            crate::free((*ctx).sha384_hasher as *const u8);
            (*ctx).sha384_hasher = core::ptr::null_mut();
        }
        if !(*ctx).sha512_hasher.is_null() {
            crate::free((*ctx).sha512_hasher as *const u8);
            (*ctx).sha512_hasher = core::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn mbedtls_sha512_clone(
    _dts: *mut mbedtls_sha512_context,
    _src: *const mbedtls_sha512_context,
) {
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_starts(
    ctx: *mut mbedtls_sha512_context,
    is384: c_int,
) -> c_int {
    if is384 == 1 {
        (*ctx).is384 = 1;
        core::ptr::write((*ctx).sha384_hasher, Sha384::default());
    } else {
        core::ptr::write((*ctx).sha512_hasher, Sha512::default());
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_update(
    ctx: *mut mbedtls_sha512_context,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    let slice = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    if (*ctx).is384 == 1 {
        (*ctx).sha384_hasher.as_mut().unwrap().update(&*slice);
    } else {
        (*ctx).sha512_hasher.as_mut().unwrap().update(&*slice);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_finish(
    ctx: *mut mbedtls_sha512_context,
    output: *mut c_uchar,
) -> c_int {
    if (*ctx).is384 == 1 {
        let hasher = core::ptr::replace((*ctx).sha384_hasher, Sha384::default());
        let data: [u8; 48] = hasher.finalize().into();
        core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    } else {
        let hasher = core::ptr::replace((*ctx).sha512_hasher, Sha512::default());
        let data: [u8; 64] = hasher.finalize().into();
        core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    }
    0
}
