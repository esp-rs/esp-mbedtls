use core::ffi::{c_int, c_uchar, c_void};

use esp_hal::sha::Sha1;

use crate::esp_hal::SHARED_SHA;

use super::{Context, ShaDigest};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct mbedtls_sha1_context {
    hasher: *mut Context<Sha1>,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_init(ctx: *mut mbedtls_sha1_context) {
    let hasher_mem = crate::aligned_calloc(
        core::mem::align_of::<Context<Sha1>>(),
        core::mem::size_of::<Context<Sha1>>(),
    ) as *mut Context<Sha1>;
    core::ptr::write(hasher_mem, Context::<Sha1>::new());
    (*ctx).hasher = hasher_mem;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_free(ctx: *mut mbedtls_sha1_context) {
    if !ctx.is_null() && !(*ctx).hasher.is_null() {
        crate::free((*ctx).hasher as *const c_void);
        (*ctx).hasher = core::ptr::null_mut();
    }
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_clone(
    dst: *mut mbedtls_sha1_context,
    src: *const mbedtls_sha1_context,
) {
    core::ptr::copy((*src).hasher.clone(), (*dst).hasher, 1);
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
    let mut data = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    critical_section::with(|cs| {
        let mut sha = SHARED_SHA.borrow_ref_mut(cs);
        let mut hasher = ShaDigest::restore(sha.as_mut().unwrap(), (*ctx).hasher.as_mut().unwrap());
        while !data.is_empty() {
            data = nb::block!(hasher.update(&*data)).unwrap();
        }
        nb::block!(hasher.save((*ctx).hasher.as_mut().unwrap())).unwrap();
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha1_finish(
    ctx: *mut mbedtls_sha1_context,
    output: *mut c_uchar,
) -> c_int {
    let mut data: [u8; 20] = [0u8; 20];
    critical_section::with(|cs| {
        let mut sha = SHARED_SHA.borrow_ref_mut(cs);
        let mut hasher = ShaDigest::restore(sha.as_mut().unwrap(), (*ctx).hasher.as_mut().unwrap());
        nb::block!(hasher.finish(&mut data)).unwrap();
        nb::block!(hasher.save((*ctx).hasher.as_mut().unwrap())).unwrap();
    });
    core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    0
}
