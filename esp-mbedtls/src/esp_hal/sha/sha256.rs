use core::ffi::{c_int, c_uchar, c_void};

use esp_hal::sha::{Sha224, Sha256};

use crate::esp_hal::SHARED_SHA;

use super::{nb, Context, ShaDigest};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct mbedtls_sha256_context {
    sha224_hasher: *mut Context<Sha224>,
    sha256_hasher: *mut Context<Sha256>,
    is224: c_int,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_init(ctx: *mut mbedtls_sha256_context) {
    let sha224_mem =
        crate::calloc(1, core::mem::size_of::<Context<Sha224>>()) as *mut Context<Sha224>;
    let sha256_mem =
        crate::calloc(1, core::mem::size_of::<Context<Sha256>>()) as *mut Context<Sha256>;
    (*ctx).sha224_hasher = sha224_mem;
    (*ctx).sha256_hasher = sha256_mem;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_free(ctx: *mut mbedtls_sha256_context) {
    if !ctx.is_null() {
        if !(*ctx).sha224_hasher.is_null() {
            crate::free((*ctx).sha224_hasher as *const c_void);
            (*ctx).sha224_hasher = core::ptr::null_mut();
        }
        if !(*ctx).sha256_hasher.is_null() {
            crate::free((*ctx).sha256_hasher as *const c_void);
            (*ctx).sha256_hasher = core::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_clone(
    dst: *mut mbedtls_sha256_context,
    src: *const mbedtls_sha256_context,
) {
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
        core::ptr::write((*ctx).sha224_hasher, Context::new());
    } else {
        core::ptr::write((*ctx).sha256_hasher, Context::new());
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_update(
    ctx: *mut mbedtls_sha256_context,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    let mut data = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    critical_section::with(|cs| {
        let mut sha = SHARED_SHA.borrow_ref_mut(cs);
        if (*ctx).is224 == 1 {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha224_hasher.as_mut().unwrap(),
            );
            while !data.is_empty() {
                data = nb::block!(hasher.update(&*data)).unwrap();
            }
            nb::block!(hasher.save((*ctx).sha224_hasher.as_mut().unwrap())).unwrap();
        } else {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha256_hasher.as_mut().unwrap(),
            );
            while !data.is_empty() {
                data = nb::block!(hasher.update(&*data)).unwrap();
            }
            nb::block!(hasher.save((*ctx).sha256_hasher.as_mut().unwrap())).unwrap();
        }
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_finish(
    ctx: *mut mbedtls_sha256_context,
    output: *mut c_uchar,
) -> c_int {
    let mut data: [u8; 32] = [0u8; 32];
    critical_section::with(|cs| {
        let mut sha = SHARED_SHA.borrow_ref_mut(cs);

        if (*ctx).is224 == 1 {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha224_hasher.as_mut().unwrap(),
            );
            nb::block!(hasher.finish(&mut data)).unwrap();
            nb::block!(hasher.save((*ctx).sha224_hasher.as_mut().unwrap())).unwrap();
        } else {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha256_hasher.as_mut().unwrap(),
            );
            nb::block!(hasher.finish(&mut data)).unwrap();
            nb::block!(hasher.save((*ctx).sha256_hasher.as_mut().unwrap())).unwrap();
        }
    });
    core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    0
}
