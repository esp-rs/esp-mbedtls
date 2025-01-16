use core::ffi::{c_int, c_uchar, c_void};

use esp_hal::sha::{Sha384, Sha512};

use crate::esp_hal::SHARED_SHA;

use super::{Context, ShaDigest};

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct mbedtls_sha512_context {
    sha384_hasher: *mut Context<Sha384>,
    sha512_hasher: *mut Context<Sha512>,
    is384: c_int,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_init(ctx: *mut mbedtls_sha512_context) {
    let sha384_mem = crate::aligned_calloc(
        core::mem::align_of::<Context<Sha384>>(),
        core::mem::size_of::<Context<Sha384>>(),
    ) as *mut Context<Sha384>;
    let sha512_mem = crate::aligned_calloc(
        core::mem::align_of::<Context<Sha512>>(),
        core::mem::size_of::<Context<Sha512>>(),
    ) as *mut Context<Sha512>;
    (*ctx).sha384_hasher = sha384_mem;
    (*ctx).sha512_hasher = sha512_mem;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_free(ctx: *mut mbedtls_sha512_context) {
    if !ctx.is_null() {
        if !(*ctx).sha384_hasher.is_null() {
            crate::free((*ctx).sha384_hasher as *const c_void);
            (*ctx).sha384_hasher = core::ptr::null_mut();
        }
        if !(*ctx).sha512_hasher.is_null() {
            crate::free((*ctx).sha512_hasher as *const c_void);
            (*ctx).sha512_hasher = core::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_clone(
    dst: *mut mbedtls_sha512_context,
    src: *const mbedtls_sha512_context,
) {
    core::ptr::copy((*src).sha384_hasher.clone(), (*dst).sha384_hasher, 1);
    core::ptr::copy((*src).sha512_hasher.clone(), (*dst).sha512_hasher, 1);
    (*dst).is384 = (*src).is384;
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_starts(
    ctx: *mut mbedtls_sha512_context,
    is384: c_int,
) -> c_int {
    if is384 == 1 {
        (*ctx).is384 = 1;
        core::ptr::write((*ctx).sha384_hasher, Context::new());
    } else {
        core::ptr::write((*ctx).sha512_hasher, Context::new());
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_update(
    ctx: *mut mbedtls_sha512_context,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    let mut data = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    critical_section::with(|cs| {
        let mut sha = SHARED_SHA.borrow_ref_mut(cs);
        if (*ctx).is384 == 1 {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha384_hasher.as_mut().unwrap(),
            );
            while !data.is_empty() {
                data = nb::block!(hasher.update(&*data)).unwrap();
            }
            nb::block!(hasher.save((*ctx).sha384_hasher.as_mut().unwrap())).unwrap();
        } else {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha512_hasher.as_mut().unwrap(),
            );
            while !data.is_empty() {
                data = nb::block!(hasher.update(&*data)).unwrap();
            }
            nb::block!(hasher.save((*ctx).sha512_hasher.as_mut().unwrap())).unwrap();
        }
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha512_finish(
    ctx: *mut mbedtls_sha512_context,
    output: *mut c_uchar,
) -> c_int {
    let mut data: [u8; 64] = [0u8; 64];
    critical_section::with(|cs| {
        let mut sha = SHARED_SHA.borrow_ref_mut(cs);

        if (*ctx).is384 == 1 {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha384_hasher.as_mut().unwrap(),
            );
            nb::block!(hasher.finish(&mut data)).unwrap();
            nb::block!(hasher.save((*ctx).sha384_hasher.as_mut().unwrap())).unwrap();
            core::ptr::copy_nonoverlapping(data.as_ptr(), output, 48);
        } else {
            let mut hasher = ShaDigest::restore(
                sha.as_mut().unwrap(),
                (*ctx).sha512_hasher.as_mut().unwrap(),
            );
            nb::block!(hasher.finish(&mut data)).unwrap();
            nb::block!(hasher.save((*ctx).sha512_hasher.as_mut().unwrap())).unwrap();
            core::ptr::copy_nonoverlapping(data.as_ptr(), output, 64);
        }
    });
    0
}
