use crate::hal::peripherals::SHA;
use crate::hal::sha::Sha;
use crate::hal::sha::ShaMode;
use esp_mbedtls_sys::c_types::*;
use nb::block;

#[repr(C)]
pub struct mbedtls_sha256_context<'a> {
    peripheral: SHA,
    hasher: Sha<'a>,
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_init(ctx: *mut mbedtls_sha256_context) {
    (*ctx).peripheral = SHA::steal();
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_free(_ctx: *mut mbedtls_sha256_context) {
    // Do nothing
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_clone<'a>(
    dst: *mut mbedtls_sha256_context<'a>,
    src: *const mbedtls_sha256_context<'a>,
) {
    core::ptr::copy_nonoverlapping(src, dst, 1)
}

#[allow(unused_variables)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_starts(
    ctx: *mut mbedtls_sha256_context,
    is224: c_int,
) -> c_int {
    #[cfg(not(feature = "esp32"))]
    let mode = if is224 == 1 {
        ShaMode::SHA224
    } else {
        ShaMode::SHA256
    };

    #[cfg(feature = "esp32")]
    let mode = ShaMode::SHA256;

    let hasher = Sha::new(&mut (*ctx).peripheral, mode);

    (*ctx).hasher = hasher;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_update(
    ctx: *mut mbedtls_sha256_context,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    let slice = core::ptr::slice_from_raw_parts(input as *const u8, ilen as usize);
    let mut remaining = &*slice;

    while remaining.len() > 0 {
        remaining = block!((*ctx).hasher.update(remaining)).unwrap();
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn mbedtls_sha256_finish(
    ctx: *mut mbedtls_sha256_context,
    output: *mut c_uchar,
) -> c_int {
    let mut data = [0u8; 32];
    block!((*ctx).hasher.finish(&mut data)).unwrap();
    core::ptr::copy_nonoverlapping(data.as_ptr(), output, data.len());
    0
}
