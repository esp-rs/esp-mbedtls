//! Platform time support for MbedTLS.
//!
//! This module provides direct C FFI implementations for MbedTLS time functions.
use core::ptr;
/// MbedTLS time structure (compatible with POSIX struct tm)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MbedtlsTm {
    pub tm_sec: i32,   // Seconds (0-59)
    pub tm_min: i32,   // Minutes (0-59)
    pub tm_hour: i32,  // Hours (0-23)
    pub tm_mday: i32,  // Day of month (1-31)
    pub tm_mon: i32,   // Month (0-11)
    pub tm_year: i32,  // Years since 1900
    pub tm_wday: i32,  // Day of week (0-6, Sunday = 0)
    pub tm_yday: i32,  // Day of year (0-365)
    pub tm_isdst: i32, // Daylight saving time flag
}

// Platform-specific backend implementations
#[cfg_attr(
    any(
        feature = "time-esp32",
        feature = "accel-esp32c2",
        feature = "accel-esp32c3",
        feature = "time-esp32c6",
        feature = "time-esp32h2",
        feature = "time-esp32s2",
        feature = "time-esp32s3"
    ),
    path = "time/esp.rs"
)]
mod driver;

pub use driver::register;
pub use driver::TimeGuard;
use driver::DRIVER;

/// Get current time in milliseconds since epoch.
///
/// This function is called by MbedTLS for time-based operations.
#[no_mangle]
#[cfg(feature = "time")]
pub unsafe extern "C" fn mbedtls_ms_time() -> i64 {
    DRIVER.ms_time()
}

/// Get current time in seconds since epoch.
///
/// This function is called by MbedTLS for time-based operations.
/// If `timer` is not null, the time is also stored in `*timer`.
#[no_mangle]
#[cfg(feature = "time")]
pub unsafe extern "C" fn time(timer: *mut i64) -> i64 {
    let current_time = DRIVER.time();
    if !timer.is_null() {
        *timer = current_time;
    }
    current_time
}

/// Convert time value to broken-down time in UTC.
///
/// This function converts a Unix timestamp to a broken-down time structure.
/// Returns a pointer to `tm_buf` on success, or null on failure.
#[no_mangle]
#[cfg(feature = "time")]
pub unsafe extern "C" fn mbedtls_platform_gmtime_r(
    tt: *const i64,
    tm_buf: *mut MbedtlsTm,
) -> *mut MbedtlsTm {
    if tt.is_null() || tm_buf.is_null() {
        return ptr::null_mut();
    }

    match DRIVER.gmtime_r(*tt, &mut *tm_buf) {
        Ok(()) => tm_buf,
        Err(()) => ptr::null_mut(),
    }
}
