//! ESP32XX time support based on the baremetal `esp-hal` crate.
//!
//! This module provides MbedTLS time integration using the ESP32's RTC peripheral.
//! It implements the standard time hooks required by MbedTLS for certificate
//! validation and other time-sensitive operations.

use core::cell::Cell;
use critical_section::Mutex;
use time::OffsetDateTime;

use super::MbedtlsTm;
pub struct Driver {
    rtc: Mutex<Cell<Option<&'static esp_hal::rtc_cntl::Rtc<'static>>>>,
}

impl Driver {
    pub const fn new() -> Self {
        Self {
            rtc: Mutex::new(Cell::new(None)),
        }
    }

    /// Get current time in seconds since Unix epoch.
    pub fn time(&self) -> i64 {
        self.with_rtc(|rtc| (rtc.current_time_us() / 1_000_000) as i64)
            .unwrap_or(i64::MAX)
    }

    /// Get current time in milliseconds since Unix epoch.
    pub fn ms_time(&self) -> i64 {
        self.with_rtc(|rtc| (rtc.current_time_us() / 1_000) as i64)
            .unwrap_or(i64::MAX)
    }

    /// Convert Unix timestamp to broken-down time in UTC.
    pub fn gmtime_r(&self, time: i64, tm_buf: &mut MbedtlsTm) -> Result<(), ()> {
        // Convert Unix timestamp to OffsetDateTime
        let dt = OffsetDateTime::from_unix_timestamp(time).map_err(|_| ())?;

        let date = dt.date();
        let time_components = dt.time();

        // Fill in the MbedtlsTm structure
        tm_buf.tm_sec = time_components.second() as i32;
        tm_buf.tm_min = time_components.minute() as i32;
        tm_buf.tm_hour = time_components.hour() as i32;
        tm_buf.tm_mday = date.day() as i32;
        tm_buf.tm_mon = u8::from(date.month()) as i32 - 1; // MbedTLS uses 0-11
        tm_buf.tm_year = date.year() - 1900; // MbedTLS uses years since 1900
        tm_buf.tm_wday = date.weekday().number_days_from_sunday() as i32;
        tm_buf.tm_yday = date.ordinal() as i32 - 1; // MbedTLS uses 0-365
        tm_buf.tm_isdst = -1; // Daylight saving time info not available

        Ok(())
    }
    fn with_rtc<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&esp_hal::rtc_cntl::Rtc<'_>) -> R,
    {
        critical_section::with(|cs| self.rtc.borrow(cs).get().map(f))
    }
}

/// Global time driver instance.
pub(crate) static DRIVER: Driver = Driver::new();

/// Guard for RAII lifecycle management of the RTC.
///
/// When dropped, this guard unregisters the RTC from the time driver.
pub struct TimeGuard;

impl Drop for TimeGuard {
    fn drop(&mut self) {
        critical_section::with(|cs| {
            DRIVER.rtc.borrow(cs).set(None);
        });
    }
}

/// Register an RTC instance with the time driver.
///
/// This function must be called before using any time functions.
/// The RTC must have a static lifetime to ensure it remains valid.
///
/// # Returns
///
/// A `TimeGuard` that automatically unregisters the RTC when dropped.
///
/// ```
pub fn register(rtc: &'static esp_hal::rtc_cntl::Rtc<'static>) -> TimeGuard {
    critical_section::with(|cs| {
        DRIVER.rtc.borrow(cs).set(Some(rtc));
    });
    TimeGuard
}
