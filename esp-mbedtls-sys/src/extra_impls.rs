//! Provide extra implementations to the generated bindings

impl core::fmt::Debug for crate::bindings::mbedtls_x509_time {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            // ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.mon, self.day, self.hour, self.min, self.sec
        )
    }
}
