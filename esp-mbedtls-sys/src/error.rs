//! MbedTLS error representation and handling.

use core::fmt::{Debug, Display};

/// Represents an error returned by the MbedTLS library.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct MbedtlsError(i32);

impl MbedtlsError {
    /// Create a new `MbedtlsError` from the given error code.
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    /// Get the underlying error code.
    pub fn code(&self) -> i32 {
        self.0
    }

    /// Get the normalized error code as a positive `u16` if applicable.
    pub fn code_normalized(&self) -> Option<u16> {
        (self.0 <= 0 && self.0 >= -65535).then_some(-self.0 as u16)
    }
}

impl Debug for MbedtlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for MbedtlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(normalized) = self.code_normalized() {
            write!(f, "MbedtlsError({} / 0x{:04x})", self.0, normalized)
        } else {
            write!(f, "MbedtlsError({})", self.0)
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for MbedtlsError {
    fn format(&self, f: defmt::Formatter) {
        if let Some(normalized) = self.code_normalized() {
            defmt::write!(f, "MbedtlsError({} / 0x{:04x})", self.0, normalized)
        } else {
            defmt::write!(f, "MbedtlsError({})", self.0)
        }
    }
}

impl core::error::Error for MbedtlsError {}

#[macro_export]
macro_rules! merr {
    ($block:expr) => {{
        let res = $block;
        if res != 0 {
            Err($crate::MbedtlsError::new(res))
        } else {
            Ok(())
        }
    }};
}
