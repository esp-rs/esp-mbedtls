//! Restartable elliptic-curve operation controls.

use crate::sys::mbedtls_ecp_set_max_ops;
use crate::RNG;

/// Set the process-wide operation budget for restartable elliptic-curve operations.
///
/// Call this during initialization, before creating a [`crate::Tls`] instance. A value of zero
/// disables the operation limit, so elliptic-curve operations run to completion without yielding.
/// Blocking `Session`s cannot yield, so they immediately re-enter an in-progress restartable
/// operation and run it to completion; only async sessions turn it into a cooperative yield.
///
/// # Panics
///
/// Panics if a `Tls` instance already exists. This ensures that the process-wide C setting cannot
/// race with TLS operations when configured through this safe wrapper.
pub fn set_restartable_max_ops(max_ops: u32) {
    critical_section::with(|critical_section| {
        assert!(
            RNG.borrow(critical_section).borrow().is_none(),
            "restartable ECP must be configured before creating Tls",
        );
        unsafe { mbedtls_ecp_set_max_ops(max_ops) }
    });
}
