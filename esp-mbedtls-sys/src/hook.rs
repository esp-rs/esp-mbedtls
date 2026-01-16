//! This module allows for replacing (hooking) some crypto algorithms in MbedTLS
//! with custom ones.
//!
//! The primary purpose being providing hardware-accelerated equivalents on platforms
//! that support it.
//!
//! NOTE: When hooking for some/all algorithms is enabled, those that remain "un-hooked"
//! by the user will NOT use the software implementations provided by MbedTLS,
//! but rather - RustCrypto based ones!

pub mod digest;
pub mod exp_mod;

/// Trait representing a work area used by MbedTLS algorithms' hooks.
///
/// The work area is just a sequence of bytes, which is fixed size and pre-allocated (so to say)
/// by MbedTLS, and hopefully big enough for all types of hooks to be able to emplace their
/// state within it.
///
/// For emplacing the state, this trait provides some helper methods to cast the work area
/// to/from the desired types by following Rust emplacement rules (i.e. proper memory alignment
/// of the emplaced type).
///
/// Typically, mult-stage algorithms (e.g., digests) will use this work area to store their
/// intermediate state between calls (as in, between init/reset/update/finish).
pub trait WorkArea {
    /// Get a reference to the work area as a byte slice
    fn area(&self) -> &[u8];

    /// Get a mutable reference to the work area as a byte slice
    fn area_mut(&mut self) -> &mut [u8];

    /// Cast the work area to a mutable `MaybeUninit<T>` reference of the specified type `T`
    ///
    /// # Safety
    /// - The caller MUST ensure that the work area does NOT contain data which is currently
    ///   initialized as type `T` or another initialized type.
    ///   Violating this rule results in undefined behavior in that the drop implementation of
    ///   the currently initialized type (if any) will not be called when the work area is
    ///   reused.
    unsafe fn cast_mut_maybe<T>(&mut self) -> &mut core::mem::MaybeUninit<T> {
        let (_, array, _) = unsafe { self.area_mut().align_to_mut::<core::mem::MaybeUninit<T>>() };

        if array.is_empty() {
            panic!(
                "work area cannot fit target type {}",
                core::any::type_name::<T>()
            );
        }

        &mut array[0]
    }

    /// Cast the work area to a reference of the specified type `T`
    ///
    /// # Safety
    /// - The caller MUST ensure that the work area contains data which is properly
    ///   initialized as type `T`.
    unsafe fn cast<T>(&self) -> &T {
        let (_, array, _) = unsafe { self.area().align_to::<T>() };

        if array.is_empty() {
            panic!(
                "work area cannot fit target type {}",
                core::any::type_name::<T>()
            );
        }

        &array[0]
    }

    /// Cast the work area to a mutable reference of the specified type `T`
    ///
    /// # Safety
    /// - The caller MUST ensure that the work area contains data which is properly
    ///   initialized as type `T`.
    unsafe fn cast_mut<T>(&mut self) -> &mut T {
        let t = self.cast_mut_maybe();

        unsafe { t.assume_init_mut() }
    }
}

impl WorkArea for [u8] {
    fn area(&self) -> &[u8] {
        self
    }

    fn area_mut(&mut self) -> &mut [u8] {
        self
    }
}
