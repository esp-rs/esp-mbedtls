use core::cell::Cell;
use core::ffi::c_int;
use core::ops::Deref;

use critical_section::Mutex;

use esp_mbedtls_sys::{mbedtls_mpi, mbedtls_mpi_exp_mod_soft};

pub(crate) static EXP_MOD: Mutex<Cell<Option<&(dyn MbedtlsMpiExpMod + Send + Sync)>>> =
    Mutex::new(Cell::new(None));
static EXP_MOD_FALLBACK: FallbackMpiExpMod = FallbackMpiExpMod::new();

pub trait MbedtlsMpiExpMod {
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: &mut mbedtls_mpi,
    );
}

impl<T> MbedtlsMpiExpMod for T
where
    T: Deref,
    T::Target: MbedtlsMpiExpMod,
{
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: &mut mbedtls_mpi,
    ) {
        self.deref().exp_mod(z, x, y, m, prec_rr);
    }
}

pub struct FallbackMpiExpMod(());

impl FallbackMpiExpMod {
    pub const fn new() -> Self {
        Self(())
    }
}

impl Default for FallbackMpiExpMod {
    fn default() -> Self {
        Self::new()
    }
}

impl MbedtlsMpiExpMod for FallbackMpiExpMod {
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: &mut mbedtls_mpi,
    ) {
        unsafe {
            mbedtls_mpi_exp_mod_soft(z, x, y, m, prec_rr);
        }
    }
}

/// Z = X ^ Y mod M
#[no_mangle]
unsafe extern "C" fn mbedtls_mpi_exp_mod(
    z: *mut mbedtls_mpi,
    x: *const mbedtls_mpi,
    y: *const mbedtls_mpi,
    m: *const mbedtls_mpi,
    prec_rr: *mut mbedtls_mpi,
) -> c_int {
    if let Some(exp_mod) = critical_section::with(|cs| EXP_MOD.borrow(cs).get()) {
        exp_mod.exp_mod(&mut *z, &*x, &*y, &*m, &mut *prec_rr);
    } else {
        EXP_MOD_FALLBACK.exp_mod(&mut *z, &*x, &*y, &*m, &mut *prec_rr);
    }

    0
}
