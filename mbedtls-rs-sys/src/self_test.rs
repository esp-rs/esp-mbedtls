//! MbedTLS self-test wrappers.
//!
//! Each `mbedtls_<alg>_self_test` symbol only exists when the corresponding
//! algorithm is compiled in (see the `alg-*` cargo features / `gen/features.rs`),
//! so every variant here is gated behind its feature. `Mpi` is always available
//! (bignum is part of the always-on core).

#[cfg(feature = "alg-aes")]
use crate::mbedtls_aes_self_test;
#[cfg(feature = "alg-ecp")]
use crate::mbedtls_ecp_self_test;
#[cfg(feature = "alg-md5")]
use crate::mbedtls_md5_self_test;
#[cfg(feature = "alg-rsa")]
use crate::mbedtls_rsa_self_test;
#[cfg(feature = "alg-sha1")]
use crate::mbedtls_sha1_self_test;
#[cfg(feature = "alg-sha256")]
use crate::{mbedtls_sha224_self_test, mbedtls_sha256_self_test};
#[cfg(feature = "alg-sha512")]
use crate::{mbedtls_sha384_self_test, mbedtls_sha512_self_test};

use crate::mbedtls_mpi_self_test;

/// An MbedTLS self-test type.
///
/// Variants are only present when the underlying algorithm is enabled.
#[derive(enumset::EnumSetType, Debug)]
pub enum MbedtlsSelfTest {
    Mpi = 0,
    #[cfg(feature = "alg-rsa")]
    Rsa = 1,
    #[cfg(feature = "alg-sha1")]
    Sha1 = 2,
    #[cfg(feature = "alg-sha256")]
    Sha224 = 3,
    #[cfg(feature = "alg-sha256")]
    Sha256 = 4,
    #[cfg(feature = "alg-sha512")]
    Sha384 = 5,
    #[cfg(feature = "alg-sha512")]
    Sha512 = 6,
    #[cfg(feature = "alg-aes")]
    Aes = 7,
    #[cfg(feature = "alg-md5")]
    Md5 = 8,
    /// Elliptic-curve point multiplication: exercises `mbedtls_ecp_mul`, and
    /// with it the `hook::ecp` shims and their hardware backends where hooked.
    #[cfg(feature = "alg-ecp")]
    Ecp = 9,
}

impl MbedtlsSelfTest {
    /// Run a self-test on the MbedTLS library
    ///
    /// # Arguments
    ///
    /// * `test` - The test to run
    /// * `verbose` - Whether to run the test in verbose mode
    pub fn run(&mut self, verbose: bool) -> bool {
        let verbose = verbose as _;

        let result = unsafe {
            match self {
                Self::Mpi => mbedtls_mpi_self_test(verbose),
                #[cfg(feature = "alg-rsa")]
                Self::Rsa => mbedtls_rsa_self_test(verbose),
                #[cfg(feature = "alg-sha1")]
                Self::Sha1 => mbedtls_sha1_self_test(verbose),
                #[cfg(feature = "alg-sha256")]
                Self::Sha224 => mbedtls_sha224_self_test(verbose),
                #[cfg(feature = "alg-sha256")]
                Self::Sha256 => mbedtls_sha256_self_test(verbose),
                #[cfg(feature = "alg-sha512")]
                Self::Sha384 => mbedtls_sha384_self_test(verbose),
                #[cfg(feature = "alg-sha512")]
                Self::Sha512 => mbedtls_sha512_self_test(verbose),
                #[cfg(feature = "alg-aes")]
                Self::Aes => mbedtls_aes_self_test(verbose),
                #[cfg(feature = "alg-md5")]
                Self::Md5 => mbedtls_md5_self_test(verbose),
                #[cfg(feature = "alg-ecp")]
                Self::Ecp => mbedtls_ecp_self_test(verbose),
            }
        };

        result == 0
    }
}

impl core::fmt::Display for MbedtlsSelfTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MbedtlsSelfTest::Mpi => write!(f, "MPI"),
            #[cfg(feature = "alg-rsa")]
            MbedtlsSelfTest::Rsa => write!(f, "RSA"),
            #[cfg(feature = "alg-sha1")]
            MbedtlsSelfTest::Sha1 => write!(f, "SHA1"),
            #[cfg(feature = "alg-sha256")]
            MbedtlsSelfTest::Sha224 => write!(f, "SHA224"),
            #[cfg(feature = "alg-sha256")]
            MbedtlsSelfTest::Sha256 => write!(f, "SHA256"),
            #[cfg(feature = "alg-sha512")]
            MbedtlsSelfTest::Sha384 => write!(f, "SHA384"),
            #[cfg(feature = "alg-sha512")]
            MbedtlsSelfTest::Sha512 => write!(f, "SHA512"),
            #[cfg(feature = "alg-aes")]
            MbedtlsSelfTest::Aes => write!(f, "AES"),
            #[cfg(feature = "alg-md5")]
            MbedtlsSelfTest::Md5 => write!(f, "MD5"),
            #[cfg(feature = "alg-ecp")]
            MbedtlsSelfTest::Ecp => write!(f, "ECP"),
        }
    }
}

#[cfg(all(
    feature = "alg-ecdsa",
    feature = "alg-ecp",
    feature = "curve-secp256r1"
))]
pub use ecdsa_bench::EcdsaP256Bench;

#[cfg(all(
    feature = "alg-ecdsa",
    feature = "alg-ecp",
    feature = "curve-secp256r1"
))]
mod ecdsa_bench {
    use core::ffi::{c_int, c_void};
    use core::mem::MaybeUninit;
    use core::ptr;

    use crate::{
        mbedtls_ecdsa_sign, mbedtls_ecdsa_verify, mbedtls_ecp_gen_keypair, mbedtls_ecp_group,
        mbedtls_ecp_group_free, mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
        mbedtls_ecp_group_init, mbedtls_ecp_group_load, mbedtls_ecp_point, mbedtls_ecp_point_free,
        mbedtls_ecp_point_init, mbedtls_mpi, mbedtls_mpi_free, mbedtls_mpi_init,
    };

    /// A production-shaped ECDSA P-256 benchmark helper.
    ///
    /// The [`MbedtlsSelfTest::Ecp`](super::MbedtlsSelfTest::Ecp) self-test
    /// under-reports hardware-acceleration gains: it reuses one group object
    /// for a loop of *base-point* multiplications, letting the software path
    /// amortize its comb precomputation table (`grp->T`) across the loop while
    /// a hardware backend pays full cost per call — and it prefers P-192,
    /// where software is disproportionately fast.
    ///
    /// This helper instead measures what a real handshake pays: NIST P-256
    /// (the curve TLS/Matter actually negotiate), a **fresh group per
    /// operation** (no comb-table reuse), and ECDSA sign / verify as separate
    /// operations (verify is the double-mul where hardware helps most).
    ///
    /// Timing is the caller's job (cycle counters and clocks are
    /// platform-specific): time each [`sign`](Self::sign) /
    /// [`verify`](Self::verify) call. Key generation (in [`new`](Self::new))
    /// stays outside any timed region. The `rng` closure just fills the buffer
    /// with randomness — platform RNG quality is fine; this type is for
    /// benchmarking, not for production key material.
    pub struct EcdsaP256Bench<'a> {
        rng: &'a mut dyn FnMut(&mut [u8]),
        /// The private scalar, public point and current signature. Curve
        /// elements are independent of any `mbedtls_ecp_group` *instance*, so
        /// they are reusable across the fresh per-operation groups.
        d: mbedtls_mpi,
        q: mbedtls_ecp_point,
        r: mbedtls_mpi,
        s: mbedtls_mpi,
    }

    impl<'a> EcdsaP256Bench<'a> {
        /// The (fixed, fake) 32-byte message digest being signed/verified.
        const HASH: [u8; 32] = [0x5A; 32];

        /// Generate a P-256 keypair and an initial signature (both untimed),
        /// so [`sign`](Self::sign) and [`verify`](Self::verify) can then be
        /// benchmarked independently. Returns `None` on any MbedTLS error.
        pub fn new(rng: &'a mut dyn FnMut(&mut [u8])) -> Option<Self> {
            let (d, q, r, s) = unsafe {
                let mut d = MaybeUninit::<mbedtls_mpi>::uninit();
                mbedtls_mpi_init(d.as_mut_ptr());
                let mut q = MaybeUninit::<mbedtls_ecp_point>::uninit();
                mbedtls_ecp_point_init(q.as_mut_ptr());
                let mut r = MaybeUninit::<mbedtls_mpi>::uninit();
                mbedtls_mpi_init(r.as_mut_ptr());
                let mut s = MaybeUninit::<mbedtls_mpi>::uninit();
                mbedtls_mpi_init(s.as_mut_ptr());

                (
                    d.assume_init(),
                    q.assume_init(),
                    r.assume_init(),
                    s.assume_init(),
                )
            };

            let mut this = Self { rng, d, q, r, s };

            let ok = this.with_fresh_group(|bench, grp| {
                let rng_ctx = bench.rng_ctx();
                unsafe {
                    mbedtls_ecp_gen_keypair(
                        grp,
                        &mut bench.d,
                        &mut bench.q,
                        Some(rng_trampoline),
                        rng_ctx,
                    ) == 0
                }
            });

            // `this` (with its initialized members) is dropped - and freed -
            // normally on the failure paths.
            (ok && this.sign()).then_some(this)
        }

        /// Run one ECDSA P-256 signing operation over a fresh group, storing
        /// the signature for [`verify`](Self::verify). Returns success.
        pub fn sign(&mut self) -> bool {
            self.with_fresh_group(|bench, grp| {
                let rng_ctx = bench.rng_ctx();
                unsafe {
                    mbedtls_ecdsa_sign(
                        grp,
                        &mut bench.r,
                        &mut bench.s,
                        &bench.d,
                        Self::HASH.as_ptr(),
                        Self::HASH.len(),
                        Some(rng_trampoline),
                        rng_ctx,
                    ) == 0
                }
            })
        }

        /// Run one ECDSA P-256 verification of the stored signature over a
        /// fresh group. Returns success (i.e. the signature verified).
        pub fn verify(&mut self) -> bool {
            self.with_fresh_group(|bench, grp| unsafe {
                mbedtls_ecdsa_verify(
                    grp,
                    Self::HASH.as_ptr(),
                    Self::HASH.len(),
                    &bench.q,
                    &bench.r,
                    &bench.s,
                ) == 0
            })
        }

        /// Load a fresh P-256 group, run `f` with it, free it. The fresh group
        /// is the point of this benchmark: no comb-precomputation state
        /// survives between operations, as in real handshakes.
        fn with_fresh_group(
            &mut self,
            f: impl FnOnce(&mut Self, *mut mbedtls_ecp_group) -> bool,
        ) -> bool {
            let mut grp = MaybeUninit::<mbedtls_ecp_group>::uninit();

            let ok = unsafe {
                mbedtls_ecp_group_init(grp.as_mut_ptr());
                mbedtls_ecp_group_load(
                    grp.as_mut_ptr(),
                    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
                ) == 0
            };

            let ok = ok && f(self, grp.as_mut_ptr());

            unsafe {
                mbedtls_ecp_group_free(grp.as_mut_ptr());
            }

            ok
        }

        /// The `p_rng` context for [`rng_trampoline`]: a pointer to the
        /// `&mut dyn FnMut` fat reference itself.
        fn rng_ctx(&mut self) -> *mut c_void {
            ptr::from_mut(&mut self.rng).cast()
        }
    }

    impl Drop for EcdsaP256Bench<'_> {
        fn drop(&mut self) {
            unsafe {
                mbedtls_mpi_free(&mut self.s);
                mbedtls_mpi_free(&mut self.r);
                mbedtls_ecp_point_free(&mut self.q);
                mbedtls_mpi_free(&mut self.d);
            }
        }
    }

    /// MbedTLS `f_rng` bridging to the bench's `&mut dyn FnMut(&mut [u8])`.
    ///
    /// # Safety
    /// `p_rng` must be the pointer produced by [`EcdsaP256Bench::rng_ctx`],
    /// and the referenced closure must outlive the call (both guaranteed by
    /// the bench methods, which only pass it within their own scope).
    unsafe extern "C" fn rng_trampoline(p_rng: *mut c_void, buf: *mut u8, len: usize) -> c_int {
        let rng = unsafe { &mut *p_rng.cast::<&mut dyn FnMut(&mut [u8])>() };
        rng(unsafe { core::slice::from_raw_parts_mut(buf, len) });

        0
    }
}
