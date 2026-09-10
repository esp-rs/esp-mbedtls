//! ECP scalar multiplication delegating to the `embassy-crypto` curve
//! arithmetic drivers (`P256Arith`, `P384Arith`).
//!
//! Operands the drivers are not given - other curves, scalars outside
//! `[1, n)`, non-affine points, coordinates outside `[0, p)`, points not on
//! the curve - are delegated to the MbedTLS software implementation, so
//! behavior (error codes included) stays identical to the un-hooked build for
//! everything the drivers do not cover.
//!
//! The drivers are constant-time by contract, so the MbedTLS coordinate
//! blinding (and its RNG) is not needed.

use core::ffi::c_void;
use core::marker::PhantomData;

use crate::hook::ecp::{ecp_mul_soft, MbedtlsEcpMul, MbedtlsEcpRestartCtx, MbedtlsFRng};
use crate::{
    mbedtls_ecp_group, mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1, mbedtls_ecp_point, mbedtls_ecp_point_cmp,
    mbedtls_mpi, mbedtls_mpi_cmp_int, mbedtls_mpi_cmp_mpi, mbedtls_mpi_lset,
    mbedtls_mpi_read_binary, mbedtls_mpi_write_binary, merr, MbedtlsError,
};

/// A set of curves served by `embassy-crypto` arithmetic drivers, as used by
/// [`EmbassyEcp`].
///
/// Implemented by [`P256`] and [`P384`], and by pairs of sets: `(P256, P384)`
/// serves both curves.
pub trait EmbassyCurves {
    /// Compute `r = m * p` on `grp` with the driver of its curve.
    ///
    /// Returns `None`, leaving `r` untouched, if the curve is not in the set
    /// or the operands are not ones the drivers are given (see the module
    /// docs); the caller then falls back to the software implementation.
    fn mul(
        grp: &mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
    ) -> Option<Result<(), MbedtlsError>>;
}

impl<A, B> EmbassyCurves for (A, B)
where
    A: EmbassyCurves,
    B: EmbassyCurves,
{
    fn mul(
        grp: &mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
    ) -> Option<Result<(), MbedtlsError>> {
        A::mul(grp, r, m, p).or_else(|| B::mul(grp, r, m, p))
    }
}

macro_rules! embassy_curve {
    ($(#[$meta:meta])* $name:ident, $curve:ident, $group_id:ident, $size:literal) => {
        $(#[$meta])*
        pub enum $name {}

        impl EmbassyCurves for $name {
            fn mul(
                grp: &mbedtls_ecp_group,
                r: &mut mbedtls_ecp_point,
                m: &mbedtls_mpi,
                p: &mbedtls_ecp_point,
            ) -> Option<Result<(), MbedtlsError>> {
                use embassy_crypto::$curve::{Point, Scalar};

                if grp.id != $group_id {
                    return None;
                }

                let k = Scalar::from_bytes(&scalar_operand::<$size>(grp, m)?).ok()?;

                let result = if unsafe { mbedtls_ecp_point_cmp(p, &grp.G) } == 0 {
                    Point::mul_base(&k)
                } else {
                    let (x, y) = point_operands::<$size>(grp, p)?;

                    // Checks that the point is on the curve
                    Point::from_xy(&x, &y).ok()?.mul(&k)
                };

                // `k` is in `[1, n)` and the curve has prime order, so the
                // result is never the point at infinity
                let result = result.to_affine()?;

                Some(write_point(r, &result.x, &result.y))
            }
        }
    };
}

embassy_curve!(
    /// NIST P-256 (secp256r1), served by the `embassy-crypto` `P256Arith` driver
    P256,
    p256,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP256R1,
    32
);

embassy_curve!(
    /// NIST P-384 (secp384r1), served by the `embassy-crypto` `P384Arith` driver
    P384,
    p384,
    mbedtls_ecp_group_id_MBEDTLS_ECP_DP_SECP384R1,
    48
);

/// Serialize an MPI to the fixed-size big-endian representation used by the
/// drivers. `None` if the value does not fit.
fn to_be<const N: usize>(mpi: &mbedtls_mpi) -> Option<[u8; N]> {
    let mut buf = [0; N];

    merr!(unsafe { mbedtls_mpi_write_binary(mpi, buf.as_mut_ptr(), N) })
        .ok()
        .map(|_| buf)
}

/// The scalar, if it is in `[1, n)` - the range MbedTLS accepts for the
/// multiplication
fn scalar_operand<const N: usize>(grp: &mbedtls_ecp_group, m: &mbedtls_mpi) -> Option<[u8; N]> {
    if unsafe { mbedtls_mpi_cmp_int(m, 0) } <= 0 || unsafe { mbedtls_mpi_cmp_mpi(m, &grp.N) } >= 0 {
        return None;
    }

    to_be(m)
}

/// The coordinates of the point, if it has affine (Z == 1) representation
/// and in-range, non-negative coordinates
fn point_operands<const N: usize>(
    grp: &mbedtls_ecp_group,
    pt: &mbedtls_ecp_point,
) -> Option<([u8; N], [u8; N])> {
    if unsafe { mbedtls_mpi_cmp_int(&pt.private_Z, 1) } != 0 {
        return None;
    }

    if unsafe { mbedtls_mpi_cmp_int(&pt.private_X, 0) } < 0
        || unsafe { mbedtls_mpi_cmp_int(&pt.private_Y, 0) } < 0
        || unsafe { mbedtls_mpi_cmp_mpi(&pt.private_X, &grp.P) } >= 0
        || unsafe { mbedtls_mpi_cmp_mpi(&pt.private_Y, &grp.P) } >= 0
    {
        return None;
    }

    Some((to_be(&pt.private_X)?, to_be(&pt.private_Y)?))
}

fn write_point(r: &mut mbedtls_ecp_point, x: &[u8], y: &[u8]) -> Result<(), MbedtlsError> {
    merr!(unsafe { mbedtls_mpi_read_binary(&mut r.private_X, x.as_ptr(), x.len()) })?;
    merr!(unsafe { mbedtls_mpi_read_binary(&mut r.private_Y, y.as_ptr(), y.len()) })?;
    merr!(unsafe { mbedtls_mpi_lset(&mut r.private_Z, 1) })?;

    Ok(())
}

/// ECP scalar multiplication delegating to the `embassy-crypto` arithmetic
/// drivers of the curves in `C` - by default P-256 only, e.g.
/// `EmbassyEcp<(P256, P384)>` serves P-384 as well - and to the MbedTLS
/// software implementation for everything else.
pub struct EmbassyEcp<C = P256>(PhantomData<fn() -> C>);

impl<C> EmbassyEcp<C> {
    /// Create a new `EmbassyEcp` instance
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C> Default for EmbassyEcp<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> MbedtlsEcpMul for EmbassyEcp<C>
where
    C: EmbassyCurves,
{
    unsafe fn mul(
        &self,
        grp: &mut mbedtls_ecp_group,
        r: &mut mbedtls_ecp_point,
        m: &mbedtls_mpi,
        p: &mbedtls_ecp_point,
        f_rng: MbedtlsFRng,
        p_rng: *mut c_void,
        rs_ctx: *mut MbedtlsEcpRestartCtx,
    ) -> Result<(), MbedtlsError> {
        match C::mul(grp, r, m, p) {
            Some(result) => result,
            None => unsafe { ecp_mul_soft(grp, r, m, p, f_rng, p_rng, rs_ctx) },
        }
    }
}
