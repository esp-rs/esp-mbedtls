#![allow(non_snake_case)]

use crate::hal::prelude::nb;
#[cfg(feature = "esp32s3")]
use crate::hal::rsa::RsaModularMultiplication;
#[cfg(feature = "esp32s3")]
use crate::hal::rsa::RsaMultiplication;
use crate::hal::rsa::{operand_sizes, RsaModularExponentiation};

use crypto_bigint::*;

use esp_mbedtls_sys::bindings::*;
use esp_mbedtls_sys::c_types::*;

macro_rules! error_checked {
    ($block:expr) => {{
        let res = $block;
        if res != 0 {
            panic!("Non zero error {:?}", res);
        } else {
            // Do nothing for now
        }
    }};
}

#[cfg(feature = "esp32")]
const SOC_RSA_MAX_BIT_LEN: usize = 4096;
#[cfg(feature = "esp32c3")]
const SOC_RSA_MAX_BIT_LEN: usize = 3072;
#[cfg(feature = "esp32s2")]
const SOC_RSA_MAX_BIT_LEN: usize = 4096;
#[cfg(feature = "esp32s3")]
const SOC_RSA_MAX_BIT_LEN: usize = 4096;

/// Bad input parameters to function.
const MBEDTLS_ERR_MPI_BAD_INPUT_DATA: c_int = -0x0004;

/// Calculate the number of words used for a hardware operation.
///
/// For every chip except `esp32`, this will return `words`
/// For `esp32`, this will return the number of words rounded up to the 512 block count.
const fn calculate_hw_words(words: usize) -> usize {
    // Round up number of words to nearest
    // 512 bit (16 word) block count.
    #[cfg(feature = "esp32")]
    return (words + 0xF) & !0xF;
    #[cfg(not(feature = "esp32"))]
    words
}

/// Return the number of words actually used to represent an mpi number.
fn mpi_words(X: &mbedtls_mpi) -> usize {
    for i in (0..=X.private_n).rev() {
        if unsafe { X.private_p.add(i - 1).read() } != 0 {
            return i;
        }
    }
    0
}

#[inline]
fn copy_bytes<T>(src: *const T, dst: *mut T, count: usize)
where
    T: Copy,
{
    unsafe { core::ptr::copy_nonoverlapping(src, dst, count) };
}

fn compute_mprime(M: &mbedtls_mpi) -> u32 {
    let mut t: u64 = 1;
    let mut two_2_i_minus_1: u64 = 2; // 2^(i-1)
    let mut two_2_i: u64 = 4; // 2^i
    let n = unsafe { M.private_p.read() } as u64;

    for _ in 2..=32 {
        if n * t % two_2_i >= two_2_i_minus_1 {
            t += two_2_i_minus_1;
        }

        two_2_i_minus_1 <<= 1;
        two_2_i <<= 1;
    }

    (u32::MAX as u64 - t + 1) as u32
}

/// Calculate Rinv = RR^2 mod M, where:
///
///  R = b^n where b = 2^32, n=num_words,
///  R = 2^N (where N=num_bits)
///  RR = R^2 = 2^(2*N) (where N=num_bits=num_words*32)
///
/// This calculation is computationally expensive (mbedtls_mpi_mod_mpi)
/// so caller should cache the result where possible.
///
/// DO NOT call this function while holding esp_mpi_enable_hardware_hw_op().
fn calculate_rinv(prec_RR: &mut mbedtls_mpi, M: &mbedtls_mpi, num_words: usize) -> c_int {
    let ret = 0;
    let num_bits = num_words * 32;
    let mut RR = mbedtls_mpi {
        private_s: 0,
        private_n: 0,
        private_p: core::ptr::null_mut(),
    };

    unsafe {
        mbedtls_mpi_init(&mut RR);
        error_checked!(mbedtls_mpi_set_bit(&mut RR, num_bits * 2, 1));
        error_checked!(mbedtls_mpi_mod_mpi(prec_RR, &RR, M));
        mbedtls_mpi_free(&mut RR);
    }

    ret
}

/// Z = X ^ Y mod M
#[no_mangle]
pub unsafe extern "C" fn mbedtls_mpi_exp_mod(
    Z: *mut mbedtls_mpi,
    X: &mbedtls_mpi,
    Y: &mbedtls_mpi,
    M: &mbedtls_mpi,
    prec_RR: *mut mbedtls_mpi,
) -> c_int {
    match crate::RSA_REF {
        None => return unsafe { mbedtls_mpi_exp_mod_soft(Z, X, Y, M, prec_RR) },
        Some(ref mut rsa) => {
            let x_words = mpi_words(X);
            let y_words = mpi_words(Y);
            let m_words = mpi_words(M);

            // All numbers must be the lame length, so choose longest number as
            // cardinal length of operation
            let num_words =
                calculate_hw_words(core::cmp::max(m_words, core::cmp::max(x_words, y_words)));

            if num_words * 32 > SOC_RSA_MAX_BIT_LEN {
                return unsafe { mbedtls_mpi_exp_mod_soft(Z, X, Y, M, prec_RR) };
            }

            if M.private_p.is_null() {
                todo!("Handle this null");
            }
            unsafe {
                if mbedtls_mpi_cmp_int(M, 0) <= 0 || M.private_p.read() & 1 == 0 {
                    return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
                }

                if mbedtls_mpi_cmp_int(Y, 0) < 0 {
                    return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
                }

                if mbedtls_mpi_cmp_int(Y, 0) == 0 {
                    return mbedtls_mpi_lset(Z, 1);
                }
            }

            let mut rinv_new = mbedtls_mpi {
                private_s: 0,
                private_n: 0,
                private_p: core::ptr::null_mut(),
            };

            // Determine RR pointer, either _RR for cached value or local RR_new
            let rinv: &mut mbedtls_mpi = if prec_RR.is_null() {
                unsafe { mbedtls_mpi_init(&mut rinv_new) };
                &mut rinv_new
            } else {
                // This is safe since we check above if pointer is not null
                unsafe { &mut *prec_RR }
            };

            if rinv.private_p.is_null() {
                calculate_rinv(rinv, M, num_words);
            }

            unsafe {
                error_checked!(mbedtls_mpi_grow(Z, m_words));
            }

            nb::block!(rsa.ready()).unwrap();
            rsa.enable_disable_constant_time_acceleration(true);
            rsa.enable_disable_search_acceleration(true);
            unsafe {
                match num_words {
                    U256::LIMBS => {
                        const OP_SIZE: usize = U256::LIMBS;
                        let mut base = [0u32; OP_SIZE];
                        let mut exponent = [0u32; OP_SIZE];
                        let mut modulus = [0u32; OP_SIZE];
                        let mut r = [0u32; OP_SIZE];
                        copy_bytes(X.private_p, base.as_mut_ptr(), x_words);
                        copy_bytes(Y.private_p, exponent.as_mut_ptr(), y_words);
                        copy_bytes(M.private_p, modulus.as_mut_ptr(), m_words);
                        copy_bytes(rinv.private_p, r.as_mut_ptr(), mpi_words(rinv));
                        let mut mod_exp = RsaModularExponentiation::<operand_sizes::Op256>::new(
                            rsa,
                            &exponent,         // exponent (Y) Y_MEM
                            &modulus,          // modulus (M)  M_MEM
                            compute_mprime(M), // mprime
                        );
                        let mut out = [0u32; OP_SIZE];
                        mod_exp.start_exponentiation(
                            &base, // X_MEM
                            &r,    // Z_MEM
                        );

                        mod_exp.read_results(&mut out);
                        copy_bytes(out.as_ptr(), (*Z).private_p, m_words);
                    }
                    U384::LIMBS => {
                        const OP_SIZE: usize = U384::LIMBS;
                        let mut base = [0u32; OP_SIZE];
                        let mut exponent = [0u32; OP_SIZE];
                        let mut modulus = [0u32; OP_SIZE];
                        let mut r = [0u32; OP_SIZE];
                        copy_bytes(X.private_p, base.as_mut_ptr(), x_words);
                        copy_bytes(Y.private_p, exponent.as_mut_ptr(), y_words);
                        copy_bytes(M.private_p, modulus.as_mut_ptr(), m_words);
                        copy_bytes(rinv.private_p, r.as_mut_ptr(), mpi_words(rinv));
                        let mut mod_exp = RsaModularExponentiation::<operand_sizes::Op384>::new(
                            rsa,
                            &exponent,         // exponent (Y) Y_MEM
                            &modulus,          // modulus (M)  M_MEM
                            compute_mprime(M), // mprime
                        );
                        let mut out = [0u32; OP_SIZE];
                        mod_exp.start_exponentiation(
                            &base, // X_MEM
                            &r,    // Z_MEM
                        );

                        mod_exp.read_results(&mut out);
                        copy_bytes(out.as_ptr(), (*Z).private_p, m_words);
                    }
                    U512::LIMBS => {
                        const OP_SIZE: usize = U512::LIMBS;
                        let mut base = [0u32; OP_SIZE];
                        let mut exponent = [0u32; OP_SIZE];
                        let mut modulus = [0u32; OP_SIZE];
                        let mut r = [0u32; OP_SIZE];
                        copy_bytes(X.private_p, base.as_mut_ptr(), x_words);
                        copy_bytes(Y.private_p, exponent.as_mut_ptr(), y_words);
                        copy_bytes(M.private_p, modulus.as_mut_ptr(), m_words);
                        copy_bytes(rinv.private_p, r.as_mut_ptr(), mpi_words(rinv));
                        let mut mod_exp = RsaModularExponentiation::<operand_sizes::Op512>::new(
                            rsa,
                            &exponent,         // exponent (Y) Y_MEM
                            &modulus,          // modulus (M)  M_MEM
                            compute_mprime(M), // mprime
                        );
                        let mut out = [0u32; OP_SIZE];
                        mod_exp.start_exponentiation(
                            &base, // X_MEM
                            &r,    // Z_MEM
                        );

                        mod_exp.read_results(&mut out);
                        copy_bytes(out.as_ptr(), (*Z).private_p, m_words);
                    }
                    U1024::LIMBS => {
                        const OP_SIZE: usize = U1024::LIMBS;
                        let mut base = [0u32; OP_SIZE];
                        let mut exponent = [0u32; OP_SIZE];
                        let mut modulus = [0u32; OP_SIZE];
                        let mut r = [0u32; OP_SIZE];
                        copy_bytes(X.private_p, base.as_mut_ptr(), x_words);
                        copy_bytes(Y.private_p, exponent.as_mut_ptr(), y_words);
                        copy_bytes(M.private_p, modulus.as_mut_ptr(), m_words);
                        copy_bytes(rinv.private_p, r.as_mut_ptr(), mpi_words(rinv));
                        let mut mod_exp = RsaModularExponentiation::<operand_sizes::Op1024>::new(
                            rsa,
                            &exponent,         // exponent (Y) Y_MEM
                            &modulus,          // modulus (M)  M_MEM
                            compute_mprime(M), // mprime
                        );
                        let mut out = [0u32; OP_SIZE];
                        mod_exp.start_exponentiation(
                            &base, // X_MEM
                            &r,    // Z_MEM
                        );

                        mod_exp.read_results(&mut out);
                        copy_bytes(out.as_ptr(), (*Z).private_p, m_words);
                    }
                    U2048::LIMBS => {
                        const OP_SIZE: usize = U2048::LIMBS;
                        let mut base = [0u32; OP_SIZE];
                        let mut exponent = [0u32; OP_SIZE];
                        let mut modulus = [0u32; OP_SIZE];
                        let mut r = [0u32; OP_SIZE];
                        copy_bytes(X.private_p, base.as_mut_ptr(), x_words);
                        copy_bytes(Y.private_p, exponent.as_mut_ptr(), y_words);
                        copy_bytes(M.private_p, modulus.as_mut_ptr(), m_words);
                        copy_bytes(rinv.private_p, r.as_mut_ptr(), mpi_words(rinv));
                        let mut mod_exp = RsaModularExponentiation::<operand_sizes::Op2048>::new(
                            rsa,
                            &exponent,         // exponent (Y) Y_MEM
                            &modulus,          // modulus (M)  M_MEM
                            compute_mprime(M), // mprime
                        );
                        let mut out = [0u32; OP_SIZE];
                        mod_exp.start_exponentiation(
                            &base, // X_MEM
                            &r,    // Z_MEM
                        );

                        mod_exp.read_results(&mut out);
                        copy_bytes(out.as_ptr(), (*Z).private_p, m_words);
                    }
                    #[cfg(not(feature = "esp32c3"))]
                    U4096::LIMBS => {
                        const OP_SIZE: usize = U4096::LIMBS;
                        let mut base = [0u32; OP_SIZE];
                        let mut exponent = [0u32; OP_SIZE];
                        let mut modulus = [0u32; OP_SIZE];
                        let mut r = [0u32; OP_SIZE];
                        copy_bytes(X.private_p, base.as_mut_ptr(), x_words);
                        copy_bytes(Y.private_p, exponent.as_mut_ptr(), y_words);
                        copy_bytes(M.private_p, modulus.as_mut_ptr(), m_words);
                        copy_bytes(rinv.private_p, r.as_mut_ptr(), mpi_words(rinv));
                        let mut mod_exp = RsaModularExponentiation::<operand_sizes::Op4096>::new(
                            rsa,
                            &exponent,         // exponent (Y) Y_MEM
                            &modulus,          // modulus (M)  M_MEM
                            compute_mprime(M), // mprime
                        );
                        let mut out = [0u32; OP_SIZE];
                        mod_exp.start_exponentiation(
                            &base, // X_MEM
                            &r,    // Z_MEM
                        );

                        mod_exp.read_results(&mut out);
                        copy_bytes(out.as_ptr(), (*Z).private_p, m_words);
                    }
                    op => {
                        todo!("Implement operand: {}", op);
                    }
                }
            }

            assert_eq!(X.private_s, 1);
            // Compensate for negative X
            if X.private_s == -1 && unsafe { Y.private_p.read() & 1 } != 0 {
                unsafe { (*Z).private_s = -1 };
                unsafe { error_checked!(mbedtls_mpi_add_mpi(Z, M, Z)) };
            } else {
                unsafe { (*Z).private_s = 1 };
            }

            if prec_RR.is_null() {
                unsafe { mbedtls_mpi_free(&mut rinv_new) };
            }
            0
        }
    }
}

#[cfg(feature = "esp32s3")]
#[inline]
const fn bits_to_words(bits: usize) -> usize {
    (bits + 31) / 32
}

/// Deal with the case when X & Y are too long for the hardware unit, by splitting one operand
/// into two halves.
///
/// Y must be the longer operand
///
/// Slice Y into Yp, Ypp such that:
/// Yp = lower 'b' bits of Y
/// Ypp = upper 'b' bits of Y (right shifted)
///
/// Such that
/// Z = X * Y
/// Z = X * (Yp + Ypp<<b)
/// Z = (X * Yp) + (X * Ypp<<b)
///
/// Note that this function may recurse multiple times, if both X & Y
/// are too long for the hardware multiplication unit.
#[cfg(feature = "esp32s3")]
fn mpi_mult_mpi_overlong(
    Z: &mut mbedtls_mpi,
    X: &mbedtls_mpi,
    Y: &mbedtls_mpi,
    y_words: usize,
) -> c_int {
    let mut ret = 0;

    // Rather than slicing in two on bits we slice on limbs (32 bit words)
    let words_slice: usize = y_words / 2;

    // Holds the lower bits of Y (declared to reuse Y's array contents to save on copying)
    let yp: mbedtls_mpi = mbedtls_mpi {
        private_p: (*Y).private_p,
        private_n: words_slice,
        private_s: (*Y).private_s,
    };

    // Holds the upper bits of Y, right shifted (also reuse Y's array contents)
    let ypp: mbedtls_mpi = mbedtls_mpi {
        private_p: unsafe { Y.private_p.add(words_slice) },
        private_n: y_words - words_slice,
        private_s: (*Y).private_s,
    };

    let mut x_temp = mbedtls_mpi {
        private_s: 0,
        private_n: 0,
        private_p: core::ptr::null_mut(),
    };

    unsafe {
        mbedtls_mpi_init(&mut x_temp);

        error_checked!(mbedtls_mpi_mul_mpi(&mut x_temp, X, &yp));

        // Z = b_upper * B
        error_checked!(mbedtls_mpi_mul_mpi(Z, X, &ypp));

        // X = X << b
        error_checked!(mbedtls_mpi_shift_l(Z, words_slice * 32));

        // X += Xtemp
        error_checked!(mbedtls_mpi_add_mpi(Z, Z, &x_temp));

        mbedtls_mpi_free(&mut x_temp);
    }

    ret
}

#[cfg(feature = "esp32s3")]
unsafe fn mbedtls_mpi_mult_mpi_failover_mod_mult(
    Z: &mut mbedtls_mpi,
    X: &mbedtls_mpi,
    Y: &mbedtls_mpi,
    z_words: usize,
) -> c_int {
    match crate::RSA_REF {
        None => unimplemented!("mbedtls_mpi_mult_mpi_failover_mod_mult"),
        Some(ref mut rsa) => {
            let mut ret = 0;

            let x_bits = unsafe { mbedtls_mpi_bitlen(X) };
            let y_bits = unsafe { mbedtls_mpi_bitlen(Y) };
            // TODO: We can have the words value from the mpi
            let x_words = bits_to_words(x_bits);
            let y_words = bits_to_words(y_bits);
            let hw_words = calculate_hw_words(z_words);

            nb::block!(rsa.ready()).unwrap();
            match hw_words {
                U2112::LIMBS => {
                    const OP_SIZE: usize = U2112::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE];
                    // RINV
                    let mut rinv = [0u32; OP_SIZE];
                    rinv[0] = 1;
                    // Modulus
                    let mut modulus = [0u32; OP_SIZE];
                    for i in 0..hw_words {
                        modulus[i] = u32::MAX;
                    }

                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);

                    let mut calc = RsaModularMultiplication::<operand_sizes::Op2112>::new(
                        rsa, &operand_x, // operand_a (X) X_MEM
                        &operand_y, // operand_b (Y) Y_MEM
                        &modulus,   // modulus   (M) M_MEM
                        1,          // mprime
                    );
                    calc.start_modular_multiplication(&rinv); // r Z_MEM

                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, hw_words);
                }
                U2560::LIMBS => {
                    const OP_SIZE: usize = U2560::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE];
                    // RINV
                    let mut rinv = [0u32; OP_SIZE];
                    rinv[0] = 1;
                    // Modulus
                    let mut modulus = [0u32; OP_SIZE];
                    for i in 0..hw_words {
                        modulus[i] = u32::MAX;
                    }

                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);

                    let mut calc = RsaModularMultiplication::<operand_sizes::Op2560>::new(
                        rsa, &operand_x, // operand_a (X) X_MEM
                        &operand_y, // operand_b (Y) Y_MEM
                        &modulus,   // modulus   (M) M_MEM
                        1,          // mprime
                    );
                    calc.start_modular_multiplication(&rinv); // r Z_MEM

                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, hw_words);
                }
                op => {
                    todo!("implement mod multi op {}", op);
                }
            }

            // Grow X to result size early, avoid interim allocations
            unsafe {
                error_checked!(mbedtls_mpi_grow(Z, hw_words));
            }

            Z.private_s = X.private_s * Y.private_s;

            // Relevant: https://github.com/espressif/esp-idf/issues/11850
            //
            // If z_words < mpi_words(Z) (the actual words taken by the MPI result),
            // the assert fails due to unsigned arithmetic - most likely hardware
            // peripheral has produced an incorrect result for MPI operation.
            // This can happen if data fed to the peripheral register was incorrect.
            //
            // z_words is calculated as the worst-case possible size of the result
            // MPI Z. The difference between z_words and the actual words taken by
            // the MPI result (mpi_words(Z)) can be a maximum of 1 word.
            // The value z_bits (actual bits taken by the MPI result) is calculated
            // as x_bits + y_bits bits, however, in some cases, z_bits can be
            // x_bits + y_bits - 1 bits (see example below).
            // 0b1111 * 0b1111 = 0b11100001 -> 8 bits
            // 0b1000 * 0b1000 = 0b01000000 -> 7 bits.
            // The code rounds up to the nearest word size, so the maximum difference
            // could be of only 1 word. The assert handles this.
            assert!(z_words - mpi_words(Z) <= 1);

            ret
        }
    }
}

// Baseline multiplication: Z = X * Y  (HAC 14.12)
#[cfg(feature = "esp32s3")]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_mpi_mul_mpi(
    Z: &mut mbedtls_mpi,
    X: &mbedtls_mpi,
    Y: &mbedtls_mpi,
) -> c_int {
    match crate::RSA_REF {
        None => unimplemented!("mbedtls_mpi_mul_mpi"),
        Some(ref mut rsa) => {
            let mut ret = 0;

            let x_bits = unsafe { mbedtls_mpi_bitlen(X) };
            let y_bits = unsafe { mbedtls_mpi_bitlen(Y) };
            // TODO: We can have the words value from the mpi
            let x_words = bits_to_words(x_bits);
            let y_words = bits_to_words(y_bits);
            let z_words = bits_to_words(x_bits + y_bits);
            let hw_words = calculate_hw_words(core::cmp::max(x_words, y_words));

            // Short-circuit eval if either argument is 0 or 1.
            //
            // This is needed as the mpi modular division
            // argument will sometimes call in here when one
            // argument is too large for the hardware unit, but other
            // argument is zero or one.
            if x_bits == 0 || y_bits == 0 {
                unsafe { mbedtls_mpi_lset(Z, 0) };
                return 0;
            }
            if x_bits == 1 {
                ret = unsafe { mbedtls_mpi_copy(Z, Y) };
                (*Z).private_s *= (*X).private_s;
                return ret;
            }
            if y_bits == 1 {
                ret = unsafe { mbedtls_mpi_copy(Z, X) };
                (*Z).private_s *= (*Y).private_s;
                return ret;
            }

            // Grow Z to result size early, avoid interim allocations
            unsafe {
                error_checked!(mbedtls_mpi_grow(Z, z_words));
            }

            // If either factor is over 2048 bits, we can't use the standard hardware multiplier
            // (it assumes result is double longest factor, and result is max 4096 bits.)
            //
            // However, we can fail over to mod_mult for up to 4096 bits of result (modulo
            // multiplication doesn't have the same restriction, so result is simply the
            // number of bits in X plus number of bits in in Y.)

            if hw_words * 32 > SOC_RSA_MAX_BIT_LEN / 2 {
                if z_words * 32 <= SOC_RSA_MAX_BIT_LEN {
                    // Note: It's possible to use mpi_mult_mpi_overlong
                    // for this case as well, but it's very slightly
                    // slower and requires a memory allocation.
                    return mbedtls_mpi_mult_mpi_failover_mod_mult(Z, X, Y, z_words);
                } else {
                    // Still too long for the hardware unit...
                    if y_words > x_words {
                        return mpi_mult_mpi_overlong(Z, X, Y, y_words);
                    } else {
                        return mpi_mult_mpi_overlong(Z, Y, X, x_words);
                    }
                }
            }

            // Otherwise, we can use the (faster) multiply hardware unit
            nb::block!(rsa.ready()).unwrap();
            match hw_words * 4 {
                U64::BYTES => {
                    const OP_SIZE: usize = U64::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op64>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U128::BYTES => {
                    const OP_SIZE: usize = U128::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op128>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U256::BYTES => {
                    const OP_SIZE: usize = U256::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op256>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U384::BYTES => {
                    const OP_SIZE: usize = U384::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op384>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U512::BYTES => {
                    const OP_SIZE: usize = U512::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op512>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                // TODO: Is it normal to have hw_words * 4 not being a multiple of 32?
                68 => {
                    const OP_SIZE: usize = U576::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op576>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U1024::BYTES => {
                    const OP_SIZE: usize = U1024::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op1024>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                // TODO: Is it normal to have hw_words * 4 not being a multiple of 32?
                132 | U1088::BYTES => {
                    const OP_SIZE: usize = U1088::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op1088>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U1152::BYTES => {
                    const OP_SIZE: usize = U1152::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op1152>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), Z.private_p, z_words);
                }
                U2048::BYTES => {
                    const OP_SIZE: usize = U2048::LIMBS;
                    let mut operand_x = [0u32; OP_SIZE];
                    let mut operand_y = [0u32; OP_SIZE];
                    let mut out = [0u32; OP_SIZE * 2];
                    copy_bytes(X.private_p, operand_x.as_mut_ptr(), x_words);
                    copy_bytes(Y.private_p, operand_y.as_mut_ptr(), y_words);
                    let mut calc = RsaMultiplication::<operand_sizes::Op2048>::new(rsa, &operand_x);
                    calc.start_multiplication(&operand_y);
                    calc.read_results(&mut out);
                    copy_bytes(out.as_ptr(), (*Z).private_p, z_words);
                }
                op => {
                    todo!("Implement operand: {}", op);
                }
            }
            Z.private_s = X.private_s * Y.private_s;

            ret
        }
    }
}

#[cfg(feature = "esp32s3")]
#[no_mangle]
pub extern "C" fn mbedtls_mpi_mul_int(
    X: &mut mbedtls_mpi,
    A: &mbedtls_mpi,
    mut b: mbedtls_mpi_uint,
) -> c_int {
    let B: mbedtls_mpi = mbedtls_mpi {
        private_s: 1,
        private_n: 1,
        private_p: &mut b,
    };

    unsafe { mbedtls_mpi_mul_mpi(X, A, &B) }
}
