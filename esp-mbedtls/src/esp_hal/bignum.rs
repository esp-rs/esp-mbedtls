#![allow(non_snake_case)]

use core::ffi::c_int;

use esp_hal::rsa::{operand_sizes, RsaModularExponentiation};

use crypto_bigint::*;

use esp_mbedtls_sys::bindings::*;

use crate::esp_hal::RSA_REF;

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
#[cfg(feature = "esp32c6")]
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
        let index = i as usize;

        if unsafe { X.private_p.add(index - 1).read() } != 0 {
            return index;
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
    match RSA_REF {
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
                        let mut mod_exp = RsaModularExponentiation::<
                            operand_sizes::Op256,
                            esp_hal::Blocking,
                        >::new(
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
                        let mut mod_exp = RsaModularExponentiation::<
                            operand_sizes::Op384,
                            esp_hal::Blocking,
                        >::new(
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
                        let mut mod_exp = RsaModularExponentiation::<
                            operand_sizes::Op512,
                            esp_hal::Blocking,
                        >::new(
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
                        let mut mod_exp = RsaModularExponentiation::<
                            operand_sizes::Op1024,
                            esp_hal::Blocking,
                        >::new(
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
                        let mut mod_exp = RsaModularExponentiation::<
                            operand_sizes::Op2048,
                            esp_hal::Blocking,
                        >::new(
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
                    #[cfg(not(any(feature = "esp32c3", feature = "esp32c6")))]
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
                        let mut mod_exp = RsaModularExponentiation::<
                            operand_sizes::Op4096,
                            esp_hal::Blocking,
                        >::new(
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
