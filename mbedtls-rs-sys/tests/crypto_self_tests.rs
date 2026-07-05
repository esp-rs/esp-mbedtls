//! Host-side MbedTLS crypto self-tests.
//!
//! These matter most for the hooked (`*_ALT`) algorithms, where the
//! implementation behind the MbedTLS API is this crate's Rust code:
//! - The AES self-test runs the NIST KATs for ECB/CBC/CFB/OFB/CTR/XTS against
//!   the `hook::aes` module (RustCrypto fallback + the Rust cipher-mode
//!   implementations).
//! - The ECP self-test (and the CCM/GCM/CMAC ones, transitively through the
//!   AES block hooks) exercises the `hook::ecp` shims and their soft
//!   fallbacks.

use std::sync::Mutex;

use mbedtls_rs_sys::*;

/// The MbedTLS self-tests are not thread-safe (e.g. the ECP self-test
/// compares global operation counters that other concurrently-running ECP
/// users would skew), so serialize them.
static SERIAL: Mutex<()> = Mutex::new(());

fn run(name: &str, test: unsafe extern "C" fn(core::ffi::c_int) -> core::ffi::c_int) {
    let _guard = SERIAL.lock().unwrap();

    let ret = unsafe { test(1) };
    assert_eq!(ret, 0, "mbedtls {name} self-test failed with {ret}");
}

#[test]
fn aes() {
    run("AES", mbedtls_aes_self_test);
}

#[test]
fn ccm() {
    run("CCM", mbedtls_ccm_self_test);
}

#[test]
fn gcm() {
    run("GCM", mbedtls_gcm_self_test);
}

#[test]
fn cmac() {
    run("CMAC", mbedtls_cmac_self_test);
}

#[test]
fn ecp() {
    run("ECP", mbedtls_ecp_self_test);
}

#[test]
fn ecjpake() {
    run("ECJPAKE", mbedtls_ecjpake_self_test);
}

#[test]
fn sha256() {
    run("SHA-256", mbedtls_sha256_self_test);
}

#[test]
fn mpi() {
    run("MPI", mbedtls_mpi_self_test);
}
