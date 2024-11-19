//! Run crypto self tests to ensure their functionnality

use esp_mbedtls::Tls;

fn cycles() -> std::time::Instant {
    std::time::Instant::now()
}

fn main() {
    let mut tls = Tls::new();

    tls.set_debug(1);

    // | Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |
    // |----------------|-------------------|-------------------|---------------------------|
    // | SHA-1          |      3,390,785    |         896,889   |           3.78            |
    // | SHA-224        |      8,251,799    |         898,344   |           9.19            |
    // | SHA-256        |      8,237,932    |         901,709   |           9.14            |
    // | SHA-384        |     13,605,806    |         799,532   |           17.02           |
    // | SHA-512        |     13,588,104    |         801,556   |           16.95           |

    for test in enumset::EnumSet::all() {
        println!("Testing {:?}", test);

        let before = cycles();

        tls.self_test(test, true);

        println!("Took {:?}", before.elapsed());
    }

    // HW Crypto:
    // Testing RSA
    // INFO -   RSA key validation:
    // INFO - passed
    //   PKCS#1 encryption :
    // INFO - passed
    //   PKCS#1 decryption :
    // INFO - passed
    // INFO -   PKCS#1 data sign  :
    // INFO - passed
    //   PKCS#1 sig. verify:
    // INFO - passed
    // INFO - 10
    // INFO - pre_cal 16377170
    // INFO -   MPI test #1 (mul_mpi):
    // INFO - passed
    // INFO -   MPI test #2 (div_mpi):
    // INFO - passed
    // INFO -   MPI test #3 (exp_mod):
    // INFO - passed
    // INFO -   MPI test #4 (inv_mod):
    // INFO - passed
    // INFO -   MPI test #5 (simple gcd):
    // INFO - passed
    // INFO - 10
    // INFO - post_cal 17338357
    // Took 961187 cycles
    // Done

    // SW Crypto:
    // Testing RSA
    // INFO -   RSA key validation:
    // INFO - passed
    //   PKCS#1 encryption :
    // INFO - passed
    //   PKCS#1 decryption :
    // INFO - passed
    // INFO -   PKCS#1 data sign  :
    // INFO - passed
    //   PKCS#1 sig. verify:
    // INFO - passed
    // INFO - 10
    // INFO - pre_cal 19067376
    // INFO -   MPI test #1 (mul_mpi):
    // INFO - passed
    // INFO -   MPI test #2 (div_mpi):
    // INFO - passed
    // INFO -   MPI test #3 (exp_mod):
    // INFO - passed
    // INFO -   MPI test #4 (inv_mod):
    // INFO - passed
    // INFO -   MPI test #5 (simple gcd):
    // INFO - passed
    // INFO - 10
    // INFO - post_cal 20393146
    // Took 1325770 cycles
    // Done

    println!("Done");
}
