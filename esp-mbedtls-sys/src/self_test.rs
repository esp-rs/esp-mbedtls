use crate::{mbedtls_aes_self_test, mbedtls_md5_self_test, mbedtls_mpi_self_test, mbedtls_rsa_self_test, mbedtls_sha1_self_test, mbedtls_sha224_self_test, mbedtls_sha256_self_test, mbedtls_sha384_self_test, mbedtls_sha512_self_test};

/// An MbedTLS self-test type
#[derive(enumset::EnumSetType, Debug)]
pub enum MbedtlsSelfTest {
    Mpi,
    Rsa,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Aes,
    Md5,
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
                Self::Rsa => mbedtls_rsa_self_test(verbose),
                Self::Sha1 => mbedtls_sha1_self_test(verbose),
                Self::Sha224 => mbedtls_sha224_self_test(verbose),
                Self::Sha256 => mbedtls_sha256_self_test(verbose),
                Self::Sha384 => mbedtls_sha384_self_test(verbose),
                Self::Sha512 => mbedtls_sha512_self_test(verbose),
                Self::Aes => mbedtls_aes_self_test(verbose),
                Self::Md5 => mbedtls_md5_self_test(verbose),
            }
        };

        result != 0
    }
}

impl core::fmt::Display for MbedtlsSelfTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MbedtlsSelfTest::Mpi => write!(f, "MPI"),
            MbedtlsSelfTest::Rsa => write!(f, "RSA"),
            MbedtlsSelfTest::Sha1 => write!(f, "SHA1"),
            MbedtlsSelfTest::Sha224 => write!(f, "SHA224"),
            MbedtlsSelfTest::Sha256 => write!(f, "SHA256"),
            MbedtlsSelfTest::Sha384 => write!(f, "SHA384"),
            MbedtlsSelfTest::Sha512 => write!(f, "SHA512"),
            MbedtlsSelfTest::Aes => write!(f, "AES"),
            MbedtlsSelfTest::Md5 => write!(f, "MD5"),
        }
    }
}
