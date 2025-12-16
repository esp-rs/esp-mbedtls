#![no_std]

use core::cell::RefCell;
use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use critical_section::Mutex;

use embedded_io::{Error, ErrorKind, ErrorType};

use embedded_io::Read;
use embedded_io::Write;

use esp_mbedtls_sys::bindings::*;

use rand_core::CryptoRng;

pub(crate) mod fmt;

#[cfg(feature = "edge-nal")]
mod edge_nal;

#[cfg(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32c6",
    feature = "esp32s2",
    feature = "esp32s3"
))]
mod esp_hal;

/// Re-export of the `embedded-io` crate so that users don't have to explicitly depend on it
/// to use e.g. `write_all` or `read_exact`.
pub mod io {
    pub use embedded_io::*;
}

macro_rules! err {
    ($block:expr) => {{
        let res = $block;
        if res != 0 {
            Err(TlsError::MbedTlsError(res))
        } else {
            Ok(())
        }
    }};
}

/// Error type for TLS operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// A `Tls` instance has already been created
    AlreadyCreated,
    /// An unknown error occurred
    Unknown,
    /// Out of heap
    OutOfMemory,
    /// MBedTLS error
    MbedTlsError(i32),
    /// End of stream
    Eof,
    /// X509 certificate missing null terminator
    X509MissingNullTerminator,
    /// The X509 is in an unexpected format (PEM instead of DER and vice-versa)
    InvalidFormat,
    /// The client has given no certificates for the request
    NoClientCertificate,
    /// IO error
    Io(ErrorKind),
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyCreated => write!(f, "TLS already created"),
            Self::Unknown => write!(f, "Unknown error"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::MbedTlsError(e) => write!(f, "MbedTLS error: {e}"),
            Self::Eof => write!(f, "End of stream"),
            Self::X509MissingNullTerminator => {
                write!(f, "X509 certificate missing null terminator")
            }
            Self::InvalidFormat => write!(
                f,
                "The X509 is in an unexpected format (PEM instead of DER and vice-versa)"
            ),
            Self::NoClientCertificate => write!(f, "No client certificate"),
            Self::Io(e) => write!(f, "IO error: {e:?}"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TlsError {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::AlreadyCreated => defmt::write!(f, "TLS already created"),
            Self::Unknown => defmt::write!(f, "Unknown error"),
            Self::OutOfMemory => defmt::write!(f, "Out of memory"),
            Self::MbedTlsError(e) => defmt::write!(f, "MbedTLS error: {}", e),
            Self::Eof => defmt::write!(f, "End of stream"),
            Self::X509MissingNullTerminator => {
                defmt::write!(f, "X509 certificate missing null terminator")
            }
            Self::InvalidFormat => defmt::write!(
                f,
                "The X509 is in an unexpected format (PEM instead of DER and vice-versa)"
            ),
            Self::NoClientCertificate => defmt::write!(f, "No client certificate"),
            Self::Io(e) => defmt::write!(f, "IO error: {:?}", debug2format!(e)),
        }
    }
}

impl core::error::Error for TlsError {}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(e) => *e,
            _ => embedded_io::ErrorKind::Other,
        }
    }
}

/// A TLS self-test type
#[derive(enumset::EnumSetType, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsTest {
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

impl core::fmt::Display for TlsTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlsTest::Mpi => write!(f, "MPI"),
            TlsTest::Rsa => write!(f, "RSA"),
            TlsTest::Sha1 => write!(f, "SHA1"),
            TlsTest::Sha224 => write!(f, "SHA224"),
            TlsTest::Sha256 => write!(f, "SHA256"),
            TlsTest::Sha384 => write!(f, "SHA384"),
            TlsTest::Sha512 => write!(f, "SHA512"),
            TlsTest::Aes => write!(f, "AES"),
            TlsTest::Md5 => write!(f, "MD5"),
        }
    }
}

static TLS_RNG: Mutex<RefCell<Option<&mut (dyn CryptoRng + Send)>>> =
    Mutex::new(RefCell::new(None));

/// A TLS instance
///
/// Represents an instance of the MbedTLS library.
/// Only one such instance can be active at any point in time.
pub struct Tls<'d>(PhantomData<&'d mut ()>);

impl<'d> Tls<'d> {
    /// Create a new instance of the `Tls` type.
    ///
    /// Note that there could be only one active `Tls` instance at any point in time,
    /// and the function will return an error if there is already an active instance.
    #[cfg(not(any(
        feature = "esp32",
        feature = "esp32c3",
        feature = "esp32c6",
        feature = "esp32s2",
        feature = "esp32s3"
    )))]
    pub fn new(rng: &'d mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        Self::create(rng)
    }

    pub(crate) fn create(rng: &'d mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        critical_section::with(|cs| {
            let created = TLS_RNG.borrow(cs).borrow().is_some();

            if created {
                return Err(TlsError::AlreadyCreated);
            }

            *TLS_RNG.borrow(cs).borrow_mut() = Some(unsafe {
                core::mem::transmute::<
                    &'d mut (dyn CryptoRng + Send),
                    &'static mut (dyn CryptoRng + Send),
                >(rng)
            });

            Ok(Self(PhantomData))
        })
    }

    pub(crate) fn release(&mut self) {
        critical_section::with(|cs| {
            *TLS_RNG.borrow(cs).borrow_mut() = None;
        });
    }

    /// Set the MbedTLS debug level (0 - 5)
    #[allow(unused)]
    pub fn set_debug(&mut self, level: u32) {
        #[cfg(not(target_os = "espidf"))]
        unsafe {
            mbedtls_debug_set_threshold(level as c_int);
        }
    }

    /// Run a self-test on the MbedTLS library
    ///
    /// # Arguments
    ///
    /// * `test` - The test to run
    /// * `verbose` - Whether to run the test in verbose mode
    pub fn self_test(&mut self, test: TlsTest, verbose: bool) -> bool {
        let verbose = verbose as _;

        let result = unsafe {
            match test {
                TlsTest::Mpi => mbedtls_mpi_self_test(verbose),
                TlsTest::Rsa => mbedtls_rsa_self_test(verbose),
                TlsTest::Sha1 => mbedtls_sha1_self_test(verbose),
                TlsTest::Sha224 => mbedtls_sha224_self_test(verbose),
                TlsTest::Sha256 => mbedtls_sha256_self_test(verbose),
                TlsTest::Sha384 => mbedtls_sha384_self_test(verbose),
                TlsTest::Sha512 => mbedtls_sha512_self_test(verbose),
                TlsTest::Aes => mbedtls_aes_self_test(verbose),
                TlsTest::Md5 => mbedtls_md5_self_test(verbose),
            }
        };

        result != 0
    }

    /// Get a reference to the `Tls` instance
    ///
    /// Each `Session` needs a reference to (the) active `Tls` instance
    /// throughout its lifetime.
    pub fn reference(&self) -> TlsReference<'_> {
        TlsReference(PhantomData)
    }
}

#[cfg(not(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32c6",
    feature = "esp32s2",
    feature = "esp32s3"
)))]
impl<'d> Drop for Tls<'d> {
    fn drop(&mut self) {
        self.release();
    }
}

/// A reference to (the) active `Tls` instance
///
/// Used instead of just `&'a Tls` so that the invariant `'d` lifetime of the `Tls` instance
/// is not exposed in the `Session` type.
#[allow(unused)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsReference<'a>(PhantomData<&'a ()>);

/// Format type for [X509]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CertificateFormat {
    PEM,
    DER,
}

/// Holds a X509 certificate
///
/// # Examples
/// Initialize with a PEM certificate
/// ```
/// const CERTIFICATE: &[u8] = include_bytes!("certificate.pem");
/// let cert = X509::pem(CERTIFICATE).unwrap();
/// ```
///
/// Initialize with a DER certificate
/// ```
/// const CERTIFICATE: &[u8] = include_bytes!("certificate.der");
/// let cert = X509::der(CERTIFICATE);
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct X509<'a> {
    bytes: &'a [u8],
    format: CertificateFormat,
}

impl<'a> X509<'a> {
    /// Reads certificate in pem format from bytes
    ///
    /// # Error
    /// This function returns [TlsError::X509MissingNullTerminator] if the certificate
    /// doesn't end with a null-byte.
    pub fn pem(bytes: &'a [u8]) -> Result<Self, TlsError> {
        if let Some(len) = X509::get_null(bytes) {
            // Get a slice of only the certificate bytes including the \0
            let bytes = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), len + 1) };
            Ok(Self {
                bytes,
                format: CertificateFormat::PEM,
            })
        } else {
            Err(TlsError::X509MissingNullTerminator)
        }
    }

    /// Reads certificate in der format from bytes
    ///
    /// *Note*: This function assumes that the size of the size is the exact
    /// length of the certificate
    pub fn der(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            format: CertificateFormat::DER,
        }
    }

    /// Returns the bytes of the certificate
    pub fn data(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the encoding format of a certificate
    pub fn format(&self) -> CertificateFormat {
        self.format
    }

    /// Returns the length of the certificate
    pub(crate) fn len(&self) -> usize {
        self.data().len()
    }

    /// Returns a pointer to the data for parsing
    pub(crate) fn as_ptr(&self) -> *const c_uchar {
        self.data().as_ptr().cast()
    }

    /// Gets the first null byte in a slice
    fn get_null(bytes: &[u8]) -> Option<usize> {
        bytes.iter().position(|&byte| byte == 0)
    }
}

/// A X509 certificate or certificate chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Certificate<'d> {
    crt: MRc<mbedtls_x509_crt>,
    _t: PhantomData<&'d ()>,
}

impl Certificate<'static> {
    /// Parse an X509 certificate into RAM by making a copy
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in PEM or DER format
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// certificate in a PEM format, and vice-versa.
    pub fn new(certificate: X509<'_>) -> Result<Self, TlsError> {
        let crt = MRc::new()?;

        match certificate.format {
            CertificateFormat::PEM => err!(unsafe {
                mbedtls_x509_crt_parse(
                    &*crt as *const _ as *mut _,
                    certificate.as_ptr(),
                    certificate.len(),
                )
            }),
            CertificateFormat::DER => err!(unsafe {
                mbedtls_x509_crt_parse_der(
                    &*crt as *const _ as *mut _,
                    certificate.as_ptr(),
                    certificate.len(),
                )
            }),
        }
        .map_err(|err| {
            if matches!(err, TlsError::MbedTlsError(-8576)) {
                TlsError::InvalidFormat
            } else {
                err
            }
        })?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

impl<'d> Certificate<'d> {
    /// Parse an X509 certificate without making a copy in RAM. This requires that the underlying data
    /// lives for the lifetime of the certificate.
    /// Note: This is currently only supported for DER encoded certificates
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in DER format only
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing.
    /// [TlsError::InvalidFormat] will be returned if a PEM encoded certificate is passed.
    pub fn new_no_copy(certificate: X509<'d>) -> Result<Self, TlsError> {
        // Currently no copy is only supported by DER certificates
        if matches!(certificate.format(), CertificateFormat::PEM) {
            return Err(TlsError::InvalidFormat);
        }

        let crt = MRc::new()?;

        err!(unsafe {
            mbedtls_x509_crt_parse_der_nocopy(
                &*crt as *const _ as *mut _,
                certificate.as_ptr(),
                certificate.len(),
            )
        })
        .map_err(|err| {
            if matches!(err, TlsError::MbedTlsError(-8576)) {
                TlsError::InvalidFormat
            } else {
                err
            }
        })?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

/// A private key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrivateKey(MRc<mbedtls_pk_context>);

impl PrivateKey {
    /// Parse an X509 private key into RAM and returns a wrapped pointer if successful.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The X509 private key in DER or PEM format
    /// * `password` - The optional password if the private key is password protected
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// private key in a PEM format, and vice-versa.
    pub fn new(private_key: X509<'_>, password: Option<&str>) -> Result<Self, TlsError> {
        let pk = MRc::new()?;

        let (password_ptr, password_len) = if let Some(password) = password {
            (password.as_ptr(), password.len())
        } else {
            (core::ptr::null(), 0)
        };

        err!(unsafe {
            mbedtls_pk_parse_key(
                &*pk as *const _ as *mut _,
                private_key.as_ptr(),
                private_key.len(),
                password_ptr,
                password_len,
                None,
                core::ptr::null_mut(),
            )
        })?;

        Ok(Self(pk))
    }
}

/// The minimum TLS version that will be supported by a particular `Session` instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsVersion {
    /// TLS 1.2
    Tls1_2,
    /// TLS 1.3
    Tls1_3,
}

impl TlsVersion {
    fn mbed_tls_version(&self) -> u32 {
        match self {
            TlsVersion::Tls1_2 => 0x303,
            TlsVersion::Tls1_3 => 0x304,
        }
    }
}

/// Certificate verification mode used for a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AuthMode {
    /// Peer certificate is not checked (default on server) (insecure on client)
    None,
    /// Peer certificate is checked, however the handshake continues even if verification failed;
    /// [mbedtls_ssl_get_verify_result()] can be called after the handshake is complete.
    Optional,
    /// Peer *must* present a valid certificate, handshake is aborted if verification failed. (default on client)
    Required,
    /// Used only for sni_authmode
    Unset,
}

impl AuthMode {
    fn mbedtls_authmode(&self) -> i32 {
        (match self {
            AuthMode::None => MBEDTLS_SSL_VERIFY_NONE,
            AuthMode::Optional => MBEDTLS_SSL_VERIFY_OPTIONAL,
            AuthMode::Required => MBEDTLS_SSL_VERIFY_REQUIRED,
            AuthMode::Unset => MBEDTLS_SSL_VERIFY_UNSET,
        }) as i32
    }
}

/// The credentials (certificate and private key)
/// used for client or server authentication
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Credentials<'a> {
    /// Certificate (chain)
    certificate: Certificate<'a>,
    /// Private key paired with the certificate.
    private_key: PrivateKey,
}

/// Configuration for a TLS session
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientSessionConfig<'a> {
    /// Trusted CA (Certificate Authority) chain to be used for certificate
    /// verification during the SSL/TLS handshake.
    ///
    /// The CA chain should contain the trusted CA certificates
    /// that will be used to verify the client's certificate by the server during the handshake.
    pub ca_chain: Option<Certificate<'a>>,
    /// Optional client credentials used for authenticating the client to the server
    pub creds: Option<Credentials<'a>>,
    /// Certificate verification mode. Can be overriden.
    /// By default, [AuthMode::Required] will be used
    pub auth_mode: AuthMode,
    /// The minimum TLS version that will be supported by a particular `Session` instance
    pub min_version: TlsVersion,
}

impl<'a> Default for ClientSessionConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ClientSessionConfig<'a> {
    pub const fn new() -> Self {
        Self {
            ca_chain: None,
            creds: None,
            auth_mode: AuthMode::Required,
            min_version: TlsVersion::Tls1_2,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerSessionConfig<'a> {
    /// Trusted CA (Certificate Authority) chain to be used for certificate
    /// verification during the SSL/TLS handshake.
    ///
    /// The CA chain should contain the trusted CA certificates
    /// that will be used to verify the server's certificate by the clientduring the handshake.
    pub ca_chain: Option<Certificate<'a>>,
    /// Server credentials used for authenticating the server to the client
    pub creds: Credentials<'a>,
    /// Certificate verification mode. Can be overriden.
    /// By default, [AuthMode::None] will be used
    pub auth_mode: AuthMode,
    /// The minimum TLS version that will be supported by a particular `Session` instance
    pub min_version: TlsVersion,
}

impl<'a> ServerSessionConfig<'a> {
    pub const fn new(creds: Credentials<'a>) -> Self {
        Self {
            ca_chain: None,
            creds,
            auth_mode: AuthMode::None,
            min_version: TlsVersion::Tls1_2,
        }
    }
}

/// Configuration for a TLS session
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionConfig<'a> {
    Client(ClientSessionConfig<'a>),
    Server(ServerSessionConfig<'a>),
}

impl<'a> SessionConfig<'a> {
    fn ca_chain(&self) -> Option<&Certificate<'a>> {
        match self {
            SessionConfig::Client(ClientSessionConfig { ca_chain, .. }) => ca_chain.as_ref(),
            SessionConfig::Server(ServerSessionConfig { ca_chain, .. }) => ca_chain.as_ref(),
        }
    }

    fn creds(&self) -> Option<&Credentials<'a>> {
        match self {
            SessionConfig::Client(ClientSessionConfig { creds, .. }) => creds.as_ref(),
            SessionConfig::Server(ServerSessionConfig { creds, .. }) => Some(creds),
        }
    }

    fn auth_mode(&self) -> AuthMode {
        match self {
            SessionConfig::Client(ClientSessionConfig { auth_mode, .. }) => *auth_mode,
            SessionConfig::Server(ServerSessionConfig { auth_mode, .. }) => *auth_mode,
        }
    }

    fn min_version(&self) -> TlsVersion {
        match self {
            SessionConfig::Client(ClientSessionConfig { min_version, .. }) => *min_version,
            SessionConfig::Server(ServerSessionConfig { min_version, .. }) => *min_version,
        }
    }

    fn raw_mode(&self) -> c_int {
        match self {
            Self::Client { .. } => MBEDTLS_SSL_IS_CLIENT as c_int,
            Self::Server { .. } => MBEDTLS_SSL_IS_SERVER as c_int,
        }
    }
}

/// Session state
struct SessionState<'a> {
    /// The SSL context
    ssl_context: MBox<mbedtls_ssl_context>,
    /// The DRBG context
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _drbg: MBox<mbedtls_ctr_drbg_context>,
    /// The SSL configuration
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _ssl_config: MBox<mbedtls_ssl_config>,
    /// The CA chain
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _ca_chain: Option<Certificate<'a>>,
    /// The credentials
    ///
    /// While not explicitly used, we need to keep a reference to it as it is used
    /// by the SSL context via a raw pointer
    _creds: Option<Credentials<'a>>,
}

impl<'a> SessionState<'a> {
    /// Initialize the Session state using the given configuration
    fn new(conf: &SessionConfig<'a>) -> Result<Self, TlsError> {
        err!(unsafe { psa_crypto_init() })?;

        let mut ssl_config = MBox::new()?;

        unsafe {
            mbedtls_ssl_conf_dbg(&mut *ssl_config, Some(dbg_print), core::ptr::null_mut());
        }

        let mut drbg_context = MBox::new()?;

        // Init RNG
        unsafe {
            mbedtls_ssl_conf_rng(
                &mut *ssl_config,
                Some(mbedtls_rng),
                &mut *drbg_context as *mut _ as *mut c_void,
            );
        }

        err!(unsafe {
            mbedtls_ssl_config_defaults(
                &mut *ssl_config,
                conf.raw_mode(),
                MBEDTLS_SSL_TRANSPORT_STREAM as i32,
                MBEDTLS_SSL_PRESET_DEFAULT as i32,
            )
        })?;

        // Set the minimum TLS version
        // Use a ddirect field modified for compatibility with the `esp-idf-svc` mbedtls
        ssl_config.private_min_tls_version = conf.min_version().mbed_tls_version();

        unsafe {
            mbedtls_ssl_conf_authmode(&mut *ssl_config, conf.auth_mode().mbedtls_authmode());
        }

        if let Some(creds) = conf.creds() {
            err!(unsafe {
                mbedtls_ssl_conf_own_cert(
                    &mut *ssl_config,
                    &*creds.certificate.crt as *const _ as *mut _,
                    &*creds.private_key.0 as *const _ as *mut _,
                )
            })?;
        }

        if let Some(ca_chain) = conf.ca_chain() {
            unsafe {
                mbedtls_ssl_conf_ca_chain(
                    &mut *ssl_config,
                    ca_chain as *const _ as *mut mbedtls_x509_crt,
                    core::ptr::null_mut(),
                );
            }
        }

        let mut ssl_context = MBox::new()?;

        err!(unsafe { mbedtls_ssl_setup(&mut *ssl_context, &*ssl_config) })?;

        Ok(Self {
            ssl_context,
            _drbg: drbg_context,
            _ssl_config: ssl_config,
            _ca_chain: conf.ca_chain().cloned(),
            _creds: conf.creds().cloned(),
        })
    }
}

/// A blocking TLS session over a stream represented by `embedded-io`'s `Read` and `Write` traits.
pub struct Session<'a, T> {
    /// The underlying stream
    stream: T,
    /// The session state
    state: SessionState<'a>,
    /// Whether the session is connected
    connected: bool,
    /// Reference to the active Tls instance
    _tls_ref: TlsReference<'a>,
}

impl<'a, T> Session<'a, T> {
    /// Create a session for a TLS stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream for the connection.
    /// * `config` - The session configuration.
    /// * `tls_ref` - A reference to the active `Tls` instance.
    ///
    /// # Errors
    ///
    /// This will return a [TlsError] if there were an error during the initialization of the
    /// session. This can happen if there is not enough memory of if the certificates are in an
    /// invalid format.
    pub fn new(
        stream: T,
        config: &SessionConfig<'a>,
        tls_ref: TlsReference<'a>,
    ) -> Result<Self, TlsError> {
        Ok(Self {
            stream,
            state: SessionState::new(config)?,
            connected: false,
            _tls_ref: tls_ref,
        })
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream(&mut self) -> &mut T {
        &mut self.stream
    }
}

impl<T> Session<'_, T>
where
    T: Read + Write,
{
    /// Set the server name for the TLS connection
    ///
    /// # Arguments
    /// - `server_name`: The server name as a C string
    pub fn set_server_name(&mut self, server_name: &CStr) -> Result<(), TlsError> {
        err!(unsafe {
            mbedtls_ssl_set_hostname(&mut *self.state.ssl_context, server_name.as_ptr())
        })
    }

    /// Negotiate the TLS connection
    ///
    /// This function will perform the TLS handshake with the server.
    ///
    /// Note that calling it is not mandatory, because the TLS session is anyway
    /// negotiated during the first read or write operation.
    pub fn connect(&mut self) -> Result<(), TlsError> {
        if self.connected {
            return Ok(());
        }

        err!(unsafe { mbedtls_ssl_session_reset(&mut *self.state.ssl_context) })?;

        loop {
            match self.call_mbedtls(|ssl_ctx| unsafe { mbedtls_ssl_handshake(ssl_ctx) }) {
                MBEDTLS_ERR_SSL_WANT_READ => continue,
                MBEDTLS_ERR_SSL_WANT_WRITE => continue,
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                len if len >= 0 => {
                    break Ok(());
                }
                other => {
                    break Err(if other == MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE {
                        TlsError::NoClientCertificate
                    } else {
                        TlsError::MbedTlsError(other)
                    })
                }
            }
        }
    }

    /// Read unencrypted data from the TLS connection
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read the data into
    ///
    /// # Returns
    ///
    /// The number of bytes read or an error
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        self.connect()?;

        loop {
            match self.call_mbedtls(|ssl_ctx| unsafe {
                mbedtls_ssl_read(ssl_ctx as *const _ as *mut _, buf.as_mut_ptr(), buf.len())
            }) {
                MBEDTLS_ERR_SSL_WANT_WRITE => continue,
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                len if len >= 0 => break Ok(len as usize),
                other => break Err(TlsError::MbedTlsError(other)),
            }
        }
    }

    /// Write unencrypted data to the TLS connection
    ///
    /// Arguments:
    ///
    /// * `data` - The data to write
    ///
    /// Returns:
    ///
    /// The number of bytes written or an error
    pub fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        self.connect()?;

        loop {
            match self.call_mbedtls(|ssl_ctx| unsafe {
                mbedtls_ssl_write(ssl_ctx as *const _ as *mut _, data.as_ptr(), data.len())
            }) {
                MBEDTLS_ERR_SSL_WANT_WRITE => continue,
                // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                len if len >= 0 => break Ok(len as usize),
                other => break Err(TlsError::MbedTlsError(other)),
            }
        }
    }

    /// Flush the TLS connection
    ///
    /// This function will flush the TLS connection, ensuring that all data is sent.
    ///
    /// Returns:
    ///
    /// An error if the flush failed
    pub fn flush(&mut self) -> Result<(), TlsError> {
        self.connect()?;

        self.stream.flush().map_err(|e| TlsError::Io(e.kind()))
    }

    /// Close the TLS connection
    ///
    /// This function will close the TLS connection, sending the TLS "close notify" info the the peer.
    ///
    /// Returns:
    ///
    /// An error if the close failed
    pub async fn close(&mut self) -> Result<(), TlsError> {
        if !self.connected {
            return Ok(());
        }

        let res =
            self.call_mbedtls(|ssl| unsafe { mbedtls_ssl_close_notify(ssl as *const _ as *mut _) });

        if res != 0 {
            return Err(TlsError::MbedTlsError(res));
        }

        self.flush()?;

        self.connected = false;

        Ok(())
    }

    fn call_mbedtls<F>(&mut self, mut f: F) -> c_int
    where
        F: FnMut(&mut mbedtls_ssl_context) -> c_int,
    {
        unsafe {
            mbedtls_ssl_set_bio(
                &mut *self.state.ssl_context as *mut _,
                self as *const _ as *mut Self as *mut c_void,
                Some(Self::raw_send),
                Some(Self::raw_receive),
                None,
            );
        }

        let result = f(&mut self.state.ssl_context);

        // Remove the callbacks so that we get a warning from MbedTLS in case
        // it needs to invoke them when we don't anticipate so (for bugs detection)
        unsafe {
            mbedtls_ssl_set_bio(
                &*self.state.ssl_context as *const _ as *mut _,
                core::ptr::null_mut(),
                None,
                None,
                None,
            );
        }

        result
    }

    fn bio_receive(&mut self, buf: &mut [u8]) -> c_int {
        let res = self.stream.read(buf);

        match res {
            Ok(len) => {
                if len == 0 {
                    MBEDTLS_ERR_SSL_WANT_READ
                } else {
                    len as c_int
                }
            }
            Err(_) => 0,
        }
    }

    fn bio_send(&mut self, data: &[u8]) -> c_int {
        let res = self.stream.write(data);

        match res {
            Ok(written) => {
                if written > 0 {
                    written as i32
                } else {
                    MBEDTLS_ERR_SSL_WANT_WRITE
                }
            }
            Err(_) => 0,
        }
    }

    unsafe extern "C" fn raw_receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
        let session = (ctx as *mut Self).as_mut().unwrap();

        session.bio_receive(core::slice::from_raw_parts_mut(buf as *mut _, len))
    }

    unsafe extern "C" fn raw_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
        let session = (ctx as *mut Self).as_mut().unwrap();

        session.bio_send(core::slice::from_raw_parts(buf as *const _, len))
    }
}

impl<T> Drop for Session<'_, T> {
    fn drop(&mut self) {
        unsafe {
            mbedtls_ssl_close_notify(&mut *self.state.ssl_context);
        }

        debug!("Session dropped - freeing memory");
    }
}

impl<T> ErrorType for Session<'_, T>
where
    T: Read + Write,
{
    type Error = TlsError;
}

impl<T> Read for Session<'_, T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Self::read(self, buf)
    }
}

impl<T> Write for Session<'_, T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Self::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Self::flush(self)
    }
}

pub mod asynch {
    use core::future::{poll_fn, Future};
    use core::pin::pin;
    use core::task::{Context, Poll};

    use embedded_io_async::{Error, Read, Write};

    use super::*;

    /// Re-export of the `embedded-io-async` crate so that users don't have to explicitly depend on it
    /// to use e.g. `write_all` or `read_exact`.
    pub mod io {
        pub use embedded_io_async::*;
    }

    /// Re-export of the `edge-nal` crate so that users don't have to explicitly depend on it
    /// to use e.g. `TlsAccept` and `TlsConnect` methods.
    #[cfg(feature = "edge-nal")]
    pub mod nal {
        pub use crate::edge_nal::*;
    }

    /// An async TLS session over a stream represented by `embedded-io-async`'s `Read` and `Write` traits.
    pub struct Session<'a, T> {
        /// The underlying stream
        stream: T,
        /// The session state
        state: SessionState<'a>,
        /// Whether the session is connected
        connected: bool,
        /// A state necessary so as to implement `MBio::readable`
        read_byte: Option<u8>,
        /// A state necessary so as to implement `MBio::writable`
        write_byte: Option<u8>,
        /// Reference to the active Tls instance
        _token: TlsReference<'a>,
    }

    impl<'a, T> Session<'a, T> {
        /// Create a session for a TLS stream.
        ///
        /// # Arguments
        ///
        /// * `stream` - The stream for the connection.
        /// * `config`` - The session configuration
        /// * `tls_ref` - A reference to the active `Tls` instance.
        ///
        /// # Errors
        ///
        /// This will return a [TlsError] if there were an error during the initialization of the
        /// session. This can happen if there is not enough memory of if the certificates are in an
        /// invalid format.
        pub fn new(
            stream: T,
            config: &SessionConfig<'a>,
            tls_ref: TlsReference<'a>,
        ) -> Result<Self, TlsError> {
            Ok(Self {
                stream,
                state: SessionState::new(config)?,
                connected: false,
                read_byte: None,
                write_byte: None,
                _token: tls_ref,
            })
        }

        /// Get a mutable reference to the underlying stream
        pub fn stream(&mut self) -> &mut T {
            &mut self.stream
        }
    }

    impl<T> Session<'_, T>
    where
        T: Read + Write,
    {
        /// Set the server name for the TLS connection
        ///
        /// # Arguments
        /// - `server_name`: The server name as a C string
        pub fn set_server_name(&mut self, server_name: &CStr) -> Result<(), TlsError> {
            err!(unsafe {
                mbedtls_ssl_set_hostname(&mut *self.state.ssl_context, server_name.as_ptr())
            })
        }

        /// Negotiate the TLS connection
        ///
        /// This function will perform the TLS handshake with the server.
        ///
        /// Note that calling it is not mandatory, because the TLS session is anyway
        /// negotiated during the first read or write operation.
        pub async fn connect(&mut self) -> Result<(), TlsError> {
            if self.connected {
                return Ok(());
            }

            MBio::from_session(self).connect().await?;

            self.connected = true;

            Ok(())
        }

        pub async fn split(
            &mut self,
        ) -> Result<
            (
                SessionRead<'_, impl Read + '_>,
                SessionWrite<'_, impl Write + '_>,
            ),
            TlsError,
        >
        where
            T: Split,
        {
            self.connect().await?;

            let (read, write) = self.stream.split();

            Ok((
                SessionRead {
                    stream: NoWrite(read),
                    ssl_context: &self.state.ssl_context,
                    read_byte: &mut self.read_byte,
                    write_byte: None,
                },
                SessionWrite {
                    stream: NoRead(write),
                    ssl_context: &self.state.ssl_context,
                    read_byte: None,
                    write_byte: &mut self.write_byte,
                },
            ))
        }

        /// Read unencrypted data from the TLS connection
        ///
        /// # Arguments
        ///
        /// * `buf` - The buffer to read the data into
        ///
        /// # Returns
        ///
        /// The number of bytes read or an error
        pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
            self.connect().await?;

            MBio::from_session(self).read(buf).await
        }

        /// Write unencrypted data to the TLS connection
        ///
        /// Arguments:
        ///
        /// * `data` - The data to write
        ///
        /// Returns:
        ///
        /// The number of bytes written or an error
        pub async fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
            self.connect().await?;

            MBio::from_session(self).write(data).await
        }

        /// Flush the TLS connection
        ///
        /// This function will flush the TLS connection, ensuring that all data is sent.
        ///
        /// Returns:
        ///
        /// An error if the flush failed
        pub async fn flush(&mut self) -> Result<(), TlsError> {
            self.connect().await?;

            MBio::from_session(self).flush().await
        }

        /// Close the TLS connection
        ///
        /// This function will close the TLS connection, sending the TLS "close notify" info the the peer.
        ///
        /// Returns:
        ///
        /// An error if the close failed
        pub async fn close(&mut self) -> Result<(), TlsError> {
            if !self.connected {
                return Ok(());
            }

            MBio::from_session(self).close().await?;

            err!(unsafe { mbedtls_ssl_session_reset(&mut *self.state.ssl_context) })?;

            self.connected = false;

            Ok(())
        }
    }

    impl<T> Drop for Session<'_, T> {
        fn drop(&mut self) {
            unsafe {
                mbedtls_ssl_close_notify(&mut *self.state.ssl_context);
            }

            debug!("Session dropped - freeing memory");
        }
    }

    impl<T> ErrorType for Session<'_, T>
    where
        T: ErrorType,
    {
        type Error = TlsError;
    }

    impl<T> Read for Session<'_, T>
    where
        T: Read + Write,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            Self::read(self, buf).await
        }
    }

    impl<T> Write for Session<'_, T>
    where
        T: Read + Write,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Self::write(self, buf).await
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Self::flush(self).await
        }
    }

    pub struct SessionRead<'a, T> {
        stream: NoWrite<T>,
        ssl_context: &'a mbedtls_ssl_context,
        read_byte: &'a mut Option<u8>,
        write_byte: Option<u8>,
    }

    impl<T> SessionRead<'_, T>
    where
        T: Read,
    {
        pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
            MBio::from_read(self).read(buf).await
        }
    }

    impl<T> ErrorType for SessionRead<'_, T> {
        type Error = TlsError;
    }

    impl<T> Read for SessionRead<'_, T>
    where
        T: Read,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            Self::read(self, buf).await
        }
    }

    pub struct SessionWrite<'a, T> {
        stream: NoRead<T>,
        ssl_context: &'a mbedtls_ssl_context,
        read_byte: Option<u8>,
        write_byte: &'a mut Option<u8>,
    }

    impl<T> SessionWrite<'_, T>
    where
        T: Write,
    {
        pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
            MBio::from_write(self).write(buf).await
        }

        pub async fn flush(&mut self) -> Result<(), TlsError> {
            MBio::from_write(self).flush().await
        }
    }

    impl<T> ErrorType for SessionWrite<'_, T> {
        type Error = TlsError;
    }

    impl<T> Write for SessionWrite<'_, T>
    where
        T: Write,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Self::write(self, buf).await
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Self::flush(self).await
        }
    }

    pub trait Split: ErrorType {
        type Read<'a>: Read<Error = Self::Error>
        where
            Self: 'a;
        type Write<'a>: Write<Error = Self::Error>
        where
            Self: 'a;

        fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>);
    }

    impl<T> Split for &mut T
    where
        T: Split,
    {
        type Read<'a>
            = T::Read<'a>
        where
            Self: 'a;
        type Write<'a>
            = T::Write<'a>
        where
            Self: 'a;

        fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
            T::split(self)
        }
    }

    struct NoRead<T>(T);

    impl<T> ErrorType for NoRead<T>
    where
        T: ErrorType,
    {
        type Error = T::Error;
    }

    impl<T> Read for NoRead<T>
    where
        T: ErrorType,
    {
        async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            unreachable!()
        }
    }

    impl<T> Write for NoRead<T>
    where
        T: Write,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.0.write(buf).await
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.0.flush().await
        }
    }

    struct NoWrite<T>(T);

    impl<T> ErrorType for NoWrite<T>
    where
        T: ErrorType,
    {
        type Error = T::Error;
    }

    impl<T> Read for NoWrite<T>
    where
        T: Read,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.0.read(buf).await
        }
    }

    impl<T> Write for NoWrite<T>
    where
        T: ErrorType,
    {
        async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
            unreachable!()
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            unreachable!()
        }
    }

    /// A type for using the async `Read` and `Write` traits from within the synchronous MbedTLS "mbio" callbacks
    /// **without any additional buffers** / memory.
    ///
    /// Using the MbedTLS callback-based IO metaphor is a bit of a challenge with the async `Read` and `Write` traits,
    /// in that these cannot be `await`-ed from within the MbedTLS mbio callbacks, as the latter are synchronous callback
    /// functions.
    ///
    /// What this type implements therefore is the following trick:
    /// - While we cannot `await` on the `Read` and `Write` traits directly from within the "mbio" callbacks, we can still
    ///   poll them (with `Future::poll`). This is because the `poll` method is synchronous in that it either resolves the
    ///   future immediately (`Poll::Ready`), or returns `Poll::Pending` if the future needs to be polled again.
    /// - Because of the `Read` and `Write` traits' semantics, polling them MUST return immediately, if there is even one
    ///   byte available for reading from the networking stack buffers (or - correspondingly - if there is space to write
    ///   even one byte in the networking stack buffers).
    /// - Since the network stack usually does not operate byte-by-byte, what this means is that by just calling `Future::poll`
    ///   on the `Read` / `Write` trait, we can efficiently transfer the incoming/outgoing data from/to the network stack, without
    ///   any additional network buffers.
    /// - Of course, if the network read buffers are empty (or write buffers are full), we still need to `await` outside the
    ///   MbedTLS callbacks, in the `Session::read` / `Session::write` / `Session::connect` methods.
    ///
    /// Note also, that the implementation is a tad more complex, because it is implemented purely in terms of the
    /// `Read` and `Write` traits, rather than `edge-nal`'s `Readable` and (future) `Writable`, so we need to shuffle single bytes
    /// between the "mbio" callbacks and the `Session` asunc context to make it work.
    ///
    /// On the other hand, this enables `Session` to be used over any streaming transport that implements the `Read` and `Write` traits
    /// (i.e. UART and others).
    struct MBio<'a, T> {
        stream: T,
        ssl_context: &'a mbedtls_ssl_context,
        read_byte: &'a mut Option<u8>,
        write_byte: &'a mut Option<u8>,
    }

    impl<'a, T> MBio<'a, &'a mut T> {
        fn from_session(session: &'a mut Session<'_, T>) -> Self {
            Self::new(
                &mut session.stream,
                &session.state.ssl_context,
                &mut session.read_byte,
                &mut session.write_byte,
            )
        }
    }

    impl<'a, T> MBio<'a, &'a mut NoWrite<T>> {
        fn from_read(session: &'a mut SessionRead<'_, T>) -> Self {
            Self::new(
                &mut session.stream,
                session.ssl_context,
                session.read_byte,
                &mut session.write_byte,
            )
        }
    }

    impl<'a, T> MBio<'a, &'a mut NoRead<T>> {
        fn from_write(session: &'a mut SessionWrite<'_, T>) -> Self {
            Self::new(
                &mut session.stream,
                session.ssl_context,
                &mut session.read_byte,
                session.write_byte,
            )
        }
    }

    impl<'a, T> MBio<'a, T> {
        const fn new(
            stream: T,
            ssl_context: &'a mbedtls_ssl_context,
            read_byte: &'a mut Option<u8>,
            write_byte: &'a mut Option<u8>,
        ) -> Self {
            Self {
                stream,
                ssl_context,
                read_byte,
                write_byte,
            }
        }
    }

    impl<T> MBio<'_, T>
    where
        T: embedded_io_async::Read + embedded_io_async::Write,
    {
        async fn connect(&mut self) -> Result<(), TlsError> {
            debug!("Establishing SSL connection");

            loop {
                match self
                    .call_mbedtls(|ssl_ctx| unsafe {
                        mbedtls_ssl_handshake(ssl_ctx as *const _ as *mut _)
                    })
                    .await
                {
                    MBEDTLS_ERR_SSL_WANT_READ => self
                        .wait_readable()
                        .await
                        .map_err(|e| TlsError::Io(e.kind()))?,
                    MBEDTLS_ERR_SSL_WANT_WRITE => self
                        .wait_writable()
                        .await
                        .map_err(|e| TlsError::Io(e.kind()))?,
                    // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                    MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                    0 => break Ok(()),
                    other => {
                        break Err(if other == MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE {
                            TlsError::NoClientCertificate
                        } else {
                            TlsError::MbedTlsError(other)
                        })
                    }
                }
            }
        }

        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
            loop {
                match self
                    .call_mbedtls(|ssl_ctx| unsafe {
                        mbedtls_ssl_read(
                            ssl_ctx as *const _ as *mut _,
                            buf.as_mut_ptr() as *mut _,
                            buf.len() as _,
                        )
                    })
                    .await
                {
                    MBEDTLS_ERR_SSL_WANT_READ => self
                        .wait_readable()
                        .await
                        .map_err(|e| TlsError::Io(e.kind()))?,
                    MBEDTLS_ERR_SSL_WANT_WRITE => panic!(),
                    // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                    MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                    len if len >= 0 => break Ok(len as usize),
                    other => Err(TlsError::MbedTlsError(other))?,
                }
            }
        }

        async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
            loop {
                match self
                    .call_mbedtls(|ssl_ctx| unsafe {
                        mbedtls_ssl_write(
                            ssl_ctx as *const _ as *mut _,
                            buf.as_ptr() as *const _,
                            buf.len() as _,
                        )
                    })
                    .await
                {
                    MBEDTLS_ERR_SSL_WANT_WRITE => self
                        .wait_writable()
                        .await
                        .map_err(|e| TlsError::Io(e.kind()))?,
                    MBEDTLS_ERR_SSL_WANT_READ => panic!(),
                    // See https://github.com/Mbed-TLS/mbedtls/issues/8749
                    MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => continue,
                    len if len >= 0 => break Ok(len as usize),
                    other => Err(TlsError::MbedTlsError(other))?,
                }
            }
        }

        async fn flush(&mut self) -> Result<(), TlsError> {
            self.wait_writable()
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;

            self.stream
                .flush()
                .await
                .map_err(|e| TlsError::Io(e.kind()))
        }

        pub async fn close(&mut self) -> Result<(), TlsError> {
            self.connect().await?;

            let res = self
                .call_mbedtls(|ssl| unsafe { mbedtls_ssl_close_notify(ssl as *const _ as *mut _) })
                .await;

            if res != 0 {
                return Err(TlsError::MbedTlsError(res));
            }

            self.flush().await?;

            Ok(())
        }

        async fn wait_readable(&mut self) -> Result<(), T::Error> {
            while !self.read_byte.is_some() {
                let mut buf = [0u8; 1];
                let len = self.stream.read(&mut buf).await?;
                if len > 0 {
                    *self.read_byte = Some(buf[0]);
                }
            }

            Ok(())
        }

        async fn wait_writable(&mut self) -> Result<(), T::Error> {
            if let Some(byte) = self.write_byte.as_ref() {
                loop {
                    let len = self.stream.write(&[*byte]).await?;
                    if len > 0 {
                        self.write_byte.take();
                        break;
                    }
                }
            }

            Ok(())
        }

        async fn call_mbedtls<F>(&mut self, mut f: F) -> i32
        where
            F: FnMut(&mbedtls_ssl_context) -> i32,
        {
            poll_fn(|ctx| {
                let mut io_ctx = MBioCallCtx { io: self, ctx };

                unsafe {
                    mbedtls_ssl_set_bio(
                        io_ctx.io.ssl_context as *const _ as *mut _,
                        &mut io_ctx as *const _ as *mut MBioCallCtx<'_, '_, '_, T> as *mut c_void,
                        Some(Self::raw_send),
                        Some(Self::raw_receive),
                        None,
                    );
                }

                let result = f(io_ctx.io.ssl_context);

                // Remove the callbacks so that we get a warning from MbedTLS in case
                // it needs to invoke them when we don't anticipate so (for bugs detection)
                unsafe {
                    mbedtls_ssl_set_bio(
                        io_ctx.io.ssl_context as *const _ as *mut _,
                        core::ptr::null_mut(),
                        None,
                        None,
                        None,
                    );
                }

                Poll::Ready(result)
            })
            .await
        }

        fn bio_receive(&mut self, buf: &mut [u8], ctx: &mut Context<'_>) -> i32 {
            debug!("Receive {}B", buf.len());

            match self.poll_read(ctx, buf) {
                Poll::Ready(len) => len as _,
                Poll::Pending => MBEDTLS_ERR_SSL_WANT_READ,
            }
        }

        fn bio_send(&mut self, buf: &[u8], ctx: &mut Context<'_>) -> i32 {
            debug!("Send {}B", buf.len());

            match self.poll_write(ctx, buf) {
                Poll::Ready(len) => len as _,
                Poll::Pending => MBEDTLS_ERR_SSL_WANT_WRITE,
            }
        }

        fn poll_read(&mut self, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<usize> {
            if buf.is_empty() {
                return Poll::Ready(0);
            }

            if let Some(byte) = self.read_byte.take() {
                buf[0] = byte;
            }

            if buf.len() > 1 {
                let mut fut = pin!(self.stream.read(&mut buf[1..]));

                match fut.as_mut().poll(ctx) {
                    Poll::Ready(Ok(len)) => Poll::Ready(len + 1),
                    _ => Poll::Pending,
                }
            } else {
                Poll::Ready(1)
            }
        }

        fn poll_write(&mut self, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<usize> {
            if self.write_byte.is_some() {
                let mut fut = pin!(self.stream.write(buf));

                match fut.as_mut().poll(ctx) {
                    Poll::Ready(Ok(1)) => *self.write_byte = None,
                    Poll::Ready(Ok(0)) => return Poll::Ready(0),
                    _ => return Poll::Pending,
                }
            }

            if buf.is_empty() {
                return Poll::Ready(0);
            }

            let mut fut = pin!(self.stream.write(buf));

            match fut.as_mut().poll(ctx) {
                Poll::Ready(Ok(len)) => Poll::Ready(len),
                _ => {
                    *self.write_byte = Some(buf[0]);
                    Poll::Ready(1)
                }
            }
        }

        unsafe extern "C" fn raw_receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
            let ctx = (ctx as *mut MBioCallCtx<'_, '_, '_, T>).as_mut().unwrap();

            ctx.io
                .bio_receive(core::slice::from_raw_parts_mut(buf as *mut _, len), ctx.ctx)
        }

        unsafe extern "C" fn raw_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
            let ctx = (ctx as *mut MBioCallCtx<'_, '_, '_, T>).as_mut().unwrap();

            ctx.io
                .bio_send(core::slice::from_raw_parts(buf as *const _, len), ctx.ctx)
        }
    }

    struct MBioCallCtx<'a, 'b, 'c, T> {
        io: &'a mut MBio<'b, T>,
        ctx: &'a mut Context<'c>,
    }
}

/// An internal trait for MbedTLS structuremodeling the (security-induced) initialization and deinitialization
/// sequence for a number of MBedTLS structures
trait MInit {
    /// Initialize the structure
    fn init(&mut self) {}

    /// Deinitialize the structure
    fn deinit(&mut self) {}
}

impl MInit for mbedtls_ctr_drbg_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_ctr_drbg_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ctr_drbg_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_config {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_config_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_config_free(self);
        }
    }
}

impl MInit for mbedtls_x509_crt {
    fn init(&mut self) {
        unsafe {
            mbedtls_x509_crt_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_x509_crt_free(self);
        }
    }
}

impl MInit for mbedtls_pk_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_pk_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_pk_free(self);
        }
    }
}

/// A uniquely-owned box-like wrapper type for MbedTLS structures that need to be allocated/deallocated
/// using `mbedtls_calloc`/`mbedtls_free`, and initialized/deinitialized using the `MInit` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MBox<T>(NonNull<T>)
where
    T: MInit;

impl<T> MBox<T>
where
    T: MInit,
{
    /// Create a new MBox
    ///
    /// # Returns
    /// - Ok(MBox<T>) if the allocation was successful
    /// - Err(TlsError::OutOfMemory) if the allocation failed
    fn new() -> Result<Self, TlsError> {
        NonNull::new(unsafe { mbedtls_calloc(align_of::<T>(), size_of::<T>()) }.cast::<T>())
            .map(|mut ptr| {
                unsafe { ptr.as_mut() }.init();

                Self(ptr)
            })
            .ok_or(TlsError::OutOfMemory)
    }

    /// Get a reference to the inner value
    fn as_ref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }

    /// Get a mutable reference to the inner value
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }
}

impl<T> Deref for MBox<T>
where
    T: MInit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> DerefMut for MBox<T>
where
    T: MInit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T> Drop for MBox<T>
where
    T: MInit,
{
    fn drop(&mut self) {
        self.as_mut().deinit();

        unsafe {
            mbedtls_free(self.0.as_ptr() as *mut c_void);
        }
    }
}

/// A reference-counted `Rc`-like wrapper type for MbedTLS structures that need to be allocated/deallocated
/// using `mbedtls_calloc`/`mbedtls_free`, and initialized/deinitialized using the `MInit` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MRc<T>(NonNull<(T, usize)>)
where
    T: MInit;

impl<T> MRc<T>
where
    T: MInit,
{
    /// Create a new MRc
    fn new() -> Result<Self, TlsError> {
        NonNull::new(
            unsafe { mbedtls_calloc(align_of::<(T, usize)>(), size_of::<(T, usize)>()) }
                .cast::<(T, usize)>(),
        )
        .map(|mut ptr| {
            unsafe { ptr.as_mut() }.0.init();

            Self(ptr)
        })
        .ok_or(TlsError::OutOfMemory)
    }

    /// Get a reference to the inner value
    fn as_ref(&self) -> &T {
        &unsafe { self.0.as_ref() }.0
    }
}

impl<T> Clone for MRc<T>
where
    T: MInit,
{
    fn clone(&self) -> Self {
        let mut ptr = self.0;

        unsafe { ptr.as_mut() }.1 += 1;

        Self(ptr)
    }
}

impl<T> Deref for MRc<T>
where
    T: MInit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> Drop for MRc<T>
where
    T: MInit,
{
    fn drop(&mut self) {
        unsafe { self.0.as_mut() }.1 -= 1;

        if unsafe { self.0.as_mut() }.1 == 0 {
            unsafe { self.0.as_mut() }.0.deinit();

            unsafe {
                mbedtls_free(self.0.as_ptr() as *mut c_void);
            }
        }
    }
}

/// Outputs the MbedTLS debug messages to the log
unsafe extern "C" fn dbg_print(
    _arg: *mut c_void,
    lvl: i32,
    file: *const c_char,
    line: i32,
    msg: *const c_char,
) {
    let file = CStr::from_ptr(file);
    let msg = CStr::from_ptr(msg);

    let file = file.to_str().unwrap_or("???").trim();
    let msg = msg.to_str().unwrap_or("???").trim();

    match lvl {
        0 => error!("{} ({}:{}) {}", lvl, file, line, msg),
        1 => warn!("{} ({}:{}) {}", lvl, file, line, msg),
        2 => debug!("{} ({}:{}) {}", lvl, file, line, msg),
        _ => trace!("{} ({}:{}) {}", lvl, file, line, msg),
    }
}

unsafe extern "C" fn mbedtls_rng(_param: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
    let buf = core::slice::from_raw_parts_mut(buf, len as _);

    critical_section::with(|cs| {
        let mut rng = TLS_RNG.borrow(cs).borrow_mut();

        rng.as_mut().unwrap().fill_bytes(buf);
    });

    0
}

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    output: *mut c_uchar,
    out_size: usize,
    output_len: *mut usize,
) -> c_int {
    *output_len = out_size;
    mbedtls_rng(core::ptr::null_mut(), output, out_size)
}

#[cfg(not(target_os = "espidf"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut c_uchar, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}

#[cfg(feature = "esp32c6")]
#[no_mangle]
unsafe extern "C" fn memchr(ptr: *const u8, ch: u8, count: usize) -> *const u8 {
    for i in 0..count {
        if ptr.add(i).read() == ch {
            return ptr.add(i);
        }
    }

    return core::ptr::null();
}
