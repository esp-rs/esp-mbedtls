use core::ffi::{c_int, c_void, CStr};

use embedded_io::{Error, ErrorKind};

use super::sys::*;
use super::{mbedtls_rng, Certificate, MBox, PrivateKey, Tls, TlsReference, TlsVersion};

pub use asynch::*;

mod asynch;
pub mod blocking;

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
    pub certificate: Certificate<'a>,
    /// Private key paired with the certificate.
    pub private_key: PrivateKey,
}

/// Configuration for a TLS session
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientSessionConfig<'a> {
    /// Trusted CA (Certificate Authority) chain to be used for certificate
    /// verification during the SSL/TLS handshake.
    ///
    /// The CA chain should contain the trusted CA certificates
    /// that will be used to verify the server's certificate by the client during the handshake.
    pub ca_chain: Option<Certificate<'a>>,
    /// Optional client credentials used for authenticating the client to the server
    pub creds: Option<Credentials<'a>>,
    /// The server name to verify in the certificate provided by the server
    /// Optional, because it can also be provided later
    pub server_name: Option<&'a CStr>,
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
            server_name: None,
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
    /// that will be used to verify the client's certificate by the server during the handshake.
    pub ca_chain: Option<Certificate<'a>>,
    /// Server credentials used for authenticating the server to the client
    pub creds: Credentials<'a>,
    /// Client certificate verification mode. Can be overriden.
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
    fn new(conf: &SessionConfig<'a>) -> Result<Self, MbedtlsError> {
        merr!(unsafe { psa_crypto_init() })?;

        let mut ssl_config = MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        merr!(unsafe {
            mbedtls_ssl_config_defaults(
                &mut *ssl_config,
                conf.raw_mode(),
                MBEDTLS_SSL_TRANSPORT_STREAM as i32,
                MBEDTLS_SSL_PRESET_DEFAULT as i32,
            )
        })?;

        // Set the minimum TLS version
        // Use a direct field modified for compatibility with the `esp-idf-svc` mbedtls
        ssl_config.private_min_tls_version = conf.min_version().mbed_tls_version();

        Tls::hook_debug_logs(&mut ssl_config);

        unsafe {
            mbedtls_ssl_conf_authmode(&mut *ssl_config, conf.auth_mode().mbedtls_authmode());
        }

        if let Some(creds) = conf.creds() {
            merr!(unsafe {
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
                    &*ca_chain.crt as *const _ as *mut _,
                    core::ptr::null_mut(),
                );
            }
        }

        let mut drbg_context =
            MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        // Init RNG
        unsafe {
            mbedtls_ssl_conf_rng(
                &mut *ssl_config,
                Some(mbedtls_rng),
                &mut *drbg_context as *mut _ as *mut c_void,
            );
        }

        let mut ssl_context = MBox::new().ok_or(MbedtlsError::new(MBEDTLS_ERR_SSL_ALLOC_FAILED))?;

        merr!(unsafe { mbedtls_ssl_setup(&mut *ssl_context, &*ssl_config) })?;

        if let SessionConfig::Client(conf) = conf {
            if let Some(server_name) = conf.server_name {
                merr!(unsafe {
                    mbedtls_ssl_set_hostname(&mut *ssl_context, server_name.as_ptr())
                })?;
            }
        }

        Ok(Self {
            ssl_context,
            _drbg: drbg_context,
            _ssl_config: ssl_config,
            _ca_chain: conf.ca_chain().cloned(),
            _creds: conf.creds().cloned(),
        })
    }
}

/// Error type for session operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// MBedTLS error
    MbedTls(MbedtlsError),
    /// IO error
    Io(ErrorKind),
}

impl SessionError {
    /// Create a SessionError from an embedded-io Error
    pub fn from_io<E: Error>(err: E) -> Self {
        Self::Io(err.kind())
    }
}

impl From<MbedtlsError> for SessionError {
    fn from(e: MbedtlsError) -> Self {
        Self::MbedTls(e)
    }
}

impl From<ErrorKind> for SessionError {
    fn from(e: ErrorKind) -> Self {
        Self::Io(e)
    }
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MbedTls(e) => write!(f, "{}", e),
            Self::Io(e) => write!(f, "IO({:?})", e),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SessionError {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::MbedTls(e) => defmt::write!(f, "{}", e),
            Self::Io(e) => defmt::write!(f, "IO({:?})", debug2format!(e)),
        }
    }
}

impl core::error::Error for SessionError {}

impl embedded_io::Error for SessionError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(e) => *e,
            _ => embedded_io::ErrorKind::Other,
        }
    }
}
