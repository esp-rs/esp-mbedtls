use core::ffi::{c_int, c_void};

use esp_mbedtls_sys::bindings::*;

use super::{
    err, mbedtls_dbg_print, mbedtls_rng, Certificate, MBox, PrivateKey, TlsError, TlsReference,
    TlsVersion,
};

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
            mbedtls_ssl_conf_dbg(
                &mut *ssl_config,
                Some(mbedtls_dbg_print),
                core::ptr::null_mut(),
            );
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
