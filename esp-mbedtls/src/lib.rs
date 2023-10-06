#![no_std]
#![feature(c_variadic)]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]
#![allow(incomplete_features)]

#[doc(hidden)]
#[cfg(feature = "esp32")]
pub use esp32_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32c3")]
pub use esp32c3_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s2")]
pub use esp32s2_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s3")]
pub use esp32s3_hal as hal;

mod compat;

use core::ffi::CStr;
use core::mem::size_of;

use compat::StrBuf;
use embedded_io::blocking::Read;
use embedded_io::blocking::Write;
use embedded_io::Io;
use esp_mbedtls_sys::bindings::*;
use esp_mbedtls_sys::c_types::*;

/// Re-export self-tests
pub use esp_mbedtls_sys::bindings::{
    // AES
    mbedtls_aes_self_test,
    // MD5
    mbedtls_md5_self_test,
    // RSA
    mbedtls_rsa_self_test,
    // SHA
    mbedtls_sha1_self_test,
    mbedtls_sha256_self_test,
    mbedtls_sha384_self_test,
    mbedtls_sha512_self_test,
};

#[cfg(not(feature = "esp32"))]
pub use esp_mbedtls_sys::bindings::mbedtls_sha224_self_test;

mod sha;

// these will come from esp-wifi (i.e. this can only be used together with esp-wifi)
extern "C" {
    fn free(ptr: *const u8);

    fn calloc(number: u32, size: u32) -> *const u8;

    fn random() -> u32;
}

macro_rules! error_checked {
    ($block:expr) => {{
        let res = $block;
        if res != 0 {
            Err(TlsError::MbedTlsError(res))
        } else {
            Ok(())
        }
    }};
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Client,
    Server,
}

impl Mode {
    fn to_mbed_tls(&self) -> i32 {
        match self {
            Mode::Client => MBEDTLS_SSL_IS_CLIENT as i32,
            Mode::Server => MBEDTLS_SSL_IS_SERVER as i32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    Tls1_2,
    Tls1_3,
}

impl TlsVersion {
    fn to_mbed_tls_minor(&self) -> i32 {
        match self {
            TlsVersion::Tls1_2 => MBEDTLS_SSL_MINOR_VERSION_3 as i32,
            TlsVersion::Tls1_3 => MBEDTLS_SSL_MINOR_VERSION_4 as i32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsError {
    Unknown,
    OutOfMemory,
    MbedTlsError(i32),
    Eof,
    X509MissingNullTerminator,
    /// The client has given no certificates for the request
    NoClientCertificate,
}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

#[allow(unused)]
pub fn set_debug(level: u32) {
    #[cfg(not(target_arch = "xtensa"))]
    unsafe {
        mbedtls_debug_set_threshold(level as c_int);
    }
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
pub struct X509<'a>(&'a [u8]);

impl<'a> X509<'a> {
    /// Reads certificate in pem format from bytes
    ///
    /// # Error
    /// This function returns [TlsError::X509MissingNullTerminator] if the certificate
    /// doesn't end with a null-byte.
    pub fn pem(bytes: &'a [u8]) -> Result<Self, TlsError> {
        if let Some(len) = X509::get_null(bytes) {
            // Get a slice of only the certificate bytes including the \0
            let slice = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), len + 1) };
            Ok(Self(slice))
        } else {
            Err(TlsError::X509MissingNullTerminator)
        }
    }

    /// Reads certificate in der format from bytes
    ///
    /// *Note*: This function assumes that the size of the size is the exact
    /// length of the certificate
    pub fn der(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes of the certificate
    pub fn data(&self) -> &'a [u8] {
        self.0
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

/// Certificates used for a connection.
///
/// # Note:
/// Both [certificate](Certificates::certificate) and [private_key](Certificates::private_key) must be set in pair.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Certificates<'a> {
    /// Trusted CA (Certificate Authority) chain to be used for certificate
    /// verification during the SSL/TLS handshake.
    ///
    /// Certificates can be chained. When dealing with intermediate CA certificates,
    /// make sure to include the entire chain up to the root CA.
    ///
    /// # Client:
    /// In Client mode, the CA chain should contain the trusted CA certificates
    /// that will be used to verify the server's certificate during the handshake.
    ///
    /// # Server:
    /// In server mode, the CA chain should contain the trusted CA certificates
    /// that will be used to verify the client's certificate during the handshake.
    /// When set to [None] the server will not request nor perform any verification
    /// on the client certificates. Only set when you want to use client authentication.
    pub ca_chain: Option<X509<'a>>,

    /// Own certificate chain used for requests
    /// It should contain in order from the bottom up your certificate chain.
    /// The top certificate (self-signed) can be omitted.
    ///
    /// # Client:
    /// In client mode, this certificate will be used for client authentication
    /// when communicating wiht the server. Use [None] if you don't want to use
    /// client authentication.
    ///
    /// # Server:
    /// In server mode, this will be the certificate given to the client when
    /// performing a handshake.
    pub certificate: Option<X509<'a>>,

    /// Private key paired with the certificate. Must be set when [Certificates::certificate]
    /// is not [None]
    pub private_key: Option<X509<'a>>,

    /// Password used for the private key.
    /// Use [None] when the private key doesn't have a password.
    pub password: Option<&'a str>,
}

impl<'a> Default for Certificates<'a> {
    fn default() -> Self {
        Self {
            ca_chain: Default::default(),
            certificate: Default::default(),
            private_key: Default::default(),
            password: Default::default(),
        }
    }
}

impl<'a> Certificates<'a> {
    // Initialize the SSL using this set of certificates
    fn init_ssl(
        &self,
        servername: &str,
        mode: Mode,
        min_version: TlsVersion,
    ) -> Result<
        (
            *mut mbedtls_ssl_context,
            *mut mbedtls_ssl_config,
            *mut mbedtls_x509_crt,
            *mut mbedtls_x509_crt,
            *mut mbedtls_pk_context,
        ),
        TlsError,
    > {
        // Make sure that both certificate and private_key are either Some() or None
        assert_eq!(
            self.certificate.is_some(),
            self.private_key.is_some(),
            "Both certificate and private_key must be Some() or None"
        );

        unsafe {
            error_checked!(psa_crypto_init())?;

            let ssl_context =
                calloc(1, size_of::<mbedtls_ssl_context>() as u32) as *mut mbedtls_ssl_context;
            if ssl_context.is_null() {
                return Err(TlsError::OutOfMemory);
            }

            let ssl_config =
                calloc(1, size_of::<mbedtls_ssl_config>() as u32) as *mut mbedtls_ssl_config;
            if ssl_config.is_null() {
                free(ssl_context as *const _);
                return Err(TlsError::OutOfMemory);
            }

            let crt = calloc(1, size_of::<mbedtls_x509_crt>() as u32) as *mut mbedtls_x509_crt;
            if crt.is_null() {
                free(ssl_context as *const _);
                free(ssl_config as *const _);
                return Err(TlsError::OutOfMemory);
            }

            let certificate =
                calloc(1, size_of::<mbedtls_x509_crt>() as u32) as *mut mbedtls_x509_crt;
            if certificate.is_null() {
                free(ssl_context as *const _);
                free(ssl_config as *const _);
                free(crt as *const _);
                return Err(TlsError::OutOfMemory);
            }

            let private_key =
                calloc(1, size_of::<mbedtls_pk_context>() as u32) as *mut mbedtls_pk_context;
            if private_key.is_null() {
                free(ssl_context as *const _);
                free(ssl_config as *const _);
                free(crt as *const _);
                free(certificate as *const _);
                return Err(TlsError::OutOfMemory);
            }

            mbedtls_ssl_init(ssl_context);
            mbedtls_ssl_config_init(ssl_config);
            // Initialize CA chain
            mbedtls_x509_crt_init(crt);
            // Initialize certificate
            mbedtls_x509_crt_init(certificate);
            // Initialize private key
            mbedtls_pk_init(private_key);
            (*ssl_config).private_f_dbg = Some(dbg_print);
            (*ssl_config).private_f_rng = Some(rng);

            error_checked!(mbedtls_ssl_config_defaults(
                ssl_config,
                mode.to_mbed_tls(),
                MBEDTLS_SSL_TRANSPORT_STREAM as i32,
                MBEDTLS_SSL_PRESET_DEFAULT as i32,
            ))?;

            mbedtls_ssl_conf_min_version(
                ssl_config,
                MBEDTLS_SSL_MAJOR_VERSION_3 as i32,
                min_version.to_mbed_tls_minor(),
            );

            mbedtls_ssl_conf_authmode(
                ssl_config,
                if self.ca_chain.is_some() {
                    MBEDTLS_SSL_VERIFY_REQUIRED as i32
                } else {
                    // Use this config when in server mode
                    // Ref: https://os.mbed.com/users/markrad/code/mbedtls/docs/tip/ssl_8h.html#a5695285c9dbfefec295012b566290f37
                    MBEDTLS_SSL_VERIFY_NONE as i32
                },
            );

            if mode == Mode::Client {
                let mut hostname = StrBuf::new();
                hostname.append(servername);
                hostname.append_char('\0');
                error_checked!(mbedtls_ssl_set_hostname(
                    ssl_context,
                    hostname.as_str_ref().as_ptr() as *const c_char
                ))?;
            }

            if let Some(ca_chain) = self.ca_chain {
                error_checked!(mbedtls_x509_crt_parse(
                    crt,
                    ca_chain.as_ptr(),
                    ca_chain.len(),
                ))?;
            }

            if let (Some(cert), Some(key)) = (self.certificate, self.private_key) {
                // Certificate
                error_checked!(mbedtls_x509_crt_parse(
                    certificate,
                    cert.as_ptr(),
                    cert.len(),
                ))?;

                // Private key
                let (password_ptr, password_len) = if let Some(password) = self.password {
                    (password.as_ptr(), password.len())
                } else {
                    (core::ptr::null(), 0)
                };
                error_checked!(mbedtls_pk_parse_key(
                    private_key,
                    key.as_ptr(),
                    key.len(),
                    password_ptr,
                    password_len,
                    None,
                    core::ptr::null_mut(),
                ))?;

                mbedtls_ssl_conf_own_cert(ssl_config, certificate, private_key);
            }

            mbedtls_ssl_conf_ca_chain(ssl_config, crt, core::ptr::null_mut());
            error_checked!(mbedtls_ssl_setup(ssl_context, ssl_config))?;
            Ok((ssl_context, ssl_config, crt, certificate, private_key))
        }
    }
}

pub struct Session<'a, T> {
    stream: &'a mut T,
    ssl_context: *mut mbedtls_ssl_context,
    ssl_config: *mut mbedtls_ssl_config,
    crt: *mut mbedtls_x509_crt,
    client_crt: *mut mbedtls_x509_crt,
    private_key: *mut mbedtls_pk_context,
}

impl<'a, T> Session<'a, T> {
    pub fn new(
        stream: &'a mut T,
        servername: &str,
        mode: Mode,
        min_version: TlsVersion,
        certificates: Certificates,
    ) -> Result<Self, TlsError> {
        let (ssl_context, ssl_config, crt, client_crt, private_key) =
            certificates.init_ssl(servername, mode, min_version)?;
        return Ok(Self {
            stream,
            ssl_context,
            ssl_config,
            crt,
            client_crt,
            private_key,
        });
    }
}

impl<'a, T> Session<'a, T>
where
    T: Read + Write,
{
    pub fn connect<'b>(self) -> Result<ConnectedSession<'a, T>, TlsError> {
        unsafe {
            mbedtls_ssl_set_bio(
                self.ssl_context,
                core::ptr::addr_of!(self) as *mut c_void,
                Some(Self::send),
                Some(Self::receive),
                None,
            );

            loop {
                let res = mbedtls_ssl_handshake(self.ssl_context);
                if res == 0 {
                    // success
                    break;
                }
                if res < 0 && res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE
                {
                    // real error
                    // Reference: https://os.mbed.com/teams/sandbox/code/mbedtls/docs/tip/ssl_8h.html#a4a37e497cd08c896870a42b1b618186e
                    mbedtls_ssl_session_reset(self.ssl_context);
                    return Err(match res {
                        MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE => TlsError::NoClientCertificate,
                        _ => TlsError::MbedTlsError(res),
                    });
                }

                // try again immediately
            }

            Ok(ConnectedSession { session: self })
        }
    }

    fn internal_write(&mut self, buf: &[u8]) -> i32 {
        unsafe {
            mbedtls_ssl_set_bio(
                self.ssl_context,
                self as *mut _ as *mut c_void,
                Some(Self::send),
                Some(Self::receive),
                None,
            );

            mbedtls_ssl_write(self.ssl_context, buf.as_ptr(), buf.len())
        }
    }

    fn internal_read(&mut self, buf: &mut [u8]) -> i32 {
        unsafe {
            mbedtls_ssl_set_bio(
                self.ssl_context,
                self as *mut _ as *mut c_void,
                Some(Self::send),
                Some(Self::receive),
                None,
            );

            mbedtls_ssl_read(self.ssl_context, buf.as_mut_ptr(), buf.len())
        }
    }

    unsafe extern "C" fn send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
        let session = ctx as *mut Session<T>;
        let stream = &mut (*session).stream;
        let slice = core::ptr::slice_from_raw_parts(buf as *const u8, len as usize);
        let res = stream.write(&*slice);

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

    unsafe extern "C" fn receive(ctx: *mut c_void, buf: *mut c_uchar, len: usize) -> c_int {
        let session = ctx as *mut Session<T>;
        let stream = &mut (*session).stream;
        let mut buffer = core::slice::from_raw_parts_mut(buf as *mut u8, len as usize);
        let res = stream.read(&mut buffer);

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
}

impl<'a, T> Drop for Session<'a, T> {
    fn drop(&mut self) {
        log::debug!("session dropped - freeing memory");
        unsafe {
            mbedtls_ssl_close_notify(self.ssl_context);
            mbedtls_ssl_config_free(self.ssl_config);
            mbedtls_ssl_free(self.ssl_context);
            mbedtls_x509_crt_free(self.crt);
            mbedtls_x509_crt_free(self.client_crt);
            mbedtls_pk_free(self.private_key);
            free(self.ssl_config as *const _);
            free(self.ssl_context as *const _);
            free(self.crt as *const _);
            free(self.client_crt as *const _);
            free(self.private_key as *const _);
        }
    }
}

pub struct ConnectedSession<'a, T>
where
    T: Read + Write,
{
    session: Session<'a, T>,
}

impl<'a, T> Io for ConnectedSession<'a, T>
where
    T: Read + Write,
{
    type Error = TlsError;
}

impl<'a, T> Read for ConnectedSession<'a, T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            let res = self.session.internal_read(buf);
            match res {
                0 | MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => {
                    continue
                } // no data
                1_i32..=i32::MAX => return Ok(res as usize), // data
                i32::MIN..=-1_i32 => return Err(TlsError::MbedTlsError(res)), // error
            }
        }
    }
}

impl<'a, T> Write for ConnectedSession<'a, T>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let res = self.session.internal_write(buf);
        Ok(res as usize)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.session.stream.flush().map_err(|_| TlsError::Unknown)
    }
}

#[cfg(feature = "async")]
pub mod asynch {
    use super::*;
    use embedded_io::asynch;

    pub struct Session<'a, T, const BUFFER_SIZE: usize = 4096> {
        stream: &'a mut T,
        ssl_context: *mut mbedtls_ssl_context,
        ssl_config: *mut mbedtls_ssl_config,
        crt: *mut mbedtls_x509_crt,
        client_crt: *mut mbedtls_x509_crt,
        private_key: *mut mbedtls_pk_context,
        eof: bool,
        tx_buffer: BufferedBytes<BUFFER_SIZE>,
        rx_buffer: BufferedBytes<BUFFER_SIZE>,
    }

    impl<'a, T, const BUFFER_SIZE: usize> Session<'a, T, BUFFER_SIZE> {
        pub fn new(
            stream: &'a mut T,
            servername: &str,
            mode: Mode,
            min_version: TlsVersion,
            certificates: Certificates,
        ) -> Result<Self, TlsError> {
            let (ssl_context, ssl_config, crt, client_crt, private_key) =
                certificates.init_ssl(servername, mode, min_version)?;
            return Ok(Self {
                stream,
                ssl_context,
                ssl_config,
                crt,
                client_crt,
                private_key,
                eof: false,
                tx_buffer: Default::default(),
                rx_buffer: Default::default(),
            });
        }
    }

    impl<'a, T, const BUFFER_SIZE: usize> Drop for Session<'a, T, BUFFER_SIZE> {
        fn drop(&mut self) {
            log::debug!("session dropped - freeing memory");
            unsafe {
                mbedtls_ssl_close_notify(self.ssl_context);
                mbedtls_ssl_config_free(self.ssl_config);
                mbedtls_ssl_free(self.ssl_context);
                mbedtls_x509_crt_free(self.crt);
                mbedtls_x509_crt_free(self.client_crt);
                mbedtls_pk_free(self.private_key);
                free(self.ssl_config as *const _);
                free(self.ssl_context as *const _);
                free(self.crt as *const _);
                free(self.client_crt as *const _);
                free(self.private_key as *const _);
            }
        }
    }

    impl<'a, T, const BUFFER_SIZE: usize> Session<'a, T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        pub async fn connect<'b>(
            mut self,
        ) -> Result<AsyncConnectedSession<'a, T, BUFFER_SIZE>, TlsError> {
            unsafe {
                mbedtls_ssl_set_bio(
                    self.ssl_context,
                    core::ptr::addr_of!(self) as *mut c_void,
                    Some(Self::sync_send),
                    Some(Self::sync_receive),
                    None,
                );

                loop {
                    let res = mbedtls_ssl_handshake(self.ssl_context);
                    log::debug!("mbedtls_ssl_handshake: {res}");
                    if res == 0 {
                        // success
                        break;
                    }
                    if res < 0
                        && res != MBEDTLS_ERR_SSL_WANT_READ
                        && res != MBEDTLS_ERR_SSL_WANT_WRITE
                    {
                        // real error
                        // Reference: https://os.mbed.com/teams/sandbox/code/mbedtls/docs/tip/ssl_8h.html#a4a37e497cd08c896870a42b1b618186e
                        mbedtls_ssl_session_reset(self.ssl_context);
                        return Err(match res {
                            MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE => TlsError::NoClientCertificate,
                            _ => TlsError::MbedTlsError(res),
                        });
                    } else {
                        if !self.tx_buffer.empty() {
                            log::debug!("Having data to send to stream");
                            let data = self.tx_buffer.pull(BUFFER_SIZE);
                            log::debug!(
                                "pulled {} bytes from tx_buffer ... send to stream",
                                data.len()
                            );
                            self.stream
                                .write(data)
                                .await
                                .map_err(|_| TlsError::Unknown)?;
                        }

                        if res == MBEDTLS_ERR_SSL_WANT_READ {
                            let mut buf = [0u8; BUFFER_SIZE];
                            let res = self
                                .stream
                                .read(&mut buf[..self.rx_buffer.remaining()])
                                .await
                                .map_err(|_| TlsError::Unknown)?;
                            if res > 0 {
                                log::debug!("push {} bytes to rx-buffer", res);
                                self.rx_buffer.push(&buf[..res]).ok();
                            }
                        }
                    }
                }
                self.drain_tx_buffer().await?;

                Ok(AsyncConnectedSession { session: self })
            }
        }

        async fn drain_tx_buffer(&mut self) -> Result<(), TlsError> {
            unsafe {
                mbedtls_ssl_set_bio(
                    self.ssl_context,
                    self as *mut _ as *mut c_void,
                    Some(Self::sync_send),
                    Some(Self::sync_receive),
                    None,
                );
                if !self.tx_buffer.empty() {
                    log::debug!("Drain tx buffer");
                    let data = self.tx_buffer.pull(BUFFER_SIZE);
                    log::debug!(
                        "pulled {} bytes from tx_buffer ... send to stream",
                        data.len()
                    );
                    log::debug!("{:02x?}", &data);
                    let res = self
                        .stream
                        .write(data)
                        .await
                        .map_err(|_| TlsError::Unknown)?;
                    log::debug!("wrote {res} bytes to stream");
                    self.stream.flush().await.map_err(|_| TlsError::Unknown)?;
                }
            }

            Ok(())
        }

        async fn async_internal_write(&mut self, buf: &[u8]) -> Result<i32, TlsError> {
            unsafe {
                mbedtls_ssl_set_bio(
                    self.ssl_context,
                    self as *mut _ as *mut c_void,
                    Some(Self::sync_send),
                    Some(Self::sync_receive),
                    None,
                );
                self.drain_tx_buffer().await?;

                let len = mbedtls_ssl_write(self.ssl_context, buf.as_ptr(), buf.len());
                self.drain_tx_buffer().await?;

                Ok(len)
            }
        }

        async fn async_internal_read(&mut self, buf: &mut [u8]) -> Result<i32, TlsError> {
            unsafe {
                mbedtls_ssl_set_bio(
                    self.ssl_context,
                    self as *mut _ as *mut c_void,
                    Some(Self::sync_send),
                    Some(Self::sync_receive),
                    None,
                );
                self.drain_tx_buffer().await?;

                if !self.rx_buffer.can_read() {
                    let mut buffer = [0u8; BUFFER_SIZE];
                    let from_socket = self
                        .stream
                        .read(&mut buffer[..self.rx_buffer.remaining()])
                        .await
                        .map_err(|_| TlsError::Unknown)?;
                    if from_socket > 0 {
                        log::debug!("<<< got {} bytes from socket", from_socket);
                        self.rx_buffer.push(&buffer[..from_socket]).ok();
                    } else {
                        // the socket is in EOF state but there might be still data to process
                        self.eof = true;
                    }
                }

                if !self.rx_buffer.empty() {
                    log::debug!("<<< read data from mbedtls");
                    let res = mbedtls_ssl_read(self.ssl_context, buf.as_mut_ptr(), buf.len());
                    log::debug!("<<< mbedtls returned {res}");

                    if res == MBEDTLS_ERR_SSL_WANT_READ {
                        log::debug!("<<< return 0 as read");
                        return Ok(0); // we need another read
                    } else if res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY {
                        self.eof = true;
                        return Ok(0);
                    }
                    Ok(res)
                } else {
                    Ok(0)
                }
            }
        }

        unsafe extern "C" fn sync_send(ctx: *mut c_void, buf: *const c_uchar, len: usize) -> c_int {
            log::debug!("*** sync send called, bytes={len}");
            let session = ctx as *mut Session<T, BUFFER_SIZE>;
            let slice = core::ptr::slice_from_raw_parts(
                buf as *const u8,
                usize::min(len as usize, (*session).tx_buffer.remaining()),
            );
            (*session).tx_buffer.push(&*slice).ok();
            let written = (&*slice).len();
            log::debug!("*** put {} bytes into tx_buffer", written);

            if written == 0 {
                MBEDTLS_ERR_SSL_WANT_WRITE
            } else {
                written as c_int
            }
        }

        unsafe extern "C" fn sync_receive(
            ctx: *mut c_void,
            buf: *mut c_uchar,
            len: usize,
        ) -> c_int {
            log::debug!("*** sync rcv, len={}", len);
            let session = ctx as *mut Session<T, BUFFER_SIZE>;

            if (*session).rx_buffer.empty() {
                log::debug!("*** buffer empty - want read");
                return MBEDTLS_ERR_SSL_WANT_READ;
            }

            let buffer = core::slice::from_raw_parts_mut(buf as *mut u8, len as usize);
            let max_len = usize::min(len as usize, (*session).tx_buffer.remaining());
            let data = (*session).rx_buffer.pull(max_len);
            buffer[0..data.len()].copy_from_slice(data);

            log::debug!("*** pulled {} bytes from rx-buffer", data.len());

            if data.len() == 0 {
                MBEDTLS_ERR_SSL_WANT_READ
            } else {
                data.len() as c_int
            }
        }
    }

    pub struct AsyncConnectedSession<'a, T, const BUFFER_SIZE: usize>
    where
        T: asynch::Read + asynch::Write,
    {
        pub(crate) session: Session<'a, T, BUFFER_SIZE>,
    }

    impl<'a, T, const BUFFER_SIZE: usize> Io for AsyncConnectedSession<'a, T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        type Error = TlsError;
    }

    impl<'a, T, const BUFFER_SIZE: usize> asynch::Read for AsyncConnectedSession<'a, T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            log::debug!("async read called");
            loop {
                if self.session.eof && self.session.rx_buffer.empty() {
                    return Err(TlsError::Eof);
                }
                let res = self.session.async_internal_read(buf).await?;
                match res {
                    0 | MBEDTLS_ERR_SSL_WANT_READ | MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET => {
                        continue
                    } // no data
                    1_i32..=i32::MAX => return Ok(res as usize), // data
                    i32::MIN..=-1_i32 => return Err(TlsError::MbedTlsError(res)), // error
                }
            }
        }
    }

    impl<'a, T, const BUFFER_SIZE: usize> asynch::Write for AsyncConnectedSession<'a, T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            let res = self.session.async_internal_write(buf).await?;
            Ok(res as usize)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.session
                .drain_tx_buffer()
                .await
                .map_err(|_| TlsError::Unknown)?;

            self.session
                .stream
                .flush()
                .await
                .map_err(|_| TlsError::Unknown)
        }
    }
    pub(crate) struct BufferedBytes<const BUFFER_SIZE: usize> {
        buffer: [u8; BUFFER_SIZE],
        write_idx: usize,
        read_idx: usize,
    }

    impl<const BUFFER_SIZE: usize> Default for BufferedBytes<BUFFER_SIZE> {
        fn default() -> Self {
            Self {
                buffer: [0u8; BUFFER_SIZE],
                write_idx: Default::default(),
                read_idx: Default::default(),
            }
        }
    }

    impl<const BUFFER_SIZE: usize> BufferedBytes<BUFFER_SIZE> {
        pub fn pull<'a>(&'a mut self, max: usize) -> &'a [u8] {
            if self.read_idx == self.write_idx {
                self.read_idx = 0;
                self.write_idx = 0;
            }

            let len = usize::min(max, self.write_idx - self.read_idx);
            let res = &self.buffer[self.read_idx..][..len];
            self.read_idx += len;
            res
        }

        pub fn push(&mut self, data: &[u8]) -> Result<(), ()> {
            if self.read_idx == self.write_idx {
                self.read_idx = 0;
                self.write_idx = 0;
            }

            if self.buffer.len() - self.write_idx < data.len() {
                return Err(());
            }

            self.buffer[self.write_idx..][..data.len()].copy_from_slice(data);
            self.write_idx += data.len();

            Ok(())
        }

        pub fn remaining(&self) -> usize {
            self.buffer.len() - self.write_idx
        }

        pub fn can_read(&self) -> bool {
            self.read_idx < self.write_idx
        }

        pub fn empty(&mut self) -> bool {
            if self.read_idx == self.write_idx {
                self.read_idx = 0;
                self.write_idx = 0;
            }

            self.read_idx == self.write_idx
        }
    }
}

unsafe extern "C" fn dbg_print(
    _arg: *mut c_void,
    lvl: i32,
    file: *const i8,
    line: i32,
    msg: *const i8,
) {
    let msg = CStr::from_ptr(msg as *const i8);
    let file = CStr::from_ptr(file as *const i8);
    log::info!(
        "{} {}:{} {}",
        lvl,
        file.to_str().unwrap_or("<invalid string>"),
        line,
        msg.to_str().unwrap_or("<invalid string>")
    );
}

unsafe extern "C" fn rng(_param: *mut c_void, buffer: *mut c_uchar, len: usize) -> c_int {
    for i in 0..len {
        buffer
            .offset(i as isize)
            .write_volatile((random() & 0xff) as u8);
    }

    0
}

#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut u8, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    output: *mut u8,
    out_size: usize,
    output_len: *mut usize,
) -> i32 {
    *output_len = out_size;
    rng(core::ptr::null_mut(), output, out_size);
    0
}
