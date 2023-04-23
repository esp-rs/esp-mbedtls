#![no_std]
#![feature(c_variadic)]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

mod compat;

use core::ffi::CStr;
use core::mem::size_of;

use compat::StrBuf;
use embedded_io::blocking::Read;
use embedded_io::blocking::Write;
use embedded_io::Io;
use esp_mbedtls_sys::bindings::*;
use esp_mbedtls_sys::c_types::*;

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

pub struct Certificates<'a> {
    pub certs: Option<&'a str>,
    pub client_cert: Option<&'a str>,
    pub client_key: Option<&'a str>,
    pub password: Option<&'a str>,
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
        // Make sure that both client_cert and client_key are either Some() or None
        assert_eq!(
            self.client_cert.is_some(),
            self.client_key.is_some(),
            "Both client_cert and client_key must be Some() or None"
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

            let client_crt =
                calloc(1, size_of::<mbedtls_x509_crt>() as u32) as *mut mbedtls_x509_crt;
            if client_crt.is_null() {
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
                free(client_crt as *const _);
                return Err(TlsError::OutOfMemory);
            }

            mbedtls_ssl_init(ssl_context);
            mbedtls_ssl_config_init(ssl_config);
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
                if self.certs.is_some() {
                    MBEDTLS_SSL_VERIFY_REQUIRED as i32
                } else {
                    MBEDTLS_SSL_VERIFY_NONE as i32
                },
            );

            let mut hostname = StrBuf::new();
            hostname.append(servername);
            hostname.append_char('\0');
            error_checked!(mbedtls_ssl_set_hostname(
                ssl_context,
                hostname.as_str_ref().as_ptr() as *const c_char
            ))?;

            error_checked!(mbedtls_ssl_setup(ssl_context, ssl_config))?;

            mbedtls_x509_crt_init(crt);

            // Init client certificate
            mbedtls_x509_crt_init(client_crt);
            // Initialize private key
            mbedtls_pk_init(private_key);

            if let Some(certs) = self.certs {
                error_checked!(mbedtls_x509_crt_parse(
                    crt,
                    certs.as_ptr(),
                    certs.len() as u32,
                ))?;
            }

            if let (Some(client_cert), Some(client_key)) = (self.client_cert, self.client_key) {
                // Client certificate
                error_checked!(mbedtls_x509_crt_parse(
                    client_crt,
                    client_cert.as_ptr(),
                    client_cert.len() as u32,
                ))?;

                // Client key
                let (password_ptr, password_len) = if let Some(password) = self.password {
                    (password.as_ptr(), password.len() as u32)
                } else {
                    (core::ptr::null(), 0)
                };
                error_checked!(mbedtls_pk_parse_key(
                    private_key,
                    client_key.as_ptr(),
                    client_key.len() as u32,
                    password_ptr,
                    password_len,
                    None,
                    core::ptr::null_mut(),
                ))?;

                mbedtls_ssl_conf_own_cert(ssl_config, client_crt, private_key);
            }

            mbedtls_ssl_conf_ca_chain(ssl_config, crt, core::ptr::null_mut());
            Ok((ssl_context, ssl_config, crt, client_crt, private_key))
        }
    }
}

pub struct Session<T> {
    stream: T,
    ssl_context: *mut mbedtls_ssl_context,
    ssl_config: *mut mbedtls_ssl_config,
    crt: *mut mbedtls_x509_crt,
    client_crt: *mut mbedtls_x509_crt,
    private_key: *mut mbedtls_pk_context,
}

impl<T> Session<T> {
    pub fn new(
        stream: T,
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

impl<T> Session<T>
where
    T: Read + Write,
{
    pub fn connect<'a>(self) -> Result<ConnectedSession<T>, TlsError> {
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
                    return Err(TlsError::MbedTlsError(res));
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

            mbedtls_ssl_write(self.ssl_context, buf.as_ptr(), buf.len() as u32)
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

            mbedtls_ssl_read(self.ssl_context, buf.as_mut_ptr(), buf.len() as u32)
        }
    }

    unsafe extern "C" fn send(ctx: *mut c_void, buf: *const c_uchar, len: u32) -> c_int {
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

    unsafe extern "C" fn receive(ctx: *mut c_void, buf: *mut c_uchar, len: u32) -> c_int {
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

impl<T> Drop for Session<T> {
    fn drop(&mut self) {
        log::debug!("session dropped - freeing memory");
        unsafe {
            free(self.ssl_config as *const _);
            free(self.ssl_context as *const _);
            free(self.crt as *const _);
            free(self.client_crt as *const _);
            free(self.private_key as *const _);
        }
    }
}

pub struct ConnectedSession<T>
where
    T: Read + Write,
{
    session: Session<T>,
}

impl<T> Io for ConnectedSession<T>
where
    T: Read + Write,
{
    type Error = TlsError;
}

impl<T> Read for ConnectedSession<T>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let res = self.session.internal_read(buf);
        if res <= 0 {
            if res == MBEDTLS_ERR_SSL_WANT_READ
                || res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
            {
                Ok(0)
            } else {
                if res == 0 {
                    Err(TlsError::Eof)
                } else {
                    Err(TlsError::MbedTlsError(res))
                }
            }
        } else {
            Ok(res as usize)
        }
    }
}

impl<T> Write for ConnectedSession<T>
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

    pub struct Session<T, const BUFFER_SIZE: usize = 4096> {
        stream: T,
        ssl_context: *mut mbedtls_ssl_context,
        ssl_config: *mut mbedtls_ssl_config,
        crt: *mut mbedtls_x509_crt,
        client_crt: *mut mbedtls_x509_crt,
        private_key: *mut mbedtls_pk_context,
        eof: bool,
        tx_buffer: BufferedBytes<BUFFER_SIZE>,
        rx_buffer: BufferedBytes<BUFFER_SIZE>,
    }

    impl<T, const BUFFER_SIZE: usize> Session<T, BUFFER_SIZE> {
        pub fn new(
            stream: T,
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

    impl<T, const BUFFER_SIZE: usize> Drop for Session<T, BUFFER_SIZE> {
        fn drop(&mut self) {
            log::debug!("session dropped - freeing memory");
            unsafe {
                free(self.ssl_config as *const _);
                free(self.ssl_context as *const _);
                free(self.crt as *const _);
                free(self.client_crt as *const _);
                free(self.private_key as *const _);
            }
        }
    }

    impl<T, const BUFFER_SIZE: usize> Session<T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        pub async fn connect<'a>(
            mut self,
        ) -> Result<AsyncConnectedSession<T, BUFFER_SIZE>, TlsError> {
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
                        return Err(TlsError::MbedTlsError(res));
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

                let len = mbedtls_ssl_write(self.ssl_context, buf.as_ptr(), buf.len() as u32);
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
                    let res =
                        mbedtls_ssl_read(self.ssl_context, buf.as_mut_ptr(), buf.len() as u32);
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

        unsafe extern "C" fn sync_send(ctx: *mut c_void, buf: *const c_uchar, len: u32) -> c_int {
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

        unsafe extern "C" fn sync_receive(ctx: *mut c_void, buf: *mut c_uchar, len: u32) -> c_int {
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

    pub struct AsyncConnectedSession<T, const BUFFER_SIZE: usize>
    where
        T: asynch::Read + asynch::Write,
    {
        pub(crate) session: Session<T, BUFFER_SIZE>,
    }

    impl<T, const BUFFER_SIZE: usize> Io for AsyncConnectedSession<T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        type Error = TlsError;
    }

    impl<T, const BUFFER_SIZE: usize> asynch::Read for AsyncConnectedSession<T, BUFFER_SIZE>
    where
        T: asynch::Read + asynch::Write,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            log::debug!("async read called");
            if self.session.eof && self.session.rx_buffer.empty() {
                return Err(TlsError::Eof);
            }

            let res = self.session.async_internal_read(buf).await?;
            if res < 0 {
                if res == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET {
                    log::debug!("MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET");
                    Ok(0)
                } else {
                    Err(TlsError::MbedTlsError(res))
                }
            } else {
                Ok(res as usize)
            }
        }
    }

    impl<T, const BUFFER_SIZE: usize> asynch::Write for AsyncConnectedSession<T, BUFFER_SIZE>
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

unsafe extern "C" fn rng(_param: *mut c_void, buffer: *mut c_uchar, len: u32) -> c_int {
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
    out_size: u32,
    output_len: *mut u32,
) -> i32 {
    *output_len = out_size;
    rng(core::ptr::null_mut(), output, out_size);
    0
}
