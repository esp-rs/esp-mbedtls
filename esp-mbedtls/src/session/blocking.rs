use core::ffi::{c_int, c_uchar, c_void, CStr};

use embedded_io::{Error, ErrorType, Read, Write};

use esp_mbedtls_sys::bindings::*;

use super::{err, SessionConfig, SessionState, TlsError, TlsReference};

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
