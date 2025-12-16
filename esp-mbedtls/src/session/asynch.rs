use core::ffi::{c_int, c_uchar, c_void, CStr};
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Context, Poll};

use esp_mbedtls_sys::bindings::*;

use embedded_io_async::{Error, ErrorType, Read, Write};

use crate::{err, TlsError, TlsReference};

use super::{SessionConfig, SessionState};

// /// Re-export of the `embedded-io-async` crate so that users don't have to explicitly depend on it
// /// to use e.g. `write_all` or `read_exact`.
// pub mod io {
//     pub use embedded_io_async::*;
// }

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
