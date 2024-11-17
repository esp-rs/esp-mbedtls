use core::{
    cell::{Cell, UnsafeCell},
    mem::MaybeUninit,
    net::SocketAddr,
    ptr::NonNull,
};

use embedded_io::{Error, ErrorType};

use crate::asynch::Session;
use crate::{Certificates, CryptoToken, Mode, TlsError, TlsVersion};

pub struct TlsAcceptor<
    'd,
    T,
    const N: usize,
    const RX_SZ: usize,
    const TX_SZ: usize,
> {
    acceptor: T,
    version: TlsVersion,
    server_name: &'d str,
    certificates: Certificates<'d>,
    tls_buffers: &'d TlsBuffers<N, RX_SZ, TX_SZ>,
    crypto_token: CryptoToken<'d>,
}

impl<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize>
    TlsAcceptor<'d, T, N, RX_SZ, TX_SZ>
where
    T: edge_nal::TcpAccept,
{
    pub const fn new(
        acceptor: T,
        server_name: &'d str,
        tls_buffers: &'d TlsBuffers<N, RX_SZ, TX_SZ>,
        version: TlsVersion,
        certificates: Certificates<'d>,
        crypto_token: CryptoToken<'d>,
    ) -> Self {
        Self {
            acceptor,
            server_name,
            version,
            certificates,
            tls_buffers,
            crypto_token,
        }
    }
}

impl<T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> edge_nal::TcpAccept
    for TlsAcceptor<'_, T, N, RX_SZ, TX_SZ>
where
    T: edge_nal::TcpAccept,
{
    type Error = TlsError;
    type Socket<'a> = BufferedSession<'a, T::Socket<'a>, N, RX_SZ, TX_SZ> where Self: 'a;

    async fn accept(
        &self,
    ) -> Result<(SocketAddr, Self::Socket<'_>), <Self as edge_nal::TcpAccept>::Error> {
        let (addr, socket) = self
            .acceptor
            .accept()
            .await
            .map_err(|e| TlsError::TcpError(e.kind()))?;
        log::debug!("Accepted new connection on socket");

        let mut socket_buffers = self.tls_buffers.pool.alloc().unwrap(); // TODO: Error handling

        let (rx, tx) = unsafe { socket_buffers.as_mut() };

        let session: Session<_, RX_SZ, TX_SZ> = Session::new(
            socket,
            self.server_name,
            Mode::Server,
            self.version,
            self.certificates,
            rx,
            tx,
            self.crypto_token,
        )?;

        let mut this = BufferedSession {
            session: Some(session),
            tls_buffers: self.tls_buffers,
            tls_buffers_ptr: socket_buffers,
        };

        log::debug!("Establishing SSL connection");
        this.session.as_mut().unwrap().connect_async().await?;

        
        Ok((addr, this))
    }
}

pub struct TlsConnector<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> {
    connector: T,
    server_name: &'d str,
    version: TlsVersion,
    certificates: Certificates<'d>,
    tls_buffers: &'d TlsBuffers<N, RX_SZ, TX_SZ>,
    crypto_token: CryptoToken<'d>,
}

impl<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> TlsConnector<'d, T, N, RX_SZ, TX_SZ>
where
    T: edge_nal::TcpConnect,
{
    pub const fn new(
        connector: T,
        server_name: &'d str,
        tls_buffers: &'d TlsBuffers<N, RX_SZ, TX_SZ>,
        version: TlsVersion,
        certificates: Certificates<'d>,
        crypto_token: CryptoToken<'d>,
    ) -> Self {
        Self {
            connector,
            server_name,
            version,
            certificates,
            tls_buffers,
            crypto_token,
        }
    }
}

impl<T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> edge_nal::TcpConnect for TlsConnector<'_, T, N, RX_SZ, TX_SZ>
where
    T: edge_nal::TcpConnect,
{
    type Error = TlsError;
    
    type Socket<'a> = BufferedSession<'a, T::Socket<'a>, N, RX_SZ, TX_SZ> where Self: 'a;
    
    async fn connect(&self, remote: SocketAddr) -> Result<Self::Socket<'_>, Self::Error> {
        let mut socket_buffers = self.tls_buffers.pool.alloc().unwrap(); // TODO: Error handling

        let socket = self
            .connector
            .connect(remote)
            .await
            .map_err(|e| TlsError::TcpError(e.kind()))?;
        log::debug!("Connected to {remote}");

        let (rx, tx) = unsafe { socket_buffers.as_mut() };

        let session: Session<_, RX_SZ, TX_SZ> = Session::new(
            socket,
            self.server_name,
            Mode::Client,
            self.version,
            self.certificates,
            rx,
            tx,
            self.crypto_token,
        )?;

        let mut this = BufferedSession {
            session: Some(session),
            tls_buffers: self.tls_buffers,
            tls_buffers_ptr: socket_buffers,
        };

        log::debug!("Establishing SSL connection");
        this.session.as_mut().unwrap().connect_async().await?;

        
        Ok(this)
    }
}

pub struct BufferedSession<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> {
    session: Option<Session<'d, 'd, T, RX_SZ, TX_SZ>>,
    tls_buffers: &'d TlsBuffers<N, RX_SZ, TX_SZ>,
    tls_buffers_ptr: NonNull<([u8; RX_SZ], [u8; TX_SZ])>,
}

impl<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> Drop for BufferedSession<'d, T, N, RX_SZ, TX_SZ> {
    fn drop(&mut self) {
        // First drop the session, and only then the buffers
        self.session = None;

        unsafe {
            self.tls_buffers.pool.free(self.tls_buffers_ptr);
        }
    }
}

impl<T, const N: usize, const RX_SIZE: usize, const TX_SIZE: usize> ErrorType
for BufferedSession<'_, T, N, RX_SIZE, TX_SIZE>
where
    T: ErrorType,
{
    type Error = TlsError;
}

impl<T, const N: usize, const RX_SIZE: usize, const TX_SIZE: usize> edge_nal::Readable
for BufferedSession<'_, T, N, RX_SIZE, TX_SIZE>
where
    T: edge_nal::Readable,
{
    async fn readable(&mut self) -> Result<(), Self::Error> {
        self.session.as_mut().unwrap().readable().await
    }
}

impl<T, const N: usize, const RX_SIZE: usize, const TX_SIZE: usize> edge_nal::TcpShutdown
for BufferedSession<'_, T, N, RX_SIZE, TX_SIZE>
where
    T: edge_nal::TcpShutdown,
{
    async fn close(&mut self, what: edge_nal::Close) -> Result<(), Self::Error> {
        self.session.as_mut().unwrap().close(what).await
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        self.session.as_mut().unwrap().abort().await
    }
}

impl<T, const RX_SIZE: usize, const TX_SIZE: usize> edge_nal::Readable
for Session<'_, '_, T, RX_SIZE, TX_SIZE>
where
    T: edge_nal::Readable,
{
    async fn readable(&mut self) -> Result<(), Self::Error> {
        self.stream.readable().await.map_err(|e| TlsError::TcpError(e.kind()))
    }
}

impl<T, const RX_SIZE: usize, const TX_SIZE: usize> edge_nal::TcpShutdown
for Session<'_, '_, T, RX_SIZE, TX_SIZE>
where
    T: edge_nal::TcpShutdown,
{
    async fn close(&mut self, what: edge_nal::Close) -> Result<(), Self::Error> {
        self.stream
            .close(what)
            .await
            .map_err(|e| TlsError::TcpError(e.kind()))
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        self.stream.abort().await.map_err(|e| TlsError::TcpError(e.kind()))
    }
}

impl<T, const N: usize, const RX_SIZE: usize, const TX_SIZE: usize> embedded_io_async::Read
for BufferedSession<'_, T, N, RX_SIZE, TX_SIZE>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.session.as_mut().unwrap().read(buf).await
    }
}

impl<T, const N: usize, const RX_SIZE: usize, const TX_SIZE: usize> embedded_io_async::Write
for BufferedSession<'_, T, N, RX_SIZE, TX_SIZE>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.session.as_mut().unwrap().write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.session.as_mut().unwrap().flush().await
    }
}

/// A struct that holds a pool of TLS buffers
pub struct TlsBuffers<const N: usize, const RX_SZ: usize, const TX_SZ: usize> {
    pool: Pool<([u8; RX_SZ], [u8; TX_SZ]), N>,
}

impl<const N: usize, const RX_SZ: usize, const TX_SZ: usize> TlsBuffers<N, RX_SZ, TX_SZ> {
    /// Create a new `TlsBuffers` instance
    pub const fn new() -> Self {
        Self { pool: Pool::new() }
    }
}

pub(crate) struct Pool<T, const N: usize> {
    used: [Cell<bool>; N],
    data: [UnsafeCell<MaybeUninit<T>>; N],
}

impl<T, const N: usize> Pool<T, N> {
    #[allow(clippy::declare_interior_mutable_const)]
    const VALUE: Cell<bool> = Cell::new(false);
    const UNINIT: UnsafeCell<MaybeUninit<T>> = UnsafeCell::new(MaybeUninit::uninit());

    const fn new() -> Self {
        Self {
            used: [Self::VALUE; N],
            data: [Self::UNINIT; N],
        }
    }
}

impl<T, const N: usize> Pool<T, N> {
    fn alloc(&self) -> Option<NonNull<T>> {
        for n in 0..N {
            // this can't race because Pool is not Sync.
            if !self.used[n].get() {
                self.used[n].set(true);
                let p = self.data[n].get() as *mut T;
                return Some(unsafe { NonNull::new_unchecked(p) });
            }
        }
        None
    }

    /// safety: p must be a pointer obtained from self.alloc that hasn't been freed yet.
    unsafe fn free(&self, p: NonNull<T>) {
        let origin = self.data.as_ptr() as *mut T;
        let n = p.as_ptr().offset_from(origin);
        assert!(n >= 0);
        assert!((n as usize) < N);
        self.used[n as usize].set(false);
    }
}
