use embedded_io::Error;

use crate::asynch::Session;
use crate::{Certificates, CryptoToken, Mode, TlsError, TlsVersion};
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    mem::MaybeUninit,
    net::SocketAddr,
    ptr::NonNull,
};

pub struct TlsAcceptor<
    'd,
    T,
    const N: usize,
    const RX_SZ: usize,
    const TX_SZ: usize,
> {
    acceptor: T,
    version: TlsVersion,
    certificates: Certificates<'d>,
    tls_buffers: &'d TlsBuffers<RX_SZ, TX_SZ>,
    tls_buffers_ptr: RefCell<NonNull<([u8; RX_SZ], [u8; TX_SZ])>>,
    crypto_token: CryptoToken<'d>,
}

impl<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize> Drop for TlsAcceptor<'d, T, N, RX_SZ, TX_SZ> {
    fn drop(&mut self) {
        unsafe {
            self.tls_buffers.pool.free(*self.tls_buffers_ptr.get_mut());
        }
    }
}

impl<'d, T, const N: usize, const RX_SZ: usize, const TX_SZ: usize>
    TlsAcceptor<'d, T, N, RX_SZ, TX_SZ>
where
    T: edge_nal::TcpAccept,
{
    pub async fn new(
        acceptor: T,
        tls_buffers: &'d TlsBuffers<RX_SZ, TX_SZ>,
        version: TlsVersion,
        certificates: Certificates<'d>,
        crypto_token: CryptoToken<'d>,
    ) -> Self {
        let socket_buffers = tls_buffers.pool.alloc().unwrap();

        Self {
            acceptor,
            version,
            certificates,
            tls_buffers,
            tls_buffers_ptr: RefCell::new(socket_buffers),
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
    type Socket<'a> = Session<'a, 'a, T::Socket<'a>, RX_SZ, TX_SZ> where Self: 'a;

    async fn accept(
        &self,
    ) -> Result<(SocketAddr, Self::Socket<'_>), <Self as edge_nal::TcpAccept>::Error> {
        let (addr, socket) = self
            .acceptor
            .accept()
            .await
            .map_err(|e| TlsError::TcpError(e.kind()))?;
        log::debug!("Accepted new connection on socket");

        let (rx, tx) = unsafe { self.tls_buffers_ptr.borrow_mut().as_mut() };

        let session: Session<_, RX_SZ, TX_SZ> = Session::new(
            socket,
            "",
            Mode::Server,
            self.version,
            self.certificates,
            rx,
            tx,
            self.crypto_token,
        )?;

        log::debug!("Establishing SSL connection");
        let connected_session = session.connect().await?;

        Ok((addr, connected_session))
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

/// A struct that holds a pool of TLS buffers
pub struct TlsBuffers<const RX_SZ: usize, const TX_SZ: usize> {
    pool: Pool<([u8; RX_SZ], [u8; TX_SZ]), 1>,
}

impl<const RX_SZ: usize, const TX_SZ: usize> TlsBuffers<RX_SZ, TX_SZ> {
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
