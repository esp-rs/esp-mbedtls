use crate::asynch::{AsyncConnectedSession, Session};
use crate::{Certificates, Mode, Peripheral, Rsa, TlsError, TlsVersion, RSA, RSA_REF};
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ptr::NonNull,
};

use edge_nal::TcpBind;
use edge_nal_embassy::{Tcp, TcpAccept, TcpSocket};

pub struct TlsAcceptor<
    'd,
    D: embassy_net::driver::Driver,
    const N: usize,
    const RX_SZ: usize,
    const TX_SZ: usize,
> {
    acceptor: TcpAccept<'d, D, N, TX_SZ, RX_SZ>,
    version: TlsVersion,
    certificates: Certificates<'d>,
    owns_rsa: bool,
    tls_buffers: &'d TlsBuffers<RX_SZ, TX_SZ>,
    tls_buffers_ptr: RefCell<NonNull<([u8; RX_SZ], [u8; TX_SZ])>>,
}

impl<'d, D, const N: usize, const RX_SZ: usize, const TX_SZ: usize> Drop
    for TlsAcceptor<'d, D, N, RX_SZ, TX_SZ>
where
    D: embassy_net::driver::Driver,
{
    fn drop(&mut self) {
        unsafe {
            // If the struct that owns the RSA reference is dropped
            // we remove RSA in static for safety
            if self.owns_rsa {
                log::debug!("Freeing RSA from acceptor");
                RSA_REF = core::mem::transmute(None::<RSA>);
            }

            self.tls_buffers.pool.free(*self.tls_buffers_ptr.get_mut());
        }
    }
}

impl<'d, D, const N: usize, const RX_SZ: usize, const TX_SZ: usize>
    TlsAcceptor<'d, D, N, RX_SZ, TX_SZ>
where
    D: embassy_net::driver::Driver,
{
    pub async fn new(
        tcp: &'d Tcp<'d, D, N, TX_SZ, RX_SZ>,
        tls_buffers: &'d TlsBuffers<RX_SZ, TX_SZ>,
        port: u16,
        version: TlsVersion,
        certificates: Certificates<'d>,
    ) -> Self {
        let acceptor = tcp
            .bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                port,
            )))
            .await
            .unwrap();

        let socket_buffers = tls_buffers.pool.alloc().unwrap();

        Self {
            acceptor,
            version,
            certificates,
            owns_rsa: false,
            tls_buffers,
            tls_buffers_ptr: RefCell::new(socket_buffers),
        }
    }

    /// Enable the use of the hardware accelerated RSA peripheral for the lifetime of
    /// [TlsAcceptor].
    ///
    /// # Arguments
    ///
    /// * `rsa` - The RSA peripheral from the HAL
    pub fn with_hardware_rsa(mut self, rsa: impl Peripheral<P = RSA>) -> Self {
        unsafe { RSA_REF = core::mem::transmute(Some(Rsa::new(rsa))) }
        self.owns_rsa = true;
        self
    }
}

impl<'a, T, const RX_SIZE: usize, const TX_SIZE: usize> edge_nal::Readable
    for AsyncConnectedSession<'a, T, RX_SIZE, TX_SIZE>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    async fn readable(&mut self) -> Result<(), Self::Error> {
        unimplemented!();
    }
}

impl<'d, D, const N: usize, const RX_SZ: usize, const TX_SZ: usize> edge_nal::TcpAccept
    for TlsAcceptor<'d, D, N, RX_SZ, TX_SZ>
where
    D: embassy_net::driver::Driver,
{
    type Error = TlsError;
    type Socket<'a> = AsyncConnectedSession<'a, TcpSocket<'a, N, TX_SZ, RX_SZ>, RX_SZ, TX_SZ> where Self: 'a;

    async fn accept(
        &self,
    ) -> Result<(SocketAddr, Self::Socket<'_>), <Self as edge_nal::TcpAccept>::Error> {
        let (addr, socket) = self
            .acceptor
            .accept()
            .await
            .map_err(|e| TlsError::TcpError(e))?;
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
        )?;

        log::debug!("Establishing SSL connection");
        let connected_session = session.connect().await?;

        Ok((addr, connected_session))
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
