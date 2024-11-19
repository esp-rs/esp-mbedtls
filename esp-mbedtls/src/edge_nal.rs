use core::ffi::CStr;
use core::net::SocketAddr;

use embedded_io::Error;

use crate::asynch::Session;
use crate::{Certificates, TlsToken, Mode, TlsError, TlsVersion};

pub struct TlsAcceptor<'d, T> {
    acceptor: T,
    min_version: TlsVersion,
    certificates: Certificates<'d>,
    token: TlsToken<'d>,
}

impl<'d, T> TlsAcceptor<'d, T>
where
    T: edge_nal::TcpAccept,
{
    pub const fn new(
        acceptor: T,
        min_version: TlsVersion,
        certificates: Certificates<'d>,
        token: TlsToken<'d>,
    ) -> Self {
        Self {
            acceptor,
            min_version,
            certificates,
            token,
        }
    }
}

impl<T> edge_nal::TcpAccept for TlsAcceptor<'_, T>
where
    T: edge_nal::TcpAccept,
{
    type Error = TlsError;
    type Socket<'a> = Session<'a, T::Socket<'a>> where Self: 'a;

    async fn accept(
        &self,
    ) -> Result<(SocketAddr, Self::Socket<'_>), <Self as edge_nal::TcpAccept>::Error> {
        let (addr, socket) = self
            .acceptor
            .accept()
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        log::debug!("Accepted new connection on socket");

        let session = Session::new(
            socket,
            Mode::Server,
            self.min_version,
            self.certificates,
            self.token,
        )?;

        Ok((addr, session))
    }
}

pub struct TlsConnector<'d, T> {
    connector: T,
    servername: &'d CStr,
    min_version: TlsVersion,
    certificates: Certificates<'d>,
    token: TlsToken<'d>,
}

impl<'d, T> TlsConnector<'d, T>
where
    T: edge_nal::TcpConnect,
{
    pub const fn new(
        connector: T,
        servername: &'d CStr,
        min_version: TlsVersion,
        certificates: Certificates<'d>,
        token: TlsToken<'d>,
    ) -> Self {
        Self {
            connector,
            servername,
            min_version,
            certificates,
            token,
        }
    }
}

impl<T> edge_nal::TcpConnect for TlsConnector<'_, T>
where
    T: edge_nal::TcpConnect,
{
    type Error = TlsError;
    
    type Socket<'a> = Session<'a, T::Socket<'a>> where Self: 'a;
    
    async fn connect(&self, remote: SocketAddr) -> Result<Self::Socket<'_>, Self::Error> {
        let socket = self
            .connector
            .connect(remote)
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        log::debug!("Connected to {remote}");

        let session = Session::new(
            socket,
            Mode::Client { servername: self.servername },
            self.min_version,
            self.certificates,
            self.token,
        )?;

        Ok(session)
    }
}

impl<T> edge_nal::Readable for Session<'_, T>
where
    T: edge_nal::Readable,
{
    async fn readable(&mut self) -> Result<(), Self::Error> {
         // ... 1- because it is difficult to figure out - with the MbedTLS API - if `Session::read` would return without blocking
         // For this, we need support for that in MbedTLS itself, which is not available at the moment.
         // 2- because `Readable` currently throws exception with `edge-nal-embassy`
        Ok(())
    }
}

impl<T> edge_nal::TcpShutdown for Session<'_, T>
where
    T: embedded_io_async::Read + embedded_io_async::Write + edge_nal::TcpShutdown,
{
    async fn close(&mut self, what: edge_nal::Close) -> Result<(), Self::Error> {
        Session::close(self).await?;

        self.stream
            .close(what)
            .await
            .map_err(|e| TlsError::Io(e.kind()))
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        self.stream.abort().await.map_err(|e| TlsError::Io(e.kind()))
    }
}
