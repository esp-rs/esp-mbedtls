use core::ffi::CStr;
use core::net::SocketAddr;

use embedded_io::Error;

use crate::asynch::Session;
use crate::{Certificates, TlsToken, Mode, TlsError, TlsVersion};

pub struct TlsAcceptor<'d, T> {
    acceptor: T,
    version: TlsVersion,
    server_name: &'d CStr,
    certificates: Certificates<'d>,
    crypto_token: TlsToken<'d>,
}

impl<'d, T> TlsAcceptor<'d, T>
where
    T: edge_nal::TcpAccept,
{
    pub const fn new(
        acceptor: T,
        server_name: &'d CStr,
        version: TlsVersion,
        certificates: Certificates<'d>,
        crypto_token: TlsToken<'d>,
    ) -> Self {
        Self {
            acceptor,
            server_name,
            version,
            certificates,
            crypto_token,
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
            .map_err(|e| TlsError::TcpError(e.kind()))?;
        log::debug!("Accepted new connection on socket");

        let session = Session::new(
            socket,
            self.server_name,
            Mode::Server,
            self.version,
            self.certificates,
            self.crypto_token,
        )?;

        Ok((addr, session))
    }
}

pub struct TlsConnector<'d, T> {
    connector: T,
    server_name: &'d CStr,
    version: TlsVersion,
    certificates: Certificates<'d>,
    crypto_token: TlsToken<'d>,
}

impl<'d, T> TlsConnector<'d, T>
where
    T: edge_nal::TcpConnect,
{
    pub const fn new(
        connector: T,
        server_name: &'d CStr,
        version: TlsVersion,
        certificates: Certificates<'d>,
        crypto_token: TlsToken<'d>,
    ) -> Self {
        Self {
            connector,
            server_name,
            version,
            certificates,
            crypto_token,
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
            .map_err(|e| TlsError::TcpError(e.kind()))?;
        log::debug!("Connected to {remote}");

        let session = Session::new(
            socket,
            self.server_name,
            Mode::Client,
            self.version,
            self.certificates,
            self.crypto_token,
        )?;

        Ok(session)
    }
}

impl<T> edge_nal::Readable for Session<'_, T>
where
    T: edge_nal::Readable,
{
    async fn readable(&mut self) -> Result<(), Self::Error> {
        self.stream.readable().await.map_err(|e| TlsError::TcpError(e.kind()))
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
            .map_err(|e| TlsError::TcpError(e.kind()))
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        self.stream.abort().await.map_err(|e| TlsError::TcpError(e.kind()))
    }
}
