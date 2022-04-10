use async_trait::async_trait;
use socks_rs_common::connector::{PlainWrappedTcpStream, WrappedTcpStream};
use tokio::io;
use tokio::net::TcpStream;

#[async_trait]
pub trait Acceptor<T: WrappedTcpStream> {
    async fn accept(&self, socket: TcpStream) -> io::Result<T>;
}

pub struct PlainAcceptor;

impl PlainAcceptor {
    pub fn new() -> PlainAcceptor {
        PlainAcceptor {}
    }
}

#[async_trait]
impl Acceptor<PlainWrappedTcpStream> for PlainAcceptor {
    async fn accept(&self, socket: TcpStream) -> io::Result<PlainWrappedTcpStream> {
        Ok(PlainWrappedTcpStream::new(socket))
    }
}

#[cfg(feature = "tls")]
pub mod tls {
    use crate::acceptor::Acceptor;
    use async_trait::async_trait;
    use socks_rs_common::connector::tls::TlsWrappedTcpStream;
    use tokio::io;
    use tokio::net::TcpStream;

    pub struct TlsAcceptor {
        tls: tokio_native_tls::TlsAcceptor,
    }

    impl TlsAcceptor {
        pub fn new(tls: tokio_native_tls::TlsAcceptor) -> TlsAcceptor {
            TlsAcceptor { tls }
        }
    }

    #[async_trait]
    impl Acceptor<TlsWrappedTcpStream> for TlsAcceptor {
        async fn accept(&self, socket: TcpStream) -> io::Result<TlsWrappedTcpStream> {
            let res = self
                .tls
                .accept(socket)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
            Ok(TlsWrappedTcpStream::new(res))
        }
    }
}
