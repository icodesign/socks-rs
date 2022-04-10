use async_trait::async_trait;
use socks_rs_common::connector::{
    tcp_connect, DNSResolver, PlainWrappedTcpStream, WrappedTcpStream,
};
use socks_rs_common::TargetAddr;
use tokio::io;

#[async_trait]
pub trait Connector<T: WrappedTcpStream> {
    async fn connect(&self, addr: &TargetAddr) -> io::Result<T>;
}

pub struct PlainConnector<'a, D: DNSResolver> {
    resolver: &'a D,
}

impl<'a, D: DNSResolver> PlainConnector<'a, D> {
    pub fn new(resolver: &'a D) -> PlainConnector<'a, D> {
        PlainConnector { resolver }
    }
}

#[async_trait]
impl<'a, D: DNSResolver + Send + Sync> Connector<PlainWrappedTcpStream> for PlainConnector<'a, D> {
    async fn connect(&self, addr: &TargetAddr) -> io::Result<PlainWrappedTcpStream> {
        tcp_connect(addr, self.resolver)
            .await
            .map(|x| PlainWrappedTcpStream::new(x))
    }
}

#[cfg(feature = "tls")]
pub mod tls {
    use crate::connector::Connector;
    use async_trait::async_trait;
    use socks_rs_common::connector::tls::TlsWrappedTcpStream;
    use socks_rs_common::connector::{tcp_connect, DNSResolver};
    use socks_rs_common::TargetAddr;
    use tokio::io;

    pub struct TlsConnector<'a, D: DNSResolver> {
        resolver: &'a D,
        tls: tokio_native_tls::TlsConnector,
    }

    impl<'a, D: DNSResolver> TlsConnector<'a, D> {
        pub fn new(resolver: &'a D, tls: tokio_native_tls::TlsConnector) -> TlsConnector<'a, D> {
            TlsConnector { resolver, tls }
        }
    }

    #[async_trait]
    impl<D: DNSResolver + Sync> Connector<TlsWrappedTcpStream> for TlsConnector<'_, D> {
        async fn connect(&self, addr: &TargetAddr) -> io::Result<TlsWrappedTcpStream> {
            let stream = tcp_connect(addr, self.resolver).await?;
            let res = self
                .tls
                .connect(&addr.host(), stream)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
            Ok(TlsWrappedTcpStream::new(res))
        }
    }
}
