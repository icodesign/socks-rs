use crate::TargetAddr;
use async_trait::async_trait;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[async_trait]
pub trait DNSResolver {
    async fn resolve(&self, addr: &TargetAddr) -> io::Result<Vec<SocketAddr>>;
}

pub trait WrappedTcpStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn get_stream_ref(&self) -> &TcpStream;
    fn get_stream_mut_ref(&mut self) -> &mut TcpStream;
}

macro_rules! async_read_proxy_impl {
    () => {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    };
}

macro_rules! async_write_proxy_impl {
    () => {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
        }
    };
}

pub struct PlainWrappedTcpStream {
    inner: TcpStream,
}

impl PlainWrappedTcpStream {
    pub fn new(inner: TcpStream) -> PlainWrappedTcpStream {
        PlainWrappedTcpStream { inner }
    }
}

impl AsyncRead for PlainWrappedTcpStream {
    async_read_proxy_impl!();
}

impl AsyncWrite for PlainWrappedTcpStream {
    async_write_proxy_impl!();
}

impl WrappedTcpStream for PlainWrappedTcpStream {
    fn get_stream_ref(&self) -> &TcpStream {
        &self.inner
    }

    fn get_stream_mut_ref(&mut self) -> &mut TcpStream {
        &mut self.inner
    }
}

pub async fn tcp_connect<D: DNSResolver>(addr: &TargetAddr, resolver: &D) -> io::Result<TcpStream> {
    let remote_addr = resolver.resolve(addr).await?;
    let mut err: io::Result<TcpStream> = Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "Couldn't resolve addr: result is empty",
    ));
    for addr in remote_addr {
        match TcpStream::connect(addr).await {
            Ok(socket) => {
                return Ok(socket);
            }
            Err(e) => {
                err = Err(e);
            }
        }
    }
    err
}

#[cfg(feature = "tls")]
pub mod tls {
    use crate::connector::WrappedTcpStream;
    use std::io::IoSlice;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io;
    use tokio::io::ReadBuf;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;
    use tokio_native_tls::TlsStream;

    pub struct TlsWrappedTcpStream {
        inner: TlsStream<TcpStream>,
    }

    impl TlsWrappedTcpStream {
        pub fn new(inner: TlsStream<TcpStream>) -> TlsWrappedTcpStream {
            TlsWrappedTcpStream { inner }
        }
    }

    impl AsyncRead for TlsWrappedTcpStream {
        async_read_proxy_impl!();
    }

    impl AsyncWrite for TlsWrappedTcpStream {
        async_write_proxy_impl!();
    }

    impl WrappedTcpStream for TlsWrappedTcpStream {
        fn get_stream_ref(&self) -> &TcpStream {
            self.inner.get_ref().get_ref().get_ref()
        }

        fn get_stream_mut_ref(&mut self) -> &mut TcpStream {
            self.inner.get_mut().get_mut().get_mut()
        }
    }
}
