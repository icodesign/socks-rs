use crate::acceptor::Acceptor;
use crate::auth::{AuthProvider, BasicAuthProvider, PlainAuthProvider};
use socks_rs_common::connector::{tcp_connect, DNSResolver, WrappedTcpStream};
use socks_rs_common::request::{AuthMethodsRequest, Request};
use socks_rs_common::response::{AuthMethodsResponse, Response, ResponseCode};
use socks_rs_common::{Addr, Command, Error, ProxyAuthScheme, Result, TargetAddr, Version};
use log::{debug, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::runtime::Handle;

pub mod acceptor;
pub mod auth;
mod relay;

pub struct SocksServer;

impl SocksServer {
    // pub async fn start_no_auth<
    //     T: ToSocketAddrs,
    //     S: WrappedTcpStream + Send + Sync + Unpin + 'static,
    //     A: Acceptor<S> + Send + Sync + 'static,
    //     D: DNSResolver + Send + Sync + 'static,
    // >(
    //     addr: T,
    //     acceptor: A,
    //     resolver: D,
    //     handle: Handle,
    // ) -> Result<SocksServer> {
    //     info!("Starting Socks server with no authentication...");
    //     SocksServer::start(
    //         addr,
    //         PlainAuthProvider::new(),
    //         acceptor,
    //         resolver,
    //         handle,
    //     )
    //         .await
    // }

    pub async fn start<
        T: ToSocketAddrs,
        S: WrappedTcpStream + Send + Sync + Unpin + 'static,
        A: Acceptor<S> + Send + Sync + 'static,
        D: DNSResolver + Send + Sync + 'static,
    >(
        addr: T,
        scheme: ProxyAuthScheme,
        acceptor: A,
        resolver: D,
        handle: Handle,
    ) -> Result<SocksServer> {
        match scheme {
            ProxyAuthScheme::None => {
                SocksServer::start_inner(addr, PlainAuthProvider::new(), acceptor, resolver, handle)
                    .await
            }
            ProxyAuthScheme::BasicAuth(cfg) => {
                SocksServer::start_inner(
                    addr,
                    BasicAuthProvider::new(cfg.username(), cfg.password()),
                    acceptor,
                    resolver,
                    handle,
                )
                .await
            }
        }
    }

    async fn start_inner<
        T: ToSocketAddrs,
        U: AuthProvider + Send + Sync + 'static,
        S: WrappedTcpStream + Send + Sync + Unpin + 'static,
        A: Acceptor<S> + Send + Sync + 'static,
        D: DNSResolver + Send + Sync + 'static,
    >(
        addr: T,
        auth_provider: U,
        acceptor: A,
        resolver: D,
        handle: Handle,
    ) -> Result<SocksServer> {
        info!("Starting Socks server...");
        let listener = TcpListener::bind(addr).await?;
        SocksServer::start_with_listener(listener, auth_provider, acceptor, resolver, handle).await
    }

    pub async fn start_with_listener<
        U: AuthProvider + Send + Sync + 'static,
        S: WrappedTcpStream + Send + Sync + Unpin + 'static,
        A: Acceptor<S> + Send + Sync + 'static,
        D: DNSResolver + Send + Sync + 'static,
    >(
        listener: TcpListener,
        auth_provider: U,
        acceptor: A,
        resolver: D,
        handle: Handle,
    ) -> Result<SocksServer> {
        let local_addr = listener.local_addr()?;
        info!("Socks server listening at {:?}", &local_addr);
        let server_auth_provider = Arc::new(auth_provider);
        let resolver = Arc::new(resolver);
        let acceptor = Arc::new(acceptor);
        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    let auth_provider = server_auth_provider.clone();
                    let resolver_inner = resolver.clone();
                    let acceptor_inner = acceptor.clone();
                    handle.spawn(async move {
                        let socket = match acceptor_inner.accept(socket).await {
                            Err(e) => {
                                warn!("Couldn't accept TCP socket with acceptor: {:?}", e);
                                return;
                            }
                            Ok(socket) => socket,
                        };
                        debug!(
                            "Accepted connection from {:?}",
                            socket.get_stream_ref().peer_addr()
                        );
                        let identifier = format!(
                            "[{:?} -> {:?}]",
                            socket.get_stream_ref().peer_addr(),
                            socket.get_stream_ref().local_addr()
                        );
                        let mut connection =
                            SocksConnection::new(identifier, socket, auth_provider);
                        connection.process(resolver_inner).await;
                    });
                }
                Err(e) => {
                    println!("couldn't accept new client: {:?}", e);
                    continue;
                }
            }
        }
    }
}

struct SocksConnection<S: WrappedTcpStream, T: AuthProvider> {
    identifier: String,
    socket: S,
    auth_provider: Arc<T>,
}

impl<S: WrappedTcpStream + Send + Sync + Unpin, T: AuthProvider> SocksConnection<S, T> {
    fn new(identifier: String, socket: S, auth_provider: Arc<T>) -> SocksConnection<S, T> {
        SocksConnection {
            identifier,
            socket,
            auth_provider,
        }
    }

    async fn process<D: DNSResolver>(&mut self, resolver: Arc<D>) {
        let nodelay = self.socket.get_stream_ref().nodelay();
        if let Err(e) = self.socket.get_stream_mut_ref().set_nodelay(true) {
            warn!("Couldn't enable tcp_nodelay: {:?}", e);
        }
        let res = self.handshake(&resolver).await;
        match nodelay {
            Ok(nodelay) => {
                if let Err(e) = self.socket.get_stream_mut_ref().set_nodelay(nodelay) {
                    warn!("Couldn't disable tcp_nodelay: {:?}", e);
                }
            }
            Err(e) => {
                warn!("Couldn't fetch tcp_nodelay status: {:?}", e);
            }
        }
        match res {
            Ok(outbound) => {
                let _ = self.relay(outbound).await;
            }
            Err(err) => {
                warn!(
                    "{}: Socks connection handshake failed: {:?}",
                    self.identifier, err
                );
                let _ = self.socket.get_stream_mut_ref().shutdown().await;
                return;
            }
        }
    }

    async fn handshake<D: DNSResolver>(&mut self, resolver: &Arc<D>) -> Result<TcpStream> {
        let (mut inbound, mut outbound) = io::split(&mut self.socket);
        debug!("{}: Reading auth methods request...", &self.identifier);
        let auth_method_request = AuthMethodsRequest::read_from(&mut inbound).await?;
        debug!(
            "{}: Received auth methods request: {:?}",
            &self.identifier, auth_method_request
        );
        let version = auth_method_request.version;
        if version != Version::V5 {
            return Err(Error::VersionNotSupported(
                auth_method_request.version.into(),
            ));
        }
        let methods = auth_method_request.methods;
        debug!(
            "{}: {:?} socks auth methods",
            &self.identifier,
            methods.len()
        );
        let auth_provider = self.auth_provider.clone();
        let method = auth_provider.select(&methods[..]).await;
        if method.is_err() {
            let response = AuthMethodsResponse::new(version, None);
            response.write_to(&mut outbound).await?;
            return Err(method.unwrap_err());
        }
        let method = method.unwrap();
        debug!(
            "{}: Select socks auth method: {:?}",
            &self.identifier, method
        );
        let response = AuthMethodsResponse::new(version, Some(method));
        response.write_to(&mut outbound).await?;
        let connection = inbound.unsplit(outbound);
        auth_provider.validate(version, method, connection).await?;
        let (mut inbound, _) = io::split(connection);
        debug!("{}: Reading socks request...", &self.identifier);
        let request = Request::read_from(&mut inbound).await?;
        debug!(
            "{}: Received socks request: {:?}",
            &self.identifier, request
        );
        debug!(
            "{}: Making request to upstream: {:?}...",
            &self.identifier, request.addr
        );
        return match request.command {
            Command::Connect => self.handle_connect_command(request, resolver).await,
            Command::Bind => self.handle_bind_command(request).await,
            Command::UdpAssociate => self.handle_udp_associate_command(request).await,
        };
    }

    async fn handle_connect_command<D: DNSResolver>(
        &mut self,
        request: Request,
        resolver: &Arc<D>,
    ) -> Result<TcpStream> {
        let (_, mut outbound) = io::split(&mut self.socket);
        let target_addr = request.addr.inner();
        let remote_conn_res = tcp_connect(target_addr, resolver.as_ref()).await;
        let addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let conn = match remote_conn_res {
            Ok(remote_conn) => {
                debug!("{}: Connected to upstream", &self.identifier);
                let response = Response::new(
                    request.version,
                    ResponseCode::Success,
                    Addr::new(TargetAddr::Addr(addr)),
                );
                debug!("{}: Send socks response: {:?}", &self.identifier, response);
                response.write_to(&mut outbound).await?;
                Ok(remote_conn)
            }
            Err(e) => {
                debug!("{}: Could not connect to upstream", &self.identifier);
                let response = Response::new(
                    request.version,
                    ResponseCode::NetworkUnreachable,
                    Addr::new(TargetAddr::Addr(addr)),
                );
                response.write_to(&mut outbound).await?;
                Err(e)
            }
        }?;
        Ok(conn)
    }

    async fn handle_bind_command(&self, request: Request) -> Result<TcpStream> {
        Err(Error::CommandNotSupported(request.command.into()))
    }

    async fn handle_udp_associate_command(&self, request: Request) -> Result<TcpStream> {
        Err(Error::CommandNotSupported(request.command.into()))
    }

    async fn relay(&mut self, mut outbound: TcpStream) -> io::Result<()> {
        warn!("Starting relay...");
        let (written, received) = relay::relay(&mut self.socket, &mut outbound).await?;
        debug!(
            "Client wrote {} bytes and received {} bytes",
            written, received
        );
        Ok(())
    }
}
