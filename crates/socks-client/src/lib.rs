use crate::auth::{AuthProvider, BasicAuthProvider, PlainAuthProvider};
use crate::connector::Connector;
use socks_rs_common::connector::WrappedTcpStream;
use socks_rs_common::request::{AuthMethodsRequest, Request};
use socks_rs_common::response::{AuthMethodsResponse, Response, ResponseCode};
use socks_rs_common::{
    Addr, BasicAuthConfig, Command, Error, ProxyAuthScheme, Result, TargetAddr, Version,
};
use log::{debug, warn};
use std::time::Instant;
use tokio::io::{self, AsyncRead, AsyncWrite};

pub mod auth;
pub mod connector;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyScheme {
    version: Version,
    addr: TargetAddr,
    auth: ProxyAuthScheme,
}

impl ProxyScheme {
    pub fn new(version: Version, addr: TargetAddr) -> ProxyScheme {
        ProxyScheme {
            version,
            addr,
            auth: ProxyAuthScheme::None,
        }
    }

    pub fn new_with_basic_auth(
        version: Version,
        addr: TargetAddr,
        username: String,
        password: String,
    ) -> ProxyScheme {
        ProxyScheme {
            version,
            addr,
            auth: ProxyAuthScheme::BasicAuth(BasicAuthConfig::new(username, password)),
        }
    }

    pub fn addr(&self) -> &TargetAddr {
        &self.addr
    }
}

pub struct SocksClient;

impl SocksClient {
    pub async fn connect<T: WrappedTcpStream, C: Connector<T>, AU: AuthProvider>(
        scheme: &ProxyScheme,
        target: TargetAddr,
        command: Command,
        connector: C,
    ) -> Result<(Response, T)> {
        let target = Addr::new(target);
        match &scheme.auth {
            ProxyAuthScheme::None => {
                SocksClient::connect_inner(
                    scheme,
                    target,
                    command,
                    connector,
                    PlainAuthProvider::new(),
                )
                .await
            }
            ProxyAuthScheme::BasicAuth(cfg) => {
                SocksClient::connect_inner(
                    scheme,
                    target,
                    command,
                    connector,
                    BasicAuthProvider::new(cfg.username(), cfg.password()),
                )
                .await
            }
        }
    }

    /// Connect the client to target address via proxy scheme, using a specific connector
    async fn connect_inner<T: WrappedTcpStream, C: Connector<T>, AU: AuthProvider>(
        scheme: &ProxyScheme,
        target: Addr,
        command: Command,
        connector: C,
        auth_provider: AU,
    ) -> Result<(Response, T)> {
        debug!("Connecting to proxy...");
        let start = Instant::now();
        let proxy_addr = scheme.addr();
        let mut connection = connector.connect(proxy_addr).await?;
        debug!("Connected to proxy, took {:?} seconds", start.elapsed());

        // Enable TCP nodelay
        let nodelay = connection.get_stream_ref().nodelay();
        if let Err(e) = &nodelay {
            warn!("Couldn't fetch tcp_nodelay status: {:?}", e);
        } else {
            if let Err(e) = connection.get_stream_mut_ref().set_nodelay(true) {
                warn!("Couldn't enable tcp_nodelay: {:?}", e);
            }
        }

        // Socks handshake
        debug!("Handshaking with proxy server...");
        let response = SocksClient::handshake(
            target,
            command,
            scheme.version,
            &mut connection,
            &auth_provider,
        )
        .await?;
        debug!("Successfully handshake with proxy");

        // Reset TCP nodelay
        if let Ok(enabled) = nodelay {
            if let Err(e) = connection.get_stream_mut_ref().set_nodelay(enabled) {
                warn!("Couldn't reset tcp_nodelay to {}: {:?}", enabled, e);
            }
        }

        Ok((response, connection))
    }

    /// Handshake with proxy server
    async fn handshake<IO: AsyncRead + AsyncWrite + Send + Unpin, AU: AuthProvider>(
        target: Addr,
        command: Command,
        version: Version,
        connection: &mut IO,
        auth_provider: &AU,
    ) -> Result<Response> {
        let (mut inbound, mut outbound) = io::split(connection);
        let methods = auth_provider.methods().await;
        debug!(
            "Writing auth methods: {:?}, version: {:?}",
            methods, version
        );
        let auth_methods_request = AuthMethodsRequest::new(version, methods);
        debug!("Sending auth method request: {:?}", auth_methods_request);
        auth_methods_request.write_to(&mut outbound).await?;
        let auth_methods_response = AuthMethodsResponse::read_from(&mut inbound).await?;
        debug!(
            "Received server auth method response: {:?}",
            auth_methods_response
        );
        let method_res = auth_methods_response.method;
        if method_res.is_none() {
            warn!("No auth method is supported");
            return Err(Error::NoAuthMethodSupported);
        }
        let method = method_res.unwrap();
        debug!("Selected auth method: {:?}", method);
        let connection = inbound.unsplit(outbound);
        debug!("Authenticating with proxy server...");
        auth_provider
            .authenticate(version, method, connection)
            .await?;
        debug!("Authenticated successfully");
        let (mut inbound, mut outbound) = io::split(connection);
        let request = Request::new(version, command, target);
        debug!("Sending request: {:?}", request);
        request.write_to(&mut outbound).await?;
        let response = Response::read_from(&mut inbound).await?;
        debug!("Received server response: {:?}", response);
        if response.code != ResponseCode::Success {
            warn!(
                "Received unsuccessful server response code: {:?}",
                response.code
            );
            return Err(Error::ConnectionFailed(response.code));
        }
        Ok(response)
    }
}
