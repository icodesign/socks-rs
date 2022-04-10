use async_trait::async_trait;
use bytes::BytesMut;
use socks_rs_common::{AuthMethod, Error, Result, Version};
use tokio::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[async_trait]
pub trait AuthProvider {
    async fn select(&self, methods: &[AuthMethod]) -> Result<AuthMethod>;
    async fn validate<IO: AsyncRead + AsyncWrite + Send + Unpin>(
        &self,
        version: Version,
        method: AuthMethod,
        io: &mut IO,
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct PlainAuthProvider;

impl PlainAuthProvider {
    pub fn new() -> PlainAuthProvider {
        PlainAuthProvider {}
    }
}

#[async_trait]
impl AuthProvider for PlainAuthProvider {
    async fn select(&self, methods: &[AuthMethod]) -> Result<AuthMethod> {
        let res = methods.iter().find(|&&x| x == AuthMethod::None);
        if res.is_some() {
            Ok(AuthMethod::None)
        } else {
            Err(Error::AuthMethodNotSupported(0xff))
        }
    }

    async fn validate<IO: AsyncRead + AsyncWrite + Send + Unpin>(
        &self,
        _version: Version,
        _method: AuthMethod,
        _io: &mut IO,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct BasicAuthProvider {
    username: String,
    password: String,
}

impl BasicAuthProvider {
    pub fn new(username: &str, password: &str) -> BasicAuthProvider {
        BasicAuthProvider {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }
}

#[async_trait]
impl AuthProvider for BasicAuthProvider {
    async fn select(&self, methods: &[AuthMethod]) -> Result<AuthMethod> {
        let res = methods.iter().find(|&&x| x == AuthMethod::UsernamePassword);
        if res.is_some() {
            return Ok(AuthMethod::UsernamePassword);
        }
        Err(Error::AuthMethodNotSupported(0xff))
    }

    async fn validate<IO: AsyncRead + AsyncWrite + Send + Unpin>(
        &self,
        version: Version,
        method: AuthMethod,
        conn: &mut IO,
    ) -> Result<()> {
        let (mut inbound, mut outbound) = io::split(conn);
        if version != Version::V5 {
            auth_respond(version, false, &mut outbound).await?;
            return Err(Error::VersionNotSupported(version.into()));
        }
        match method {
            AuthMethod::UsernamePassword => {
                auth_validate(
                    version,
                    &self.username,
                    &self.password,
                    &mut inbound,
                    &mut outbound,
                )
                .await
            }
            _ => {
                auth_respond(version, false, &mut outbound).await?;
                Err(Error::AuthMethodNotSupported(method.into()))
            }
        }
    }
}

async fn auth_validate<R, W>(
    version: Version,
    username: &str,
    password: &str,
    inbound: &mut R,
    outbound: &mut W,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let auth_version_raw = inbound.read_u8().await?;
    if auth_version_raw != 0x01 {
        return Err(Error::VersionNotSupported(auth_version_raw));
    }
    let ulen = inbound.read_u8().await?;
    let mut ubuff = BytesMut::with_capacity(ulen as usize);
    inbound.read_buf(&mut ubuff).await?;
    let plen = inbound.read_u8().await?;
    let mut pbuff = BytesMut::with_capacity(plen as usize);
    inbound.read_buf(&mut pbuff).await?;
    if username.as_bytes() == &ubuff[..] && password.as_bytes() == &pbuff[..] {
        auth_respond(version, true, outbound).await
    } else {
        auth_respond(version, false, outbound).await?;
        Err(Error::AuthFailed("incorrect credentials".to_owned()))
    }
}

async fn auth_respond<T>(version: Version, success: bool, outbound: &mut T) -> Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let res = if success { 0x00 } else { 0x01 };
    outbound.write_all(&[version.into(), res]).await?;
    Ok(())
}
