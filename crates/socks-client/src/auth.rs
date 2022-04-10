use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use socks_rs_common::{AuthMethod, Error, Result, Version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[async_trait]
pub trait AuthProvider {
    async fn methods(&self) -> Vec<AuthMethod>;
    async fn authenticate<IO: AsyncRead + AsyncWrite + Send + Unpin>(
        &self,
        version: Version,
        method: AuthMethod,
        io: &mut IO,
    ) -> Result<()>;
}

#[derive(Debug)]
pub(crate) struct PlainAuthProvider;

impl PlainAuthProvider {
    pub(crate) fn new() -> PlainAuthProvider {
        PlainAuthProvider {}
    }
}

#[async_trait]
impl AuthProvider for PlainAuthProvider {
    async fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::None]
    }

    async fn authenticate<IO: AsyncRead + AsyncWrite + Send + Unpin>(
        &self,
        version: Version,
        method: AuthMethod,
        _io: &mut IO,
    ) -> Result<()> {
        if version != Version::V5 {
            return Err(Error::VersionNotSupported(version.into()));
        }
        match method {
            AuthMethod::None => Ok(()),
            _ => Err(Error::AuthMethodNotSupported(method.into())),
        }
    }
}

#[derive(Debug)]
pub(crate) struct BasicAuthProvider<'a> {
    username: &'a str,
    password: &'a str,
}

impl<'a> BasicAuthProvider<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(username: &'a str, password: &'a str) -> BasicAuthProvider<'a> {
        BasicAuthProvider { username, password }
    }
}

#[async_trait]
impl<'a> AuthProvider for BasicAuthProvider<'a> {
    async fn methods(&self) -> Vec<AuthMethod> {
        vec![AuthMethod::None, AuthMethod::UsernamePassword]
    }

    async fn authenticate<IO: AsyncRead + AsyncWrite + Send + Unpin>(
        &self,
        version: Version,
        method: AuthMethod,
        io: &mut IO,
    ) -> Result<()> {
        if version != Version::V5 {
            return Err(Error::VersionNotSupported(version.into()));
        }
        match method {
            AuthMethod::None => Ok(()),
            AuthMethod::UsernamePassword => {
                let (mut inbound, mut outbound) = tokio::io::split(io);
                let username_bytes = self.username.as_bytes();
                let ulen = username_bytes.len();
                let password_bytes = self.password.as_bytes();
                let plen = password_bytes.len();
                if ulen > 255 {
                    return Err(Error::AuthFailed("username is too long".to_owned()));
                }
                if plen > 255 {
                    return Err(Error::AuthFailed("password is too long".to_owned()));
                }
                let mut buf = BytesMut::with_capacity(1 + 1 + ulen + 1 + plen);
                buf.put_u8(0x01);
                buf.put_u8(ulen as u8);
                buf.put_slice(username_bytes);
                buf.put_u8(plen as u8);
                buf.put_slice(password_bytes);
                outbound.write_all(&buf).await?;
                // version
                let _ = inbound.read_u8().await?;
                let res = inbound.read_u8().await?;
                if res == 0x00 {
                    Ok(())
                } else {
                    return Err(Error::AuthFailed("incorrect credential".to_owned()));
                }
            }
            _ => Err(Error::AuthMethodNotSupported(method.into())),
        }
    }
}
