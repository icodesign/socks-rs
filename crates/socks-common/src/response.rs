use crate::{Addr, AuthMethod, Error, Result, Version};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum ResponseCode {
    Success,
    GeneralSocksServerFailure,
    ConnectionNotAllowedByRuleset,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddrTypeNotSupported,
}

impl Into<u8> for ResponseCode {
    fn into(self) -> u8 {
        match self {
            ResponseCode::Success => 0x00,
            ResponseCode::GeneralSocksServerFailure => 0x01,
            ResponseCode::ConnectionNotAllowedByRuleset => 0x02,
            ResponseCode::NetworkUnreachable => 0x03,
            ResponseCode::HostUnreachable => 0x04,
            ResponseCode::ConnectionRefused => 0x05,
            ResponseCode::TtlExpired => 0x06,
            ResponseCode::CommandNotSupported => 0x07,
            ResponseCode::AddrTypeNotSupported => 0x08,
        }
    }
}

impl TryFrom<u8> for ResponseCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(ResponseCode::Success),
            0x01 => Ok(ResponseCode::NetworkUnreachable),
            0x02 => Ok(ResponseCode::ConnectionNotAllowedByRuleset),
            0x03 => Ok(ResponseCode::NetworkUnreachable),
            0x04 => Ok(ResponseCode::HostUnreachable),
            0x05 => Ok(ResponseCode::ConnectionRefused),
            0x06 => Ok(ResponseCode::TtlExpired),
            0x07 => Ok(ResponseCode::CommandNotSupported),
            0x08 => Ok(ResponseCode::AddrTypeNotSupported),
            _ => Err(Error::ResponseCodeNotSupported(value).into()),
        }
    }
}

#[derive(Debug)]
pub struct AuthMethodsResponse {
    pub version: Version,
    pub method: Option<AuthMethod>,
}

impl AuthMethodsResponse {
    pub fn new(version: Version, method: Option<AuthMethod>) -> AuthMethodsResponse {
        AuthMethodsResponse { version, method }
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let mut buf = BytesMut::with_capacity(1 + 1);
        buf.put_u8(self.version.into());
        match self.method {
            Some(method) => {
                buf.put_u8(method.into());
            }
            None => {
                buf.put_u8(0xff);
            }
        }
        writer.write_all(&buf).await?;
        Ok(())
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Send + Unpin,
    {
        let version_raw = reader.read_u8().await?;
        let version = Version::try_from(version_raw)?;
        let method_raw = reader.read_u8().await?;
        let method = AuthMethod::try_from(method_raw)?;
        Ok(AuthMethodsResponse::new(version, Some(method)))
    }
}

#[derive(Debug)]
pub struct Response {
    pub version: Version,
    pub code: ResponseCode,
    pub addr: Addr,
}

impl Response {
    pub fn new(version: Version, code: ResponseCode, addr: Addr) -> Response {
        Response {
            version,
            code,
            addr,
        }
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let mut buf = BytesMut::with_capacity(1 + 1 + self.addr.serialize_len());
        buf.put_u8(self.version.into());
        buf.put_u8(self.code.into());
        buf.put_u8(0x00);
        self.addr.write_to_buf(&mut buf)?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Send + Unpin,
    {
        let version_raw = reader.read_u8().await?;
        let version = Version::try_from(version_raw)?;
        let code_raw = reader.read_u8().await?;
        let code = ResponseCode::try_from(code_raw)?;
        // Reserved
        let _ = reader.read_u8().await?;
        let addr = Addr::read_from(reader).await?;
        Ok(Response {
            version,
            code,
            addr,
        })
    }
}
