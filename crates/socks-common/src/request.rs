use crate::{Addr, AuthMethod, Command, Error, Result, Version};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub struct AuthMethodsRequest {
    pub version: Version,
    pub methods: Vec<AuthMethod>,
}

impl AuthMethodsRequest {
    pub fn new(version: Version, methods: Vec<AuthMethod>) -> AuthMethodsRequest {
        AuthMethodsRequest { version, methods }
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let method_len = self.methods.len();
        if method_len > 255 {
            return Err(Error::TooManyMethods);
        }
        let mut buf = BytesMut::with_capacity(1 + 1 + method_len);
        buf.put_u8(self.version.into());
        buf.put_u8(method_len as u8);
        for method in self.methods.iter() {
            buf.put_u8((*method).into());
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
        let method_len = reader.read_u8().await?;
        let mut methods = Vec::<AuthMethod>::new();
        for _ in 0..method_len {
            let method_raw = reader.read_u8().await?;
            let method = AuthMethod::try_from(method_raw)?;
            methods.push(method);
        }
        Ok(AuthMethodsRequest { version, methods })
    }
}

#[derive(Debug)]
pub struct Request {
    pub version: Version,
    pub command: Command,
    pub addr: Addr,
}

impl Request {
    pub fn new(version: Version, command: Command, addr: Addr) -> Request {
        Request {
            version,
            command,
            addr,
        }
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Send + Unpin,
    {
        let mut buf = BytesMut::with_capacity(1 + 1 + self.addr.serialize_len());
        buf.put_u8(self.version.into());
        buf.put_u8(self.command.into());
        buf.put_u8(0x00);
        self.addr.write_to_buf(&mut buf)?;
        writer.write_all(&buf).await?;
        Ok(())
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Send + Unpin,
    {
        let venison_raw = reader.read_u8().await?;
        let version = Version::try_from(venison_raw)?;
        let command_raw = reader.read_u8().await?;
        let command = Command::try_from(command_raw)?;
        // Reserved
        let _ = reader.read_u8().await?;
        let addr = Addr::read_from(reader).await?;
        Ok(Request::new(version, command, addr))
    }
}
