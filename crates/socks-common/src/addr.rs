use crate::{Error, Result};
use bytes::BufMut;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum AddrType {
    Ipv4,
    Domain,
    Ipv6,
}

impl Into<u8> for AddrType {
    fn into(self) -> u8 {
        match self {
            AddrType::Ipv4 => 0x01,
            AddrType::Domain => 0x03,
            AddrType::Ipv6 => 0x04,
        }
    }
}

impl TryFrom<u8> for AddrType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddrType::Ipv4),
            0x03 => Ok(AddrType::Domain),
            0x04 => Ok(AddrType::Ipv6),
            _ => Err(Error::AddrTypeNotSupported(value)),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum TargetAddr {
    Host(String, u16),
    Addr(SocketAddr),
}

impl TargetAddr {
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Host(host, _) => host.to_owned(),
            TargetAddr::Addr(addr) => addr.ip().to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match *self {
            TargetAddr::Host(_, port) => port,
            TargetAddr::Addr(addr) => addr.port(),
        }
    }

    pub fn unwrap_addr(&self) -> SocketAddr {
        match *self {
            TargetAddr::Host(_, _) => panic!("Invalid destination type"),
            TargetAddr::Addr(addr) => addr,
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        TargetAddr::Addr(addr)
    }
}

impl From<(&str, u16)> for TargetAddr {
    fn from(pair: (&str, u16)) -> Self {
        TargetAddr::Host(pair.0.to_owned(), pair.1)
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Host(addr, port) => {
                write!(f, "({}:{})", addr, port)
            }
            TargetAddr::Addr(addr) => {
                write!(f, "({})", addr.to_string())
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Addr(TargetAddr);

impl Addr {
    pub fn new(dest: TargetAddr) -> Addr {
        Addr(dest)
    }

    pub fn inner(&self) -> &TargetAddr {
        &self.0
    }

    pub fn is_dummy(&self) -> bool {
        match &self.0 {
            TargetAddr::Addr(SocketAddr::V4(addr)) => {
                addr.ip().is_unspecified() || addr.port() == 0
            }
            TargetAddr::Addr(SocketAddr::V6(addr)) => {
                addr.ip().is_unspecified() || addr.port() == 0
            }
            TargetAddr::Host(_, _) => false,
        }
    }

    pub fn serialize_len(&self) -> usize {
        match &self.0 {
            TargetAddr::Addr(SocketAddr::V4(_)) => 1 + 4 + 2,
            TargetAddr::Addr(SocketAddr::V6(_)) => 1 + 16 + 2,
            TargetAddr::Host(domain, _) => 1 + 1 + domain.as_bytes().len() + 2,
        }
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        match &self.0 {
            TargetAddr::Addr(SocketAddr::V4(addr)) => {
                buf.put_u8(AddrType::Ipv4.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            TargetAddr::Addr(SocketAddr::V6(addr)) => {
                buf.put_u8(AddrType::Ipv6.into());
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            TargetAddr::Host(domain, port) => {
                buf.put_u8(AddrType::Domain.into());
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(Error::DomainTooLong.into());
                }
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
                buf.put_u16(*port);
            }
        }
        Ok(())
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let addr_type_raw = reader.read_u8().await?;
        let addr_type = AddrType::try_from(addr_type_raw)?;
        let addr = match addr_type {
            AddrType::Ipv4 => {
                let mut ip = [0; 4];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                TargetAddr::Addr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            AddrType::Ipv6 => {
                let mut ip = [0; 16];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                TargetAddr::Addr(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            AddrType::Domain => {
                let len = reader.read_u8().await?;
                let mut str = Vec::with_capacity(len as usize);
                reader.read_exact(&mut str).await?;
                let domain = String::from_utf8(str).map_err(|e| Error::InvalidDomain(e))?;
                let port = reader.read_u16().await?;
                TargetAddr::Host(domain, port)
            }
        };
        Ok(Addr(addr))
    }
}
