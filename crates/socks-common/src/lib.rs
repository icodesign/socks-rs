pub mod addr;
pub mod connector;
pub mod error;
pub mod request;
pub mod response;

pub use addr::{Addr, TargetAddr};
pub use error::{Error, Result};

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum Version {
    V4,
    V5,
}

impl Into<u8> for Version {
    fn into(self) -> u8 {
        match self {
            Version::V4 => 0x04,
            Version::V5 => 0x05,
        }
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x04 => Ok(Version::V4),
            0x05 => Ok(Version::V5),
            _ => Err(Error::VersionNotSupported(value)),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AuthMethod {
    /// No authentication required.
    None,
    /// GSS API.
    GssApi,
    /// A username + password authentication.
    UsernamePassword,
    /// IANA reserved.
    IanaReserved(u8),
    /// A private authentication method.
    Private(u8),
}

impl Into<u8> for AuthMethod {
    fn into(self) -> u8 {
        match self {
            AuthMethod::None => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::IanaReserved(v) => v.to_owned(),
            AuthMethod::Private(v) => v.to_owned(),
        }
    }
}

impl TryFrom<u8> for AuthMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(AuthMethod::None),
            0x01 => Ok(AuthMethod::GssApi),
            0x02 => Ok(AuthMethod::UsernamePassword),
            0x03..=0x7f => Ok(AuthMethod::IanaReserved(value)),
            0x80..=0xfe => Ok(AuthMethod::Private(value)),
            _ => Err(Error::AuthMethodNotSupported(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyAuthScheme {
    None,
    BasicAuth(BasicAuthConfig),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicAuthConfig {
    username: String,
    password: String,
}

impl BasicAuthConfig {
    pub fn new(username: String, password: String) -> BasicAuthConfig {
        BasicAuthConfig { username, password }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Command::Connect => 0x01,
            Command::Bind => 0x02,
            Command::UdpAssociate => 0x03,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(Error::CommandNotSupported(value)),
        }
    }
}
