use crate::response::ResponseCode;
use std::string::FromUtf8Error;
use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("version is not supported: {0}")]
    VersionNotSupported(u8),
    #[error("auth method is not supported: {0}")]
    AuthMethodNotSupported(u8),
    #[error("too many methods")]
    TooManyMethods,
    #[error("command is not supported: {0}")]
    CommandNotSupported(u8),
    #[error("addr type is not supported: {0}")]
    AddrTypeNotSupported(u8),
    #[error("domain name is too long")]
    DomainTooLong,
    #[error("invalid domain: {0}")]
    InvalidDomain(FromUtf8Error),
    #[error("response code is not supported: {0}")]
    ResponseCodeNotSupported(u8),
    #[error("no auth method is supported")]
    NoAuthMethodSupported,
    #[error("auth failed: {0}")]
    AuthFailed(String),
    #[error("connection failed with response code: {0:?}")]
    ConnectionFailed(ResponseCode),
}
