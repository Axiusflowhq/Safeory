#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("platform capability is unavailable")]
    Unavailable,
    #[error("platform operation failed")]
    OperationFailed,
}

pub trait SecureKeyStore {
    fn store(&self, key_id: &str, secret: &[u8]) -> Result<(), PlatformError>;
    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>, PlatformError>;
    fn delete(&self, key_id: &str) -> Result<(), PlatformError>;
}

pub trait Clipboard {
    fn set_secret(&self, value: &str) -> Result<(), PlatformError>;
    fn clear(&self) -> Result<(), PlatformError>;
}
