//! Error types for the system info library

use thiserror::Error;

/// Result type alias for this library
pub type Result<T> = std::result::Result<T, SysInfoError>;

/// Error types that can occur when querying system information
#[derive(Error, Debug)]
pub enum SysInfoError {
    /// IO error when reading system files or making system calls
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Error parsing system information
    #[error("Parse error: {0}")]
    Parse(String),

    /// Error when a system call fails
    #[error("System call failed: {0}")]
    SysCall(String),

    /// Feature not supported on this platform
    #[error("Not supported on this platform: {0}")]
    NotSupported(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Process not found
    #[error("Process not found: pid {0}")]
    ProcessNotFound(u32),

    /// Netlink error (Linux specific)
    #[error("Netlink error: {0}")]
    Netlink(String),

    /// Windows API error
    #[error("Windows API error: {0}")]
    WindowsApi(String),
}
