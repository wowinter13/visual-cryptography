//! Error types for visual cryptography operations

use std::{error::Error, fmt};

/// Result type alias for visual cryptography operations
pub type Result<T> = std::result::Result<T, VCError>;

/// Error types for visual cryptography operations
#[derive(Debug)]
pub enum VCError {
    /// Invalid configuration provided
    InvalidConfiguration(String),
    /// Insufficient shares to decrypt
    InsufficientShares { required: usize, provided: usize },
    /// Error during decryption
    DecryptionError(String),
    /// Error related to cover images
    CoverImageError(String),
    /// Image processing error
    ImageError(String),
    /// Matrix operation error
    MatrixError(String),
    /// QR code generation or processing error
    QrCodeError(String),
}

impl fmt::Display for VCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VCError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            VCError::InsufficientShares { required, provided } => {
                write!(
                    f,
                    "Insufficient shares: required {}, provided {}",
                    required, provided
                )
            }
            VCError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            VCError::CoverImageError(msg) => write!(f, "Cover image error: {}", msg),
            VCError::ImageError(msg) => write!(f, "Image error: {}", msg),
            VCError::MatrixError(msg) => write!(f, "Matrix error: {}", msg),
            VCError::QrCodeError(msg) => write!(f, "QR code error: {}", msg),
        }
    }
}

impl Error for VCError {}

impl From<image::ImageError> for VCError {
    fn from(err: image::ImageError) -> Self {
        VCError::ImageError(err.to_string())
    }
}
