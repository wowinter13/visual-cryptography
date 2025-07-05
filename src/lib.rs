//! Visual Cryptography Library
//!
//! This library implements various visual cryptography algorithms including:
//! - Basic (k,n) threshold schemes
//! - Progressive visual cryptography
//! - Support for binary, greyscale, and color images
//! - Configurable block sizes

pub mod algorithms;
pub mod error;
pub mod matrix;
pub mod share;
pub mod utils;

pub use algorithms::{Algorithm, VCScheme};
pub use error::{Result, VCError};
pub use share::{Share, ShareType};

// Re-export common types
pub use image::{DynamicImage, ImageBuffer, Luma, Rgb, Rgba};

/// Configuration for visual cryptography operations
#[derive(Debug, Clone)]
pub struct VCConfig {
    /// Number of shares to generate
    pub num_shares: usize,
    /// Minimum shares needed to reconstruct (k in (k,n) scheme)
    pub threshold: usize,
    /// Block size for pixel expansion (e.g., 2 for 2x2, 3 for 3x3)
    pub block_size: usize,
    /// Algorithm to use
    pub algorithm: Algorithm,
    /// Whether to use meaningful shares (with cover images)
    pub use_meaningful_shares: bool,
}

impl Default for VCConfig {
    fn default() -> Self {
        Self {
            num_shares: 2,
            threshold: 2,
            block_size: 2,
            algorithm: Algorithm::BasicThreshold,
            use_meaningful_shares: false,
        }
    }
}

/// Main struct for visual cryptography operations
pub struct VisualCryptography {
    config: VCConfig,
}

impl VisualCryptography {
    /// Create a new VisualCryptography instance with the given configuration
    pub fn new(config: VCConfig) -> Result<Self> {
        if config.threshold > config.num_shares {
            return Err(VCError::InvalidConfiguration(
                "Threshold cannot be greater than number of shares".to_string(),
            ));
        }
        if config.threshold == 0 || config.num_shares == 0 {
            return Err(VCError::InvalidConfiguration(
                "Threshold and number of shares must be greater than 0".to_string(),
            ));
        }
        if config.block_size == 0 {
            return Err(VCError::InvalidConfiguration(
                "Block size must be greater than 0".to_string(),
            ));
        }

        Ok(Self { config })
    }

    /// Encrypt an image into shares
    pub fn encrypt(
        &self,
        image: &DynamicImage,
        cover_images: Option<Vec<DynamicImage>>,
    ) -> Result<Vec<Share>> {
        algorithms::encrypt(image, &self.config, cover_images)
    }

    /// Decrypt shares back into an image
    pub fn decrypt(&self, shares: &[Share]) -> Result<DynamicImage> {
        if shares.len() < self.config.threshold {
            return Err(VCError::InsufficientShares {
                required: self.config.threshold,
                provided: shares.len(),
            });
        }
        algorithms::decrypt(shares, &self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        // Valid config
        let config = VCConfig {
            num_shares: 3,
            threshold: 2,
            block_size: 2,
            algorithm: Algorithm::BasicThreshold,
            use_meaningful_shares: false,
        };
        assert!(VisualCryptography::new(config).is_ok());

        // Invalid: threshold > num_shares
        let config = VCConfig {
            num_shares: 2,
            threshold: 3,
            ..Default::default()
        };
        assert!(VisualCryptography::new(config).is_err());

        // Invalid: zero threshold
        let config = VCConfig {
            threshold: 0,
            ..Default::default()
        };
        assert!(VisualCryptography::new(config).is_err());
    }
}
