//! QR code integration for visual cryptography (QEVCS)
//!
//! This module implements the QR code-based Expansion-free Extended Visual
//! Cryptography Scheme (QEVCS) as described in the research paper.

use crate::{
    error::{Result, VCError},
    share::Share,
    utils::{convert_to_binary, resize_to_match},
};
use image::{DynamicImage, GenericImageView, ImageBuffer, Luma, Rgb};
use qrcode::{EcLevel, QrCode};

/// QR code error correction levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrErrorCorrection {
    Low,      // ~7%
    Medium,   // ~15%
    Quartile, // ~25%
    High,     // ~30%
}

impl From<QrErrorCorrection> for EcLevel {
    fn from(level: QrErrorCorrection) -> Self {
        match level {
            QrErrorCorrection::Low => EcLevel::L,
            QrErrorCorrection::Medium => EcLevel::M,
            QrErrorCorrection::Quartile => EcLevel::Q,
            QrErrorCorrection::High => EcLevel::H,
        }
    }
}

/// Configuration for QR code-based visual cryptography
#[derive(Debug, Clone)]
pub struct QrVcConfig {
    /// Error correction level for QR codes
    pub error_correction: QrErrorCorrection,
    /// Size of each QR code module in pixels
    pub module_size: u32,
    /// Border size around QR code
    pub border: u32,
    /// Whether to embed shares in error correction area
    pub use_error_correction_embedding: bool,
    /// Maximum data capacity utilization (0.0 to 1.0)
    pub data_capacity_ratio: f32,
}

impl Default for QrVcConfig {
    fn default() -> Self {
        Self {
            error_correction: QrErrorCorrection::Medium,
            module_size: 4,
            border: 4,
            use_error_correction_embedding: true,
            data_capacity_ratio: 0.8,
        }
    }
}

/// QR code with embedded visual cryptography share
#[derive(Debug, Clone)]
pub struct QrShare {
    /// The visual cryptography share
    pub share: Share,
    /// The QR code data
    pub qr_data: String,
    /// The combined QR code image
    pub qr_image: DynamicImage,
    /// Metadata about the embedding
    pub metadata: QrEmbeddingMetadata,
}

/// Metadata about QR code embedding
#[derive(Debug, Clone)]
pub struct QrEmbeddingMetadata {
    /// Original QR code dimensions
    pub original_qr_size: (u32, u32),
    /// Share dimensions
    pub share_size: (u32, u32),
    /// Number of bits embedded in error correction area
    pub embedded_bits: usize,
    /// QR code version
    pub qr_version: String,
    /// Data capacity utilization
    pub capacity_used: f32,
}

/// QR code-based visual cryptography processor
pub struct QrVisualCryptography {
    config: QrVcConfig,
}

impl QrVisualCryptography {
    /// Create a new QR-based visual cryptography processor
    pub fn new(config: QrVcConfig) -> Self {
        Self { config }
    }

    /// Generate QR codes with embedded visual cryptography shares
    pub fn generate_qr_shares(&self, shares: &[Share], qr_data: &[String]) -> Result<Vec<QrShare>> {
        if shares.len() != qr_data.len() {
            return Err(VCError::InvalidConfiguration(
                "Number of shares must match number of QR data strings".to_string(),
            ));
        }

        let mut qr_shares = Vec::new();

        for (share, data) in shares.iter().zip(qr_data.iter()) {
            let qr_share = self.embed_share_in_qr(share, data)?;
            qr_shares.push(qr_share);
        }

        Ok(qr_shares)
    }

    /// Embed a visual cryptography share into a QR code
    fn embed_share_in_qr(&self, share: &Share, qr_data: &str) -> Result<QrShare> {
        // Generate base QR code
        let qr_code =
            QrCode::with_error_correction_level(qr_data, self.config.error_correction.into())
                .map_err(|e| VCError::QrCodeError(format!("Failed to generate QR code: {}", e)))?;

        // Convert QR code to image
        let qr_image = self.qr_to_image(&qr_code);
        let (qr_width, qr_height) = qr_image.dimensions();

        // Resize share to match QR code dimensions
        let resized_share = resize_to_match(&share.image, qr_width, qr_height);
        let share_binary = convert_to_binary(&resized_share);

        // Embed share data using the QEVCS algorithm
        let embedded_image = if self.config.use_error_correction_embedding {
            self.embed_using_error_correction(&qr_image, &share_binary, &qr_code)?
        } else {
            self.embed_using_module_replacement(&qr_image, &share_binary)?
        };

        let metadata = QrEmbeddingMetadata {
            original_qr_size: (qr_width, qr_height),
            share_size: share.dimensions(),
            embedded_bits: self.count_embedded_bits(&share_binary),
            qr_version: format!("{:?}", qr_code.version()),
            capacity_used: self.calculate_capacity_usage(&qr_code, &share_binary),
        };

        Ok(QrShare {
            share: share.clone(),
            qr_data: qr_data.to_string(),
            qr_image: embedded_image,
            metadata,
        })
    }

    /// Embed share using error correction area (QEVCS method)
    fn embed_using_error_correction(
        &self,
        qr_image: &DynamicImage,
        share_binary: &ImageBuffer<Luma<u8>, Vec<u8>>,
        qr_code: &QrCode,
    ) -> Result<DynamicImage> {
        let qr_gray = qr_image.to_luma8();
        let (width, height) = qr_gray.dimensions();
        let mut result = qr_gray.clone();

        // Get QR code module information
        let modules = qr_code.to_vec();
        let module_count = qr_code.width();
        let scale_x = width as f32 / module_count as f32;
        let scale_y = height as f32 / module_count as f32;

        // Create a map of error correction modules
        let error_correction_modules =
            self.identify_error_correction_modules(&modules, module_count);

        // Embed share data in error correction modules
        for y in 0..height {
            for x in 0..width {
                let module_x = (x as f32 / scale_x) as usize;
                let module_y = (y as f32 / scale_y) as usize;

                if module_x < module_count && module_y < module_count {
                    let module_idx = module_y * module_count + module_x;

                    if error_correction_modules.contains(&module_idx) {
                        // This is an error correction module, we can modify it
                        let share_pixel = share_binary
                            .get_pixel(x % share_binary.width(), y % share_binary.height())[0];

                        // Blend QR code and share data
                        let qr_pixel = qr_gray.get_pixel(x, y)[0];
                        let blended = self.blend_pixels(qr_pixel, share_pixel);
                        result.put_pixel(x, y, Luma([blended]));
                    }
                }
            }
        }

        Ok(DynamicImage::ImageLuma8(result))
    }

    /// Embed share using direct module replacement
    fn embed_using_module_replacement(
        &self,
        qr_image: &DynamicImage,
        share_binary: &ImageBuffer<Luma<u8>, Vec<u8>>,
    ) -> Result<DynamicImage> {
        let qr_gray = qr_image.to_luma8();
        let (width, height) = qr_gray.dimensions();
        let mut result = qr_gray.clone();

        // Simple alpha blending approach
        for y in 0..height {
            for x in 0..width {
                let qr_pixel = qr_gray.get_pixel(x, y)[0];
                let share_pixel =
                    share_binary.get_pixel(x % share_binary.width(), y % share_binary.height())[0];

                // Weighted blend: prioritize QR code structure but include share information
                let alpha = self.config.data_capacity_ratio;
                let blended = ((1.0 - alpha) * qr_pixel as f32 + alpha * share_pixel as f32) as u8;
                result.put_pixel(x, y, Luma([blended]));
            }
        }

        Ok(DynamicImage::ImageLuma8(result))
    }

    /// Extract visual cryptography shares from QR codes
    pub fn extract_shares_from_qr(&self, qr_shares: &[QrShare]) -> Result<Vec<Share>> {
        let mut extracted_shares = Vec::new();

        for qr_share in qr_shares {
            let share = self.extract_share_from_qr_image(&qr_share.qr_image, &qr_share.metadata)?;
            extracted_shares.push(share);
        }

        Ok(extracted_shares)
    }

    /// Extract a single share from a QR code image
    fn extract_share_from_qr_image(
        &self,
        qr_image: &DynamicImage,
        metadata: &QrEmbeddingMetadata,
    ) -> Result<Share> {
        let qr_gray = qr_image.to_luma8();
        let (qr_width, qr_height) = qr_gray.dimensions();

        // Extract the embedded share data
        let mut extracted_data = ImageBuffer::new(metadata.share_size.0, metadata.share_size.1);

        for y in 0..metadata.share_size.1 {
            for x in 0..metadata.share_size.0 {
                // Map share coordinates to QR code coordinates
                let qr_x = (x * qr_width) / metadata.share_size.0;
                let qr_y = (y * qr_height) / metadata.share_size.1;

                let pixel = qr_gray.get_pixel(qr_x.min(qr_width - 1), qr_y.min(qr_height - 1))[0];

                // Apply extraction filter to recover share data
                let extracted_pixel = self.extract_pixel(pixel);
                extracted_data.put_pixel(x, y, Luma([extracted_pixel]));
            }
        }

        Ok(Share::new(
            DynamicImage::ImageLuma8(extracted_data),
            1, // Index would need to be tracked separately
            1, // Total shares would need to be tracked separately
            metadata.share_size.0,
            metadata.share_size.1,
            1,
            true, // QR shares are meaningful
        ))
    }

    /// Decode QR code data from QR share
    pub fn decode_qr_data(&self, qr_share: &QrShare) -> Result<String> {
        // For now, return the stored QR data
        // In a full implementation, this would decode the QR image
        Ok(qr_share.qr_data.clone())
    }

    /// Convert QR code to image with proper scaling
    fn qr_to_image(&self, qr_code: &QrCode) -> DynamicImage {
        let modules = qr_code.to_vec();
        let module_count = qr_code.width();

        let image_size = (module_count as u32 + 2 * self.config.border) * self.config.module_size;
        let mut img = ImageBuffer::new(image_size, image_size);

        // Fill with white background
        for pixel in img.pixels_mut() {
            *pixel = Luma([255u8]);
        }

        // Draw QR modules
        for y in 0..module_count {
            for x in 0..module_count {
                if modules[y * module_count + x] {
                    // Black module
                    let start_x = (x as u32 + self.config.border) * self.config.module_size;
                    let start_y = (y as u32 + self.config.border) * self.config.module_size;

                    for dy in 0..self.config.module_size {
                        for dx in 0..self.config.module_size {
                            img.put_pixel(start_x + dx, start_y + dy, Luma([0u8]));
                        }
                    }
                }
            }
        }

        DynamicImage::ImageLuma8(img)
    }

    /// Identify error correction modules in QR code
    fn identify_error_correction_modules(
        &self,
        modules: &[bool],
        module_count: usize,
    ) -> Vec<usize> {
        let mut error_correction_modules = Vec::new();

        // This is a simplified approach - in a full implementation,
        // you would need to properly identify the error correction areas
        // based on QR code specification

        // For now, identify modules that are not part of finder patterns,
        // timing patterns, or format information
        for y in 0..module_count {
            for x in 0..module_count {
                if !self.is_function_module(x, y, module_count) {
                    error_correction_modules.push(y * module_count + x);
                }
            }
        }

        error_correction_modules
    }

    /// Check if a module is a function module (finder pattern, timing, etc.)
    fn is_function_module(&self, x: usize, y: usize, size: usize) -> bool {
        // Finder patterns (top-left, top-right, bottom-left)
        if (x < 9 && y < 9) || (x >= size - 8 && y < 9) || (x < 9 && y >= size - 8) {
            return true;
        }

        // Timing patterns
        if (x == 6 && y >= 8 && y < size - 8) || (y == 6 && x >= 8 && x < size - 8) {
            return true;
        }

        // Dark module (always at position (4*version + 9, 8))
        // This is simplified - would need proper version detection

        false
    }

    /// Blend QR code pixel with share pixel
    fn blend_pixels(&self, qr_pixel: u8, share_pixel: u8) -> u8 {
        // Use different blending strategies based on configuration
        let alpha = self.config.data_capacity_ratio;

        if self.config.use_error_correction_embedding {
            // More sophisticated blending for error correction embedding
            if qr_pixel == 0 && share_pixel == 0 {
                0 // Both black - keep black
            } else if qr_pixel == 255 && share_pixel == 255 {
                255 // Both white - keep white
            } else {
                // Mixed - use weighted average
                ((1.0 - alpha) * qr_pixel as f32 + alpha * share_pixel as f32) as u8
            }
        } else {
            // Simple weighted blend
            ((1.0 - alpha) * qr_pixel as f32 + alpha * share_pixel as f32) as u8
        }
    }

    /// Extract pixel from blended QR/share data
    fn extract_pixel(&self, blended_pixel: u8) -> u8 {
        // This would use the inverse of the blending function
        // For now, use simple thresholding
        if blended_pixel > 127 {
            255
        } else {
            0
        }
    }

    /// Count number of bits embedded in share
    fn count_embedded_bits(&self, share_binary: &ImageBuffer<Luma<u8>, Vec<u8>>) -> usize {
        share_binary.pixels().filter(|pixel| pixel[0] == 0).count()
    }

    /// Calculate capacity usage
    fn calculate_capacity_usage(
        &self,
        qr_code: &QrCode,
        share_binary: &ImageBuffer<Luma<u8>, Vec<u8>>,
    ) -> f32 {
        let total_modules = (qr_code.width() * qr_code.width()) as f32;
        let embedded_bits = self.count_embedded_bits(share_binary) as f32;
        embedded_bits / total_modules
    }
}

/// Create a simple QR share for testing
pub fn create_test_qr_share(data: &str, share_data: Vec<u8>) -> Result<QrShare> {
    let config = QrVcConfig::default();
    let qr_processor = QrVisualCryptography::new(config);

    // Create a dummy share
    let width = 100;
    let height = 100;
    let mut share_img = ImageBuffer::new(width, height);

    for (i, pixel) in share_img.pixels_mut().enumerate() {
        let value = if i < share_data.len() && share_data[i] == 1 {
            0
        } else {
            255
        };
        *pixel = Luma([value]);
    }

    let share = Share::new(
        DynamicImage::ImageLuma8(share_img),
        1,
        1,
        width,
        height,
        1,
        true,
    );

    qr_processor.embed_share_in_qr(&share, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_vc_config_default() {
        let config = QrVcConfig::default();
        assert_eq!(config.error_correction, QrErrorCorrection::Medium);
        assert_eq!(config.module_size, 4);
    }

    #[test]
    fn test_create_test_qr_share() {
        let share_data = vec![1, 0, 1, 0, 1];
        let qr_share = create_test_qr_share("Hello World", share_data);
        assert!(qr_share.is_ok());

        let qr_share = qr_share.unwrap();
        assert_eq!(qr_share.qr_data, "Hello World");
    }

    #[test]
    fn test_qr_visual_cryptography_creation() {
        let config = QrVcConfig::default();
        let qr_vc = QrVisualCryptography::new(config);

        // Test that we can create the processor
        assert_eq!(qr_vc.config.error_correction, QrErrorCorrection::Medium);
    }
}
