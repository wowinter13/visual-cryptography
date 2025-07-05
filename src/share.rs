//! Share management for visual cryptography

use image::{DynamicImage, ImageBuffer, Luma};
use std::fmt;

/// Type of share based on image format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    /// Binary (black and white) share
    Binary,
    /// Grayscale share
    Grayscale,
    /// RGB color share
    Color,
}

/// Represents a single share in a visual cryptography scheme
#[derive(Debug, Clone)]
pub struct Share {
    /// The share image data
    pub image: DynamicImage,
    /// Type of the share
    pub share_type: ShareType,
    /// Index of this share (e.g., share 1 of n)
    pub index: usize,
    /// Total number of shares in the scheme
    pub total_shares: usize,
    /// Original image dimensions (before any expansion)
    pub original_width: u32,
    pub original_height: u32,
    /// Block size used for pixel expansion
    pub block_size: usize,
    /// Whether this is a meaningful share (with cover image)
    pub is_meaningful: bool,
}

impl Share {
    /// Create a new share
    pub fn new(
        image: DynamicImage,
        index: usize,
        total_shares: usize,
        original_width: u32,
        original_height: u32,
        block_size: usize,
        is_meaningful: bool,
    ) -> Self {
        let share_type = match &image {
            DynamicImage::ImageLuma8(_) => ShareType::Binary,
            DynamicImage::ImageLuma16(_) => ShareType::Grayscale,
            DynamicImage::ImageRgb8(_) | DynamicImage::ImageRgba8(_) => ShareType::Color,
            _ => ShareType::Grayscale,
        };

        Self {
            image,
            share_type,
            index,
            total_shares,
            original_width,
            original_height,
            block_size,
            is_meaningful,
        }
    }

    /// Get the dimensions of the share image
    pub fn dimensions(&self) -> (u32, u32) {
        (self.image.width(), self.image.height())
    }

    /// Convert share to binary (black and white)
    pub fn to_binary(&self) -> ImageBuffer<Luma<u8>, Vec<u8>> {
        match &self.image {
            DynamicImage::ImageLuma8(img) => {
                // Convert grayscale to binary using threshold
                let mut binary = ImageBuffer::new(img.width(), img.height());
                for (x, y, pixel) in img.enumerate_pixels() {
                    let value = if pixel[0] > 127 { 255 } else { 0 };
                    binary.put_pixel(x, y, Luma([value]));
                }
                binary
            }
            _ => {
                // Convert to grayscale first, then to binary
                let gray = self.image.to_luma8();
                let mut binary = ImageBuffer::new(gray.width(), gray.height());
                for (x, y, pixel) in gray.enumerate_pixels() {
                    let value = if pixel[0] > 127 { 255 } else { 0 };
                    binary.put_pixel(x, y, Luma([value]));
                }
                binary
            }
        }
    }

    /// Check if this share is compatible with another share for stacking
    pub fn is_compatible(&self, other: &Share) -> bool {
        self.dimensions() == other.dimensions()
            && self.total_shares == other.total_shares
            && self.original_width == other.original_width
            && self.original_height == other.original_height
            && self.block_size == other.block_size
    }

    /// Stack this share with another using OR operation (for binary shares)
    pub fn stack_binary(&self, other: &Share) -> ImageBuffer<Luma<u8>, Vec<u8>> {
        let binary1 = self.to_binary();
        let binary2 = other.to_binary();

        let (width, height) = self.dimensions();
        let mut result = ImageBuffer::new(width, height);

        for y in 0..height {
            for x in 0..width {
                let p1 = binary1.get_pixel(x, y)[0];
                let p2 = binary2.get_pixel(x, y)[0];
                // OR operation: black (0) OR black (0) = black (0)
                // white (255) OR anything = white (255)
                let value = if p1 == 0 && p2 == 0 { 0 } else { 255 };
                result.put_pixel(x, y, Luma([value]));
            }
        }

        result
    }

    /// Stack this share with another using AND operation (alternative method)
    pub fn stack_and(&self, other: &Share) -> ImageBuffer<Luma<u8>, Vec<u8>> {
        let binary1 = self.to_binary();
        let binary2 = other.to_binary();

        let (width, height) = self.dimensions();
        let mut result = ImageBuffer::new(width, height);

        for y in 0..height {
            for x in 0..width {
                let p1 = binary1.get_pixel(x, y)[0];
                let p2 = binary2.get_pixel(x, y)[0];
                // AND operation: both must be black (0) for result to be black
                let value = if p1 == 0 || p2 == 0 { 0 } else { 255 };
                result.put_pixel(x, y, Luma([value]));
            }
        }

        result
    }

    /// Save the share to a file
    pub fn save(&self, path: &str) -> Result<(), image::ImageError> {
        self.image.save(path)
    }
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Share {}/{}: {:?} {}x{} (original: {}x{}, block_size: {})",
            self.index,
            self.total_shares,
            self.share_type,
            self.image.width(),
            self.image.height(),
            self.original_width,
            self.original_height,
            self.block_size
        )
    }
}

/// Stack multiple shares together
pub fn stack_shares(shares: &[Share]) -> Option<ImageBuffer<Luma<u8>, Vec<u8>>> {
    if shares.is_empty() {
        return None;
    }

    // Check all shares are compatible
    let first = &shares[0];
    for share in shares.iter().skip(1) {
        if !first.is_compatible(share) {
            return None;
        }
    }

    // Stack all shares using OR operation
    let mut result = shares[0].to_binary();

    for share in shares.iter().skip(1) {
        let binary = share.to_binary();
        for y in 0..result.height() {
            for x in 0..result.width() {
                let current = result.get_pixel(x, y)[0];
                let new = binary.get_pixel(x, y)[0];
                let value = if current == 0 && new == 0 { 0 } else { 255 };
                result.put_pixel(x, y, Luma([value]));
            }
        }
    }

    Some(result)
}

/// Stack shares progressively to show how the image is revealed
pub fn progressive_stack(shares: &[Share]) -> Vec<ImageBuffer<Luma<u8>, Vec<u8>>> {
    let mut results = Vec::new();

    for i in 2..=shares.len() {
        if let Some(stacked) = stack_shares(&shares[0..i]) {
            results.push(stacked);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_creation() {
        let img = DynamicImage::new_luma8(100, 100);
        let share = Share::new(img, 1, 3, 50, 50, 2, false);

        assert_eq!(share.index, 1);
        assert_eq!(share.total_shares, 3);
        assert_eq!(share.share_type, ShareType::Binary);
        assert_eq!(share.dimensions(), (100, 100));
    }

    #[test]
    fn test_share_compatibility() {
        let img1 = DynamicImage::new_luma8(100, 100);
        let img2 = DynamicImage::new_luma8(100, 100);
        let img3 = DynamicImage::new_luma8(200, 200);

        let share1 = Share::new(img1, 1, 3, 50, 50, 2, false);
        let share2 = Share::new(img2, 2, 3, 50, 50, 2, false);
        let share3 = Share::new(img3, 3, 3, 50, 50, 2, false);

        assert!(share1.is_compatible(&share2));
        assert!(!share1.is_compatible(&share3));
    }
}
