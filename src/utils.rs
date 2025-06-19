//! Utility functions for visual cryptography

use image::{DynamicImage, ImageBuffer, Luma, Rgb};

/// Convert an image to binary (black and white)
pub fn convert_to_binary(image: &DynamicImage) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    let gray = image.to_luma8();
    let (width, height) = (gray.width(), gray.height());
    let mut binary = ImageBuffer::new(width, height);

    // Use Otsu's method or simple threshold
    let threshold = calculate_threshold(&gray);

    for (x, y, pixel) in gray.enumerate_pixels() {
        let value = if pixel[0] > threshold { 255 } else { 0 };
        binary.put_pixel(x, y, Luma([value]));
    }

    binary
}

/// Calculate threshold for binary conversion using simple mean
fn calculate_threshold(gray: &ImageBuffer<Luma<u8>, Vec<u8>>) -> u8 {
    let sum: u64 = gray.pixels().map(|p| p[0] as u64).sum();
    let count = (gray.width() * gray.height()) as u64;
    (sum / count) as u8
}

/// Apply halftone to an image
pub fn apply_halftone(image: &DynamicImage) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    let gray = image.to_luma8();
    let (width, height) = (gray.width(), gray.height());
    let mut halftone = ImageBuffer::new(width, height);

    // Simple ordered dithering matrix (Bayer matrix)
    let dither_matrix = [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]];

    for y in 0..height {
        for x in 0..width {
            let pixel = gray.get_pixel(x, y)[0];
            let threshold = dither_matrix[(y % 4) as usize][(x % 4) as usize] * 16;
            let value = if pixel as u16 > threshold { 255 } else { 0 };
            halftone.put_pixel(x, y, Luma([value]));
        }
    }

    halftone
}

/// Expand a pixel into a block
pub fn expand_pixel(value: u8, block_size: usize) -> Vec<Vec<u8>> {
    vec![vec![value; block_size]; block_size]
}

/// Resize an image to match target dimensions
pub fn resize_to_match(
    image: &DynamicImage,
    target_width: u32,
    target_height: u32,
) -> DynamicImage {
    if image.width() == target_width && image.height() == target_height {
        image.clone()
    } else {
        image.resize_exact(
            target_width,
            target_height,
            image::imageops::FilterType::Lanczos3,
        )
    }
}

/// Create a random noise image
pub fn create_noise_image(width: u32, height: u32) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut img = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let value = if rng.gen_bool(0.5) { 0 } else { 255 };
            img.put_pixel(x, y, Luma([value]));
        }
    }

    img
}

/// Apply a pattern to a block of pixels
pub fn apply_pattern_to_block(
    image: &mut ImageBuffer<Luma<u8>, Vec<u8>>,
    x: u32,
    y: u32,
    block_size: usize,
    pattern: &[u8],
) {
    for dy in 0..block_size {
        for dx in 0..block_size {
            let idx = dy * block_size + dx;
            if idx < pattern.len() {
                let value = if pattern[idx] == 1 { 0 } else { 255 };
                image.put_pixel(x + dx as u32, y + dy as u32, Luma([value]));
            }
        }
    }
}

/// Calculate the contrast between two regions
pub fn calculate_contrast(image: &ImageBuffer<Luma<u8>, Vec<u8>>) -> f32 {
    let (width, height) = (image.width(), image.height());
    let total_pixels = (width * height) as f32;

    let black_pixels = image.pixels().filter(|p| p[0] == 0).count() as f32;
    let white_pixels = total_pixels - black_pixels;

    (white_pixels - black_pixels).abs() / total_pixels
}

/// Combine RGB channels into a color image
pub fn combine_rgb_channels(
    r: &ImageBuffer<Luma<u8>, Vec<u8>>,
    g: &ImageBuffer<Luma<u8>, Vec<u8>>,
    b: &ImageBuffer<Luma<u8>, Vec<u8>>,
) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
    assert_eq!(r.dimensions(), g.dimensions());
    assert_eq!(r.dimensions(), b.dimensions());

    let (width, height) = r.dimensions();
    let mut rgb = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let r_val = r.get_pixel(x, y)[0];
            let g_val = g.get_pixel(x, y)[0];
            let b_val = b.get_pixel(x, y)[0];
            rgb.put_pixel(x, y, Rgb([r_val, g_val, b_val]));
        }
    }

    rgb
}

/// Extract a color channel from an RGB image
pub fn extract_channel(image: &DynamicImage, channel: usize) -> ImageBuffer<Luma<u8>, Vec<u8>> {
    let rgb = image.to_rgb8();
    let (width, height) = rgb.dimensions();
    let mut channel_img = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let pixel = rgb.get_pixel(x, y);
            channel_img.put_pixel(x, y, Luma([pixel[channel]]));
        }
    }

    channel_img
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_to_binary() {
        let gray = DynamicImage::new_luma8(10, 10);
        let binary = convert_to_binary(&gray);

        // All pixels should be either 0 or 255
        for pixel in binary.pixels() {
            assert!(pixel[0] == 0 || pixel[0] == 255);
        }
    }

    #[test]
    fn test_expand_pixel() {
        let expanded = expand_pixel(255, 3);
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[0].len(), 3);
        assert_eq!(expanded[0][0], 255);
    }

    #[test]
    fn test_create_noise_image() {
        let noise = create_noise_image(100, 100);
        assert_eq!(noise.dimensions(), (100, 100));

        // Should have both black and white pixels
        let has_black = noise.pixels().any(|p| p[0] == 0);
        let has_white = noise.pixels().any(|p| p[0] == 255);
        assert!(has_black);
        assert!(has_white);
    }
}
