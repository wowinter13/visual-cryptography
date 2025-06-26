//! Dhiman-Kasana Color Visual Cryptography Example
//!
//! This example demonstrates the Dhiman-Kasana EVCT(3,3) algorithm for color images.
//! This scheme encrypts a color image into 3 shares, processing each RGB channel
//! separately using color mixing matrices to preserve color information.

use image::DynamicImage;
use std::path::Path;
use visual_cryptography::{Algorithm, VCConfig, VisualCryptography};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Dhiman-Kasana Color Visual Cryptography Example");
    println!("===============================================\n");

    let secret_image = load_color_image();
    secret_image.save("assets/dhiman_kasana_secret.png")?;
    println!(
        "Loaded secret image: {}",
        get_image_description(&secret_image)
    );
    println!(
        "  Original dimensions: {}x{}",
        secret_image.width(),
        secret_image.height()
    );
    println!("  Color format: RGB");

    // Configure for Dhiman-Kasana EVCT(3,3) scheme
    let config = VCConfig {
        num_shares: 3, // Dhiman-Kasana requires exactly 3 shares
        threshold: 3,  // All 3 shares needed for reconstruction
        block_size: 5, // 5x5 pixel expansion
        algorithm: Algorithm::DhimanKasana,
        use_meaningful_shares: false,
    };

    println!("\nDhiman-Kasana Configuration:");
    println!("  - Shares: {} (all required)", config.num_shares);
    println!("  - Threshold: {}", config.threshold);
    println!(
        "  - Pixel expansion: {}x{} blocks",
        config.block_size, config.block_size
    );
    println!("  - Algorithm: Dhiman-Kasana EVCT(3,3) color scheme");

    let vc = VisualCryptography::new(config)?;

    println!("\nEncrypting color image using Dhiman-Kasana scheme...");
    let shares = vc.encrypt(&secret_image, None)?;

    println!("Generated {} color shares", shares.len());

    for (i, share) in shares.iter().enumerate() {
        let (share_width, share_height) = share.dimensions();
        println!("  Share {}: {}", i + 1, share);
        println!(
            "    Dimensions: {}x{} ({}x expansion)",
            share_width,
            share_height,
            share_width / secret_image.width()
        );
        analyze_color_share_properties(&share.image, i + 1);
    }

    println!("\nSaving color shares...");
    for (i, share) in shares.iter().enumerate() {
        let filename = format!("assets/dhiman_kasana_share_{}.png", i + 1);
        share.save(&filename)?;
        println!("Saved {}", filename);
    }

    println!("\nIndividual share analysis:");
    println!("  - Each share uses 5x5 blocks for each original pixel");
    println!("  - RGB bits are encoded at specific coordinates within each block");
    println!("  - Bit positions: R=(4,4),(4,2)..., G=(4,3),(3,4)..., B=(4,1),(3,3)...");
    println!("  - Black pixels (0,0,0) encode bit '1', dark grey (30,30,30) encodes bit '0'");
    println!("  - All 3 shares are required for full reconstruction");
    println!("  - Without cover images, shares have white backgrounds with encoded bits");

    println!("\nDecrypting using all shares...");
    let decrypted = vc.decrypt(&shares)?;
    decrypted.save("assets/dhiman_kasana_decrypted.png")?;
    println!("Saved decrypted image: dhiman_kasana_decrypted.png");

    analyze_color_reconstruction_quality(&secret_image, &decrypted);

    println!("\nTesting with insufficient shares...");

    // Test with 2 shares
    match vc.decrypt(&shares[0..2]) {
        Err(e) => println!("Expected error with 2 shares: {}", e),
        Ok(_) => println!("Unexpected success with 2 shares!"),
    }

    // Test with 1 share
    match vc.decrypt(&shares[0..1]) {
        Err(e) => println!("Expected error with 1 share: {}", e),
        Ok(_) => println!("Unexpected success with 1 share!"),
    }

    Ok(())
}

fn load_color_image() -> DynamicImage {
    let path = "assets/RGB_24bits_palette_sample_image.jpg";

    if Path::new(path).exists() {
        if let Ok(img) = image::open(path) {
            return img;
        }
    }

    panic!("Failed to load image from {}", path);
}

fn get_image_description(image: &DynamicImage) -> &'static str {
    match (image.width(), image.height()) {
        (w, h) if w > h => "Image (landscape)",
        (w, h) if h > w => "Image (portrait)",
        _ => "Image (square format)",
    }
}

fn analyze_color_share_properties(share: &DynamicImage, share_num: usize) {
    if let DynamicImage::ImageRgb8(img) = share {
        let mut r_min = 255u8;
        let mut r_max = 0u8;
        let mut g_min = 255u8;
        let mut g_max = 0u8;
        let mut b_min = 255u8;
        let mut b_max = 0u8;

        let mut r_sum = 0u64;
        let mut g_sum = 0u64;
        let mut b_sum = 0u64;
        let mut count = 0u64;

        for pixel in img.pixels() {
            let [r, g, b] = pixel.0;

            r_min = r_min.min(r);
            r_max = r_max.max(r);
            g_min = g_min.min(g);
            g_max = g_max.max(g);
            b_min = b_min.min(b);
            b_max = b_max.max(b);

            r_sum += r as u64;
            g_sum += g as u64;
            b_sum += b as u64;
            count += 1;
        }

        let r_avg = r_sum / count;
        let g_avg = g_sum / count;
        let b_avg = b_sum / count;

        println!("    Color analysis for Share {}:", share_num);
        println!("      Red   channel: {}-{}, avg: {}", r_min, r_max, r_avg);
        println!("      Green channel: {}-{}, avg: {}", g_min, g_max, g_avg);
        println!("      Blue  channel: {}-{}, avg: {}", b_min, b_max, b_avg);
    }
}

fn analyze_color_reconstruction_quality(original: &DynamicImage, reconstructed: &DynamicImage) {
    println!(
        "  Reconstructed dimensions: {}x{}",
        reconstructed.width(),
        reconstructed.height()
    );

    if original.width() == reconstructed.width() && original.height() == reconstructed.height() {
        let orig = original.to_rgb8();
        let recon = reconstructed.to_rgb8();

        let mut r_total_diff = 0u64;
        let mut g_total_diff = 0u64;
        let mut b_total_diff = 0u64;
        let mut max_r_diff = 0u8;
        let mut max_g_diff = 0u8;
        let mut max_b_diff = 0u8;
        let pixels = orig.width() * orig.height();

        for (orig_pixel, recon_pixel) in orig.pixels().zip(recon.pixels()) {
            let r_diff = orig_pixel[0].abs_diff(recon_pixel[0]);
            let g_diff = orig_pixel[1].abs_diff(recon_pixel[1]);
            let b_diff = orig_pixel[2].abs_diff(recon_pixel[2]);

            r_total_diff += r_diff as u64;
            g_total_diff += g_diff as u64;
            b_total_diff += b_diff as u64;

            max_r_diff = max_r_diff.max(r_diff);
            max_g_diff = max_g_diff.max(g_diff);
            max_b_diff = max_b_diff.max(b_diff);
        }

        let r_avg_diff = r_total_diff as f64 / pixels as f64;
        let g_avg_diff = g_total_diff as f64 / pixels as f64;
        let b_avg_diff = b_total_diff as f64 / pixels as f64;
        let overall_avg_diff = (r_avg_diff + g_avg_diff + b_avg_diff) / 3.0;

        println!("  Color reconstruction analysis:");
        println!(
            "    Red   channel - Avg diff: {:.2}, Max diff: {}",
            r_avg_diff, max_r_diff
        );
        println!(
            "    Green channel - Avg diff: {:.2}, Max diff: {}",
            g_avg_diff, max_g_diff
        );
        println!(
            "    Blue  channel - Avg diff: {:.2}, Max diff: {}",
            b_avg_diff, max_b_diff
        );
        println!("    Overall average difference: {:.2}", overall_avg_diff);

        if overall_avg_diff < 15.0 {
            println!("  Quality: Excellent color reconstruction");
        } else if overall_avg_diff < 35.0 {
            println!("  Quality: Good color reconstruction");
        } else if overall_avg_diff < 60.0 {
            println!("  Quality: Fair color reconstruction");
        } else {
            println!("  Quality: Poor color reconstruction (significant color loss)");
        }
    }
}
