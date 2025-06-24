//! Taghaddos-Latif Grayscale Visual Cryptography Example
//!
//! This example demonstrates the Taghaddos-Latif algorithm for grayscale images
//! using bit-level decomposition as described in the original 2014 paper.
//!
//! The algorithm encrypts a grayscale image into two shares using bit-plane
//! decomposition and specific 2x2 patterns, preserving the continuous tone
//! of the original image in the reconstruction.

use image::DynamicImage;
use std::path::Path;
use visual_cryptography::{Algorithm, VCConfig, VisualCryptography};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Taghaddos-Latif Grayscale Visual Cryptography Example");
    println!("====================================================\n");

    let secret_image = load_grayscale_image();
    secret_image.save("assets/taghaddos_latif_secret.png")?;
    println!(
        "Loaded secret image: {}",
        get_image_description(&secret_image)
    );
    println!(
        "  Original dimensions: {}x{}",
        secret_image.width(),
        secret_image.height()
    );
    println!("  Pixel values: 0-255 grayscale");

    let config = VCConfig {
        num_shares: 2,
        threshold: 2,
        block_size: 2, // 2x2 pixel expansion (mentioned in paper)
        algorithm: Algorithm::TaghaddosLatif,
        use_meaningful_shares: false,
    };

    let vc = VisualCryptography::new(config)?;

    let shares = vc.encrypt(&secret_image, None)?;

    for (i, share) in shares.iter().enumerate() {
        let (share_width, share_height) = share.dimensions();
        println!("  Share {}: {}", i + 1, share);
        println!(
            "    Expanded dimensions: {}x{} ({}x pixel expansion)",
            share_width,
            share_height,
            share_width / secret_image.width()
        );
        analyze_share_properties(&share.image);
    }

    println!("\nSaving shares...");
    for (i, share) in shares.iter().enumerate() {
        let filename = format!("assets/taghaddos_latif_share_{}.png", i + 1);
        share.save(&filename)?;
        println!("Saved {}", filename);
    }

    let decrypted = vc.decrypt(&shares)?;
    decrypted.save("assets/taghaddos_latif_decrypted.png")?;
    println!("Saved decrypted image: taghaddos_latif_decrypted.png");

    analyze_reconstruction_quality(&secret_image, &decrypted);

    println!("\nTesting with insufficient shares...");
    match vc.decrypt(&shares[0..1]) {
        Err(e) => println!("Expected error with single share: {}", e),
        Ok(_) => println!("Unexpected success with single share!"),
    }

    Ok(())
}

fn load_grayscale_image() -> DynamicImage {
    let path = "assets/Barbara-original-image.png";

    if Path::new(path).exists() {
        if let Ok(img) = image::open(path) {
            println!("Using Barbara test image from {}", path);
            return img.to_luma8().into();
        }
    }

    panic!("Failed to load Barbara test image");
}

fn get_image_description(image: &DynamicImage) -> &'static str {
    match image.width() {
        256 if image.height() == 256 => "Synthetic grayscale test image",
        512 if image.height() == 512 => "Barbara test image (likely)",
        _ => "Custom grayscale image",
    }
}

fn analyze_share_properties(share: &DynamicImage) {
    if let DynamicImage::ImageLuma8(img) = share {
        let mut min_val = 255u8;
        let mut max_val = 0u8;
        let mut sum = 0u64;
        let mut count = 0u64;

        for pixel in img.pixels() {
            let val = pixel[0];
            min_val = min_val.min(val);
            max_val = max_val.max(val);
            sum += val as u64;
            count += 1;
        }

        let avg = sum / count;
        println!(
            "    Intensity range: {}-{}, average: {}",
            min_val, max_val, avg
        );
    }
}

fn analyze_reconstruction_quality(original: &DynamicImage, reconstructed: &DynamicImage) {
    println!(
        "  Reconstructed dimensions: {}x{}",
        reconstructed.width(),
        reconstructed.height()
    );

    if original.width() == reconstructed.width() && original.height() == reconstructed.height() {
        let orig = original.to_luma8();
        let recon = reconstructed.to_luma8();
        {
            let mut total_diff = 0u64;
            let mut max_diff = 0u8;
            let pixels = orig.width() * orig.height();

            for (orig_pixel, recon_pixel) in orig.pixels().zip(recon.pixels()) {
                let diff = orig_pixel[0].abs_diff(recon_pixel[0]);
                total_diff += diff as u64;
                max_diff = max_diff.max(diff);
            }

            let avg_diff = total_diff as f64 / pixels as f64;
            println!("  Average pixel difference: {:.2}", avg_diff);
            println!("  Maximum pixel difference: {}", max_diff);

            if avg_diff < 10.0 {
                println!("  Quality: Excellent reconstruction");
            } else if avg_diff < 25.0 {
                println!("  Quality: Good reconstruction");
            } else {
                println!("  Quality: Fair reconstruction (some information loss)");
            }
        }
    }
}
