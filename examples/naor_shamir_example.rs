//! Naor-Shamir Visual Cryptography Example
//!
//! This example demonstrates the original Naor-Shamir (2,2) visual cryptography scheme
//! with 2x2 pixel expansion.

use image::{DynamicImage, ImageBuffer, Luma};
use std::path::Path;
use visual_cryptography::{Algorithm, VCConfig, VisualCryptography};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Naor-Shamir Visual Cryptography Example");
    println!("=======================================\n");

    let secret_image = load_secret_image();
    secret_image.save("assets/naor_shamir_secret.png")?;
    println!(
        "  Original dimensions: {}x{}",
        secret_image.width(),
        secret_image.height()
    );

    // Configure for Naor-Shamir (2,2) scheme
    let config = VCConfig {
        num_shares: 2, // Naor-Shamir requires exactly 2 shares
        threshold: 2,  // Both shares needed for reconstruction
        block_size: 2, // Fixed 2x2 pixel expansion
        algorithm: Algorithm::NaorShamir,
        use_meaningful_shares: false,
    };

    println!("\nNaor-Shamir Configuration:");
    println!("  - Shares: {} (both required)", config.num_shares);
    println!("  - Threshold: {}", config.threshold);
    println!(
        "  - Pixel expansion: {}x{}",
        config.block_size, config.block_size
    );
    println!("  - Algorithm: Original Naor-Shamir scheme");

    let vc = VisualCryptography::new(config)?;

    println!("\nEncrypting image using Naor-Shamir scheme...");
    let shares = vc.encrypt(&secret_image, None)?;

    println!("Generated {} shares", shares.len());

    for (i, share) in shares.iter().enumerate() {
        let (share_width, share_height) = share.dimensions();
        println!("  Share {}: {}", i + 1, share);
        println!(
            "    Expanded dimensions: {}x{} ({}x expansion)",
            share_width,
            share_height,
            share_width / secret_image.width()
        );
    }

    // Save shares
    println!("\nSaving shares...");
    for (i, share) in shares.iter().enumerate() {
        let filename = format!("assets/naor_shamir_share_{}.png", i + 1);
        share.save(&filename)?;
        println!("Saved {}", filename);
    }

    println!("\nIndividual share analysis:");
    println!("  - Each share appears as random noise");
    println!("  - No information about the secret is visible");
    println!("  - Both shares are required for reconstruction");

    println!("\nDecrypting using both shares...");
    let decrypted = vc.decrypt(&shares)?;
    decrypted.save("assets/naor_shamir_decrypted.png")?;
    println!("Saved decrypted image: naor_shamir_decrypted.png");
    println!(
        "  Reconstructed dimensions: {}x{}",
        decrypted.width(),
        decrypted.height()
    );

    println!("\nTesting with insufficient shares...");
    match vc.decrypt(&shares[0..1]) {
        Err(e) => println!("Expected error with single share: {}", e),
        Ok(_) => println!("Unexpected success with single share!"),
    }

    println!("\nNaor-Shamir Security Properties:");
    println!("  - Perfect security: Individual shares reveal zero information");
    println!("  - Pixel expansion: Each pixel becomes a 2x2 block");
    println!("  - Contrast: Reconstructed image has 50% contrast");
    println!("  - Historical significance: First practical visual cryptography scheme (1994)");
    Ok(())
}

/// Load image
fn load_secret_image() -> DynamicImage {
    let path = "assets/dino.png";

    if Path::new(path).exists() {
        image::open(path).unwrap()
    } else {
        println!("Unable to load image from {}", path);
        std::process::exit(1);
    }
}
