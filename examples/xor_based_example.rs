//! XOR-based Visual Cryptography Example
//!
//! This example demonstrates the XOR-based visual cryptography scheme which provides
//! better contrast compared to traditional threshold schemes by using XOR operations
//! instead of AND operations for reconstruction.

use image::{DynamicImage, ImageBuffer, Luma};
use std::path::Path;
use visual_cryptography::{Algorithm, VCConfig, VisualCryptography};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("XOR-based Visual Cryptography Example");
    println!("====================================\n");

    let secret_image = load_or_create_secret_image();
    secret_image.save("assets/xor_based_secret.png")?;
    println!(
        "  Original dimensions: {}x{}",
        secret_image.width(),
        secret_image.height()
    );

    // Configure for XOR-based scheme
    let config = VCConfig {
        num_shares: 3, // Can work with any number of shares
        threshold: 3,  // All shares needed for XOR reconstruction
        block_size: 1, // No pixel expansion needed
        algorithm: Algorithm::XorBased,
        use_meaningful_shares: false,
    };

    println!("\nXOR-based Configuration:");
    println!("  - Shares: {}", config.num_shares);
    println!("  - Threshold: {} (all shares required)", config.threshold);
    println!(
        "  - Pixel expansion: {}x{} (no expansion)",
        config.block_size, config.block_size
    );
    println!("  - Algorithm: XOR-based scheme");
    println!("  - Key advantage: Better contrast preservation");

    let num_shares = config.num_shares;
    let threshold = config.threshold;
    let vc = VisualCryptography::new(config)?;

    println!("\nEncrypting image using XOR-based scheme...");
    let shares = vc.encrypt(&secret_image, None)?;

    println!("Generated {} shares", shares.len());

    for (i, share) in shares.iter().enumerate() {
        let (share_width, share_height) = share.dimensions();
        println!("  Share {}: {}", i + 1, share);
        println!(
            "    Dimensions: {}x{} (same as original)",
            share_width, share_height
        );
    }

    // Save shares
    println!("\nSaving shares...");
    for (i, share) in shares.iter().enumerate() {
        let filename = format!("assets/xor_based_share_{}.png", i + 1);
        share.save(&filename)?;
        println!("Saved {}", filename);
    }

    println!("\nIndividual share analysis:");
    println!("  - Each share appears as random noise");
    println!("  - No pixel expansion maintains original resolution");
    println!("  - XOR matrices ensure perfect secrecy");

    println!("\nDecrypting using XOR of all shares...");
    let decrypted = vc.decrypt(&shares)?;
    decrypted.save("assets/xor_based_decrypted.png")?;
    println!("Saved decrypted image: xor_based_decrypted.png");
    println!(
        "  Reconstructed dimensions: {}x{}",
        decrypted.width(),
        decrypted.height()
    );

    // Test with different share combinations
    println!("\nTesting with different share combinations:");

    // Test with insufficient shares
    println!(
        "\n1. Testing with {} shares (need {}):",
        num_shares - 1,
        threshold
    );
    match vc.decrypt(&shares[0..num_shares - 1]) {
        Err(e) => println!("   Expected error: {}", e),
        Ok(_) => println!("   Warning: Unexpected success!"),
    }

    // Test with subset of shares
    if num_shares >= 2 {
        println!("\n2. Testing with only 2 shares:");
        let partial_result = vc.decrypt(&shares[0..2]);
        match partial_result {
            Ok(img) => {
                img.save("assets/xor_based_partial.png")?;
                println!("   Partial reconstruction saved (will be incorrect)");
            }
            Err(e) => println!("   Error: {}", e),
        }
    }

    // Test XOR properties
    println!("\n3. Demonstrating XOR properties:");
    demonstrate_xor_properties(&shares, &vc)?;

    println!("\nXOR-based Scheme Properties:");
    println!("  - Perfect security: Each share is cryptographically secure");
    println!("  - No pixel expansion: Maintains original image resolution");
    println!("  - Better contrast: XOR operation preserves more contrast than AND");
    println!("  - Flexible threshold: Can work with any number of shares");
    println!("  - Computational efficiency: Simple XOR operations");

    println!("\nComparison with traditional schemes:");
    println!("  - Traditional AND-based: Lower contrast, pixel expansion");
    println!("  - XOR-based: Higher contrast, no pixel expansion");
    println!("  - Trade-off: All shares required vs. threshold flexibility");

    Ok(())
}

fn load_or_create_secret_image() -> DynamicImage {
    let path = "assets/dino.png";

    if Path::new(path).exists() {
        image::open(path).unwrap()
    } else {
        println!("Creating test image (dino.png not found)...");
        create_test_image()
    }
}

fn create_test_image() -> DynamicImage {
    let width = 200;
    let height = 150;
    let mut img = ImageBuffer::new(width, height);

    // Fill with white background
    for y in 0..height {
        for x in 0..width {
            img.put_pixel(x, y, Luma([255u8]));
        }
    }

    // Draw "XOR" text pattern
    draw_x(&mut img, 20, 40, 40);
    draw_o(&mut img, 80, 40, 40);
    draw_r(&mut img, 140, 40, 40);

    // Add some geometric patterns to demonstrate XOR properties
    draw_checkerboard(&mut img, 20, 100, 40);
    draw_diagonal_lines(&mut img, 80, 100, 40);
    draw_concentric_squares(&mut img, 140, 100, 40);

    DynamicImage::ImageLuma8(img)
}

fn draw_x(img: &mut ImageBuffer<Luma<u8>, Vec<u8>>, start_x: u32, start_y: u32, size: u32) {
    for i in 0..size {
        // Main diagonal
        if start_x + i < img.width() && start_y + i < img.height() {
            img.put_pixel(start_x + i, start_y + i, Luma([0u8]));
        }
        // Anti-diagonal
        if start_x + i < img.width() && start_y + size - 1 - i < img.height() {
            img.put_pixel(start_x + i, start_y + size - 1 - i, Luma([0u8]));
        }
    }
}

fn draw_o(img: &mut ImageBuffer<Luma<u8>, Vec<u8>>, start_x: u32, start_y: u32, size: u32) {
    let center_x = start_x + size / 2;
    let center_y = start_y + size / 2;
    let radius = size / 2 - 5;

    for y in start_y..start_y + size {
        for x in start_x..start_x + size {
            if x < img.width() && y < img.height() {
                let dx = (x as i32 - center_x as i32) as f32;
                let dy = (y as i32 - center_y as i32) as f32;
                let distance = (dx * dx + dy * dy).sqrt();

                if distance >= radius as f32 - 2.0 && distance <= radius as f32 + 2.0 {
                    img.put_pixel(x, y, Luma([0u8]));
                }
            }
        }
    }
}

fn draw_r(img: &mut ImageBuffer<Luma<u8>, Vec<u8>>, start_x: u32, start_y: u32, size: u32) {
    // Vertical line
    for y in start_y..start_y + size {
        if start_x < img.width() && y < img.height() {
            img.put_pixel(start_x, y, Luma([0u8]));
        }
    }

    // Top horizontal line
    for x in start_x..start_x + size / 2 {
        if x < img.width() && start_y < img.height() {
            img.put_pixel(x, start_y, Luma([0u8]));
        }
    }

    // Middle horizontal line
    for x in start_x..start_x + size / 2 {
        if x < img.width() && start_y + size / 2 < img.height() {
            img.put_pixel(x, start_y + size / 2, Luma([0u8]));
        }
    }

    // Diagonal line
    for i in 0..size / 2 {
        if start_x + size / 2 + i < img.width() && start_y + size / 2 + i < img.height() {
            img.put_pixel(start_x + size / 2 + i, start_y + size / 2 + i, Luma([0u8]));
        }
    }
}

fn draw_checkerboard(
    img: &mut ImageBuffer<Luma<u8>, Vec<u8>>,
    start_x: u32,
    start_y: u32,
    size: u32,
) {
    let square_size = size / 8;
    for y in 0..8 {
        for x in 0..8 {
            if (x + y) % 2 == 0 {
                let pixel_x = start_x + x * square_size;
                let pixel_y = start_y + y * square_size;

                for dy in 0..square_size {
                    for dx in 0..square_size {
                        if pixel_x + dx < img.width() && pixel_y + dy < img.height() {
                            img.put_pixel(pixel_x + dx, pixel_y + dy, Luma([0u8]));
                        }
                    }
                }
            }
        }
    }
}

fn draw_diagonal_lines(
    img: &mut ImageBuffer<Luma<u8>, Vec<u8>>,
    start_x: u32,
    start_y: u32,
    size: u32,
) {
    for i in 0..size {
        for j in 0..size {
            if (i + j) % 4 == 0 {
                if start_x + i < img.width() && start_y + j < img.height() {
                    img.put_pixel(start_x + i, start_y + j, Luma([0u8]));
                }
            }
        }
    }
}

fn draw_concentric_squares(
    img: &mut ImageBuffer<Luma<u8>, Vec<u8>>,
    start_x: u32,
    start_y: u32,
    size: u32,
) {
    let center = size / 2;
    for y in 0..size {
        for x in 0..size {
            let dist_x = if x > center { x - center } else { center - x };
            let dist_y = if y > center { y - center } else { center - y };
            let max_dist = dist_x.max(dist_y);

            if max_dist % 8 == 0 {
                if start_x + x < img.width() && start_y + y < img.height() {
                    img.put_pixel(start_x + x, start_y + y, Luma([0u8]));
                }
            }
        }
    }
}

fn demonstrate_xor_properties(
    shares: &[visual_cryptography::Share],
    vc: &VisualCryptography,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("   XOR Property: A ⊕ B ⊕ C = Secret");
    println!("   - Each share is essential for reconstruction");
    println!("   - Missing any share results in random noise");

    // Show that XOR of first two shares gives meaningful partial result
    if shares.len() >= 2 {
        let partial_shares = &shares[0..2];
        if let Ok(partial_result) = vc.decrypt(partial_shares) {
            let width = partial_result.width();
            let height = partial_result.height();
            println!("   - Partial XOR (2 shares): {}x{} pixels", width, height);
            partial_result.save("assets/xor_based_partial_xor.png")?;
        }
    }

    println!("   - XOR operations preserve more image information than AND");
    println!("   - Perfect reconstruction requires all shares");

    Ok(())
}
