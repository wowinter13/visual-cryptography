use image::{DynamicImage, ImageBuffer, Luma};
use std::fs;
use visual_cryptography::{Algorithm, VCConfig, VisualCryptography};

/// Example demonstrating the Yamaguchi-Nakajima Extended Visual Cryptography scheme
///
/// This algorithm processes three grayscale images:
/// 1. Target image - the secret image to be revealed
/// 2. Sheet 1 - first cover image (meaningful share)
/// 3. Sheet 2 - second cover image (meaningful share)
///
/// It produces two encrypted sheets that, when overlaid, reveal the target image.
/// The algorithm uses Floyd-Steinberg error diffusion and Boolean matrix construction.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Yamaguchi-Nakajima Extended Visual Cryptography Example ===\n");

    // Use assets directory for output
    let output_dir = "assets";
    fs::create_dir_all(output_dir).unwrap_or_else(|_| {
        println!("Assets directory already exists");
    });

    // Create synthetic test images
    println!("1. Creating synthetic test images...");
    let (target_image, sheet1_image, sheet2_image) = create_synthetic_images(128, 128);

    // Save original images
    target_image.save(format!("{}/yamaguchi_target_original.png", output_dir))?;
    sheet1_image.save(format!("{}/yamaguchi_sheet1_original.png", output_dir))?;
    sheet2_image.save(format!("{}/yamaguchi_sheet2_original.png", output_dir))?;

    // Configure the algorithm
    let config = VCConfig {
        algorithm: Algorithm::YamaguchiNakajima,
        num_shares: 2,
        threshold: 2,
        block_size: 16, // 16 subpixels per pixel (4x4 subpixel structure)
        use_meaningful_shares: true,
    };

    // Create visual cryptography instance
    let vc = VisualCryptography::new(config)?;

    println!("2. Encrypting with Yamaguchi-Nakajima algorithm...");
    println!("   - Target image: Circle pattern");
    println!("   - Sheet 1: Horizontal gradient");
    println!("   - Sheet 2: Vertical gradient");
    println!("   - Subpixel structure: 4x4 (16 subpixels per pixel)");
    println!("   - Contrast: 0.6");
    println!("   - Halftoning: Floyd-Steinberg error diffusion");

    // Encrypt the target image using the two sheet images as covers
    let cover_images = vec![sheet1_image.clone(), sheet2_image.clone()];
    let shares = vc.encrypt(&target_image, Some(cover_images))?;

    println!("   ✓ Generated {} encrypted shares", shares.len());

    // Save encrypted shares
    shares[0]
        .image
        .save(format!("{}/yamaguchi_encrypted_sheet1.png", output_dir))?;
    shares[1]
        .image
        .save(format!("{}/yamaguchi_encrypted_sheet2.png", output_dir))?;

    println!("3. Decrypting to reveal the target...");

    // Decrypt the shares
    let decrypted = vc.decrypt(&shares)?;
    decrypted.save(format!("{}/yamaguchi_revealed_target.png", output_dir))?;

    println!("   ✓ Target image revealed successfully");

    // Display results
    println!("\n=== Results ===");
    println!(
        "Original target dimensions: {}x{}",
        target_image.width(),
        target_image.height()
    );
    println!(
        "Encrypted share dimensions: {}x{}",
        shares[0].image.width(),
        shares[0].image.height()
    );
    println!(
        "Revealed target dimensions: {}x{}",
        decrypted.width(),
        decrypted.height()
    );

    // Try to process real images if available
    println!("\n4. Processing real images from assets...");
    if let Ok(real_shares) = load_and_process_real_images(&vc, output_dir) {
        println!("   ✓ Real images processed successfully");
        let real_decrypted = vc.decrypt(&real_shares)?;
        real_decrypted.save(format!("{}/yamaguchi_real_revealed.png", output_dir))?;
    } else {
        println!("   ℹ No suitable real images found - using synthetic images only");
    }

    println!("\n=== Algorithm Details ===");
    println!("The Yamaguchi-Nakajima algorithm implements Extended Visual Cryptography");
    println!("for natural images with the following features:");
    println!("• Processes 3 grayscale images (target + 2 sheet images)");
    println!("• Uses Floyd-Steinberg error diffusion for halftoning");
    println!("• Applies contrast adjustment for better visual quality");
    println!("• Generates Boolean matrices with transparency constraints");
    println!("• Creates meaningful shares that resemble the original sheet images");
    println!("• Reveals the target image through Boolean AND operation");

    println!("\n=== Usage Instructions ===");
    println!("1. Print yamaguchi_encrypted_sheet1.png and yamaguchi_encrypted_sheet2.png on transparencies");
    println!("2. Stack the two transparencies together");
    println!("3. The target image will be revealed through the overlay");
    println!("4. For best results, use high-contrast transparencies");

    println!("\n=== Files Generated ===");
    println!("All output files have been saved to: {}/", output_dir);
    println!("• yamaguchi_target_original.png - Original target image");
    println!("• yamaguchi_sheet1_original.png - Original sheet 1 image");
    println!("• yamaguchi_sheet2_original.png - Original sheet 2 image");
    println!("• yamaguchi_encrypted_sheet1.png - Encrypted sheet 1 (print this)");
    println!("• yamaguchi_encrypted_sheet2.png - Encrypted sheet 2 (print this)");
    println!("• yamaguchi_revealed_target.png - Digitally revealed target");

    println!("\n✓ Yamaguchi-Nakajima example completed successfully!");

    Ok(())
}

/// Create synthetic test images for demonstration
fn create_synthetic_images(width: u32, height: u32) -> (DynamicImage, DynamicImage, DynamicImage) {
    // Target: Circle pattern
    let mut target = ImageBuffer::new(width, height);
    let center_x = width as f32 / 2.0;
    let center_y = height as f32 / 2.0;
    let radius = (width.min(height) as f32) / 3.0;

    for y in 0..height {
        for x in 0..width {
            let dx = x as f32 - center_x;
            let dy = y as f32 - center_y;
            let distance = (dx * dx + dy * dy).sqrt();

            let pixel_value = if distance < radius {
                0u8 // Black circle
            } else {
                255u8 // White background
            };

            target.put_pixel(x, y, Luma([pixel_value]));
        }
    }

    // Sheet 1: Horizontal gradient
    let mut sheet1 = ImageBuffer::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let intensity = (x as f32 / width as f32 * 255.0) as u8;
            sheet1.put_pixel(x, y, Luma([intensity]));
        }
    }

    // Sheet 2: Vertical gradient
    let mut sheet2 = ImageBuffer::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let intensity = (y as f32 / height as f32 * 255.0) as u8;
            sheet2.put_pixel(x, y, Luma([intensity]));
        }
    }

    (
        DynamicImage::ImageLuma8(target),
        DynamicImage::ImageLuma8(sheet1),
        DynamicImage::ImageLuma8(sheet2),
    )
}

/// Try to load and process real images from the assets directory
fn load_and_process_real_images(
    vc: &VisualCryptography,
    output_dir: &str,
) -> Result<Vec<visual_cryptography::Share>, Box<dyn std::error::Error>> {
    // Try to load real images from assets directory
    let target_path = "assets/dino.png";
    let sheet1_path = "assets/Barbara-original-image.png";
    let sheet2_path = "assets/RGB_24bits_palette_sample_image.jpg";

    if let (Ok(target), Ok(sheet1), Ok(sheet2)) = (
        image::open(target_path),
        image::open(sheet1_path),
        image::open(sheet2_path),
    ) {
        println!("   ✓ Found real images in assets directory");

        // Convert to grayscale and resize to same dimensions
        let target = target.to_luma8();
        let sheet1 = sheet1.to_luma8();
        let sheet2 = sheet2.to_luma8();

        let size = 128; // Resize to manageable size
        let target = DynamicImage::ImageLuma8(image::imageops::resize(
            &target,
            size,
            size,
            image::imageops::FilterType::Lanczos3,
        ));
        let sheet1 = DynamicImage::ImageLuma8(image::imageops::resize(
            &sheet1,
            size,
            size,
            image::imageops::FilterType::Lanczos3,
        ));
        let sheet2 = DynamicImage::ImageLuma8(image::imageops::resize(
            &sheet2,
            size,
            size,
            image::imageops::FilterType::Lanczos3,
        ));

        // Save resized originals
        target.save(format!("{}/yamaguchi_real_target.png", output_dir))?;
        sheet1.save(format!("{}/yamaguchi_real_sheet1.png", output_dir))?;
        sheet2.save(format!("{}/yamaguchi_real_sheet2.png", output_dir))?;

        // Encrypt
        let cover_images = vec![sheet1, sheet2];
        let shares = vc.encrypt(&target, Some(cover_images))?;

        // Save encrypted shares
        shares[0].image.save(format!(
            "{}/yamaguchi_real_encrypted_sheet1.png",
            output_dir
        ))?;
        shares[1].image.save(format!(
            "{}/yamaguchi_real_encrypted_sheet2.png",
            output_dir
        ))?;

        Ok(shares)
    } else {
        Err("Real images not found".into())
    }
}
