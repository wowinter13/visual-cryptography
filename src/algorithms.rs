//! Visual cryptography algorithms implementation

use crate::{
    error::{Result, VCError},
    matrix::{
        generate_basic_matrices, generate_color_mixing_matrices, generate_dispatching_matrices,
        generate_proper_sharing_matrices, generate_xor_matrices, select_dispatching_row,
        ColorMixingMatrices, XorMatrices,
    },
    share::{stack_shares, Share},
    utils::{apply_halftone, convert_to_binary, expand_pixel},
    VCConfig,
};
use image::{DynamicImage, ImageBuffer, Luma, Rgb};
use rand::Rng;

/// Available visual cryptography algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Basic (k,n) threshold scheme
    BasicThreshold,
    /// Progressive visual cryptography
    Progressive,
    /// Extended visual cryptography with meaningful shares
    ExtendedMeaningful,
    /// Naor-Shamir original scheme
    NaorShamir,
    /// Taghaddos-Latif for grayscale
    TaghaddosLatif,
    /// Dhiman-Kasana for color images
    DhimanKasana,
    /// XOR-based scheme for better contrast
    XorBased,
}

/// Trait for visual cryptography schemes
pub trait VCScheme {
    /// Encrypt an image into shares
    fn encrypt(
        &self,
        image: &DynamicImage,
        config: &VCConfig,
        cover_images: Option<Vec<DynamicImage>>,
    ) -> Result<Vec<Share>>;

    /// Decrypt shares back into an image
    fn decrypt(&self, shares: &[Share], config: &VCConfig) -> Result<DynamicImage>;
}

/// Main encryption function that dispatches to the appropriate algorithm
pub fn encrypt(
    image: &DynamicImage,
    config: &VCConfig,
    cover_images: Option<Vec<DynamicImage>>,
) -> Result<Vec<Share>> {
    match config.algorithm {
        Algorithm::BasicThreshold => basic_threshold_encrypt(image, config),
        Algorithm::Progressive => progressive_encrypt(image, config, cover_images),
        Algorithm::ExtendedMeaningful => extended_meaningful_encrypt(image, config, cover_images),
        Algorithm::NaorShamir => naor_shamir_encrypt(image, config),
        Algorithm::TaghaddosLatif => taghaddos_latif_encrypt(image, config),
        Algorithm::DhimanKasana => dhiman_kasana_encrypt(image, config, cover_images),
        Algorithm::XorBased => xor_based_encrypt(image, config),
    }
}

/// Main decryption function that dispatches to the appropriate algorithm
pub fn decrypt(shares: &[Share], config: &VCConfig) -> Result<DynamicImage> {
    match config.algorithm {
        Algorithm::BasicThreshold => basic_threshold_decrypt(shares, config),
        Algorithm::Progressive => progressive_decrypt(shares, config),
        Algorithm::ExtendedMeaningful => extended_meaningful_decrypt(shares, config),
        Algorithm::NaorShamir => naor_shamir_decrypt(shares, config),
        Algorithm::TaghaddosLatif => taghaddos_latif_decrypt(shares, config),
        Algorithm::DhimanKasana => dhiman_kasana_decrypt(shares, config),
        Algorithm::XorBased => xor_based_decrypt(shares, config),
    }
}

/// XOR-based encryption for better contrast
fn xor_based_encrypt(image: &DynamicImage, config: &VCConfig) -> Result<Vec<Share>> {
    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());

    // Generate XOR matrices
    let xor_matrices = generate_xor_matrices(config.num_shares)?;

    let mut shares = Vec::new();
    for i in 0..config.num_shares {
        shares.push(ImageBuffer::new(width, height));
    }

    let mut rng = rand::thread_rng();

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let pixel = binary.get_pixel(x, y)[0];
            let is_black = pixel == 0;

            // Select appropriate matrix
            let matrix = if is_black {
                &xor_matrices.black_pixel
            } else {
                &xor_matrices.white_pixel
            };

            // Select random column
            let col = rng.gen_range(0..matrix.ncols());

            // Distribute values to shares
            for share_idx in 0..config.num_shares {
                let value = matrix[(share_idx, col)];
                let pixel_value = if value == 1 { 0u8 } else { 255u8 };
                shares[share_idx].put_pixel(x, y, Luma([pixel_value]));
            }
        }
    }

    // Convert to Share objects
    let result: Vec<Share> = shares
        .into_iter()
        .enumerate()
        .map(|(i, img)| {
            Share::new(
                DynamicImage::ImageLuma8(img),
                i + 1,
                config.num_shares,
                width,
                height,
                1,
                false,
            )
        })
        .collect();

    Ok(result)
}

/// XOR-based decryption
fn xor_based_decrypt(shares: &[Share], _config: &VCConfig) -> Result<DynamicImage> {
    if shares.is_empty() {
        return Err(VCError::InsufficientShares {
            required: 1,
            provided: 0,
        });
    }

    let (width, height) = shares[0].dimensions();
    let mut result = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let mut xor_value = 0u8;

            for share in shares {
                if let DynamicImage::ImageLuma8(img) = &share.image {
                    let pixel = img.get_pixel(x, y)[0];
                    let bit = if pixel == 0 { 1 } else { 0 };
                    xor_value ^= bit;
                }
            }

            // XOR result: 1 = black, 0 = white
            let pixel_value = if xor_value == 1 { 0u8 } else { 255u8 };
            result.put_pixel(x, y, Luma([pixel_value]));
        }
    }

    Ok(DynamicImage::ImageLuma8(result))
}

/// Basic (k,n) threshold scheme encryption
fn basic_threshold_encrypt(image: &DynamicImage, config: &VCConfig) -> Result<Vec<Share>> {
    // Convert to binary image
    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());

    // Generate sharing matrices
    let matrices = generate_basic_matrices(config.threshold, config.num_shares, config.block_size)?;

    // Create shares with expanded dimensions
    let share_width = width * config.block_size as u32;
    let share_height = height * config.block_size as u32;

    let mut shares = Vec::new();
    for i in 0..config.num_shares {
        shares.push(ImageBuffer::new(share_width, share_height));
    }

    let mut rng = rand::thread_rng();

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let pixel = binary.get_pixel(x, y)[0];
            let matrix_idx = if pixel == 0 { 1 } else { 0 }; // black = 0, white = 255
            let matrix = &matrices[matrix_idx];

            // Select a random column from the matrix
            let col = rng.gen_range(0..matrix.ncols());

            // Distribute the column values to shares
            for share_idx in 0..config.num_shares {
                let value = matrix[(share_idx, col)];
                let block_value = if value == 1 { 0u8 } else { 255u8 };

                // Expand pixel to block
                let base_x = x * config.block_size as u32;
                let base_y = y * config.block_size as u32;

                for dy in 0..config.block_size as u32 {
                    for dx in 0..config.block_size as u32 {
                        shares[share_idx].put_pixel(base_x + dx, base_y + dy, Luma([block_value]));
                    }
                }
            }
        }
    }

    // Convert to Share objects
    let result: Vec<Share> = shares
        .into_iter()
        .enumerate()
        .map(|(i, img)| {
            Share::new(
                DynamicImage::ImageLuma8(img),
                i + 1,
                config.num_shares,
                width,
                height,
                config.block_size,
                false,
            )
        })
        .collect();

    Ok(result)
}

/// Basic threshold scheme decryption
fn basic_threshold_decrypt(shares: &[Share], _config: &VCConfig) -> Result<DynamicImage> {
    if let Some(stacked) = stack_shares(shares) {
        Ok(DynamicImage::ImageLuma8(stacked))
    } else {
        Err(VCError::DecryptionError(
            "Failed to stack shares".to_string(),
        ))
    }
}

/// Progressive visual cryptography encryption
fn progressive_encrypt(
    image: &DynamicImage,
    config: &VCConfig,
    cover_images: Option<Vec<DynamicImage>>,
) -> Result<Vec<Share>> {
    // Convert to binary
    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());

    // Use meaningful shares if cover images are provided
    if let Some(covers) = cover_images {
        if covers.len() != config.num_shares {
            return Err(VCError::CoverImageError(format!(
                "Number of cover images ({}) must match number of shares ({})",
                covers.len(),
                config.num_shares
            )));
        }

        // Generate dispatching matrices
        let i = config.num_shares; // Use n for maximum contrast
        let matrices = generate_dispatching_matrices(config.num_shares, i)?;

        let mut shares = Vec::new();

        for share_idx in 0..config.num_shares {
            let mut share_img = ImageBuffer::new(width, height);
            let cover_binary = convert_to_binary(&covers[share_idx]);

            for y in 0..height {
                for x in 0..width {
                    let secret_pixel = binary.get_pixel(x, y)[0] == 0; // true if black
                    let cover_pixel = cover_binary.get_pixel(x, y)[0] == 0; // true if black

                    let row = select_dispatching_row(&matrices, secret_pixel, cover_pixel);
                    let value = if row[share_idx] == 1 { 0u8 } else { 255u8 };

                    share_img.put_pixel(x, y, Luma([value]));
                }
            }

            shares.push(Share::new(
                DynamicImage::ImageLuma8(share_img),
                share_idx + 1,
                config.num_shares,
                width,
                height,
                1,    // No pixel expansion
                true, // Meaningful share
            ));
        }

        Ok(shares)
    } else {
        // Use proper progressive matrix construction
        progressive_matrix_based_encrypt(image, config)
    }
}

/// Proper progressive encryption using matrix construction
fn progressive_matrix_based_encrypt(image: &DynamicImage, config: &VCConfig) -> Result<Vec<Share>> {
    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());

    // Generate proper sharing matrices for progressive revelation
    let (white_matrix, black_matrix) = generate_proper_sharing_matrices(2, config.num_shares)?;

    let mut shares = Vec::new();
    for i in 0..config.num_shares {
        shares.push(ImageBuffer::new(width, height));
    }

    let mut rng = rand::thread_rng();

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let pixel = binary.get_pixel(x, y)[0];
            let is_black = pixel == 0;

            // Select appropriate matrix
            let matrix = if is_black {
                &black_matrix
            } else {
                &white_matrix
            };

            // For progressive schemes, weight column selection by share index
            let total_cols = matrix.ncols();
            let mut col_weights = Vec::new();

            for col in 0..total_cols {
                // Calculate weight based on how many participants have black pixels
                let black_count = (0..config.num_shares)
                    .map(|row| matrix[(row, col)] as usize)
                    .sum::<usize>();

                // Higher weight for patterns that progressively reveal
                let weight = if is_black {
                    (config.num_shares - black_count) + 1
                } else {
                    black_count + 1
                };

                col_weights.push(weight);
            }

            // Weighted random selection
            let total_weight: usize = col_weights.iter().sum();
            let mut random_weight = rng.gen_range(0..total_weight);
            let mut selected_col = 0;

            for (col, &weight) in col_weights.iter().enumerate() {
                if random_weight < weight {
                    selected_col = col;
                    break;
                }
                random_weight -= weight;
            }

            // Apply selected column to shares
            for share_idx in 0..config.num_shares {
                let value = matrix[(share_idx, selected_col)];
                let pixel_value = if value == 1 { 0u8 } else { 255u8 };
                shares[share_idx].put_pixel(x, y, Luma([pixel_value]));
            }
        }
    }

    // Convert to Share objects
    let result: Vec<Share> = shares
        .into_iter()
        .enumerate()
        .map(|(i, img)| {
            Share::new(
                DynamicImage::ImageLuma8(img),
                i + 1,
                config.num_shares,
                width,
                height,
                1,
                false,
            )
        })
        .collect();

    Ok(result)
}

/// Progressive decryption
fn progressive_decrypt(shares: &[Share], _config: &VCConfig) -> Result<DynamicImage> {
    basic_threshold_decrypt(shares, _config)
}

/// Extended meaningful shares encryption
fn extended_meaningful_encrypt(
    image: &DynamicImage,
    config: &VCConfig,
    cover_images: Option<Vec<DynamicImage>>,
) -> Result<Vec<Share>> {
    if cover_images.is_none() {
        return Err(VCError::CoverImageError(
            "Extended meaningful scheme requires cover images".to_string(),
        ));
    }

    // Use proper extended VCS algorithm
    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());
    let covers = cover_images.unwrap();

    // Generate dispatching matrices for extended scheme
    let matrices = generate_dispatching_matrices(config.num_shares, config.num_shares)?;

    let mut shares = Vec::new();

    for share_idx in 0..config.num_shares {
        let mut share_img = ImageBuffer::new(width, height);
        let cover_binary = convert_to_binary(&covers[share_idx]);

        for y in 0..height {
            for x in 0..width {
                let secret_pixel = binary.get_pixel(x, y)[0] == 0;
                let cover_pixel = cover_binary.get_pixel(x, y)[0] == 0;

                // Use extended algorithm logic
                let row = select_dispatching_row(&matrices, secret_pixel, cover_pixel);
                let value = if row[share_idx] == 1 { 0u8 } else { 255u8 };

                share_img.put_pixel(x, y, Luma([value]));
            }
        }

        shares.push(Share::new(
            DynamicImage::ImageLuma8(share_img),
            share_idx + 1,
            config.num_shares,
            width,
            height,
            1,
            true,
        ));
    }

    Ok(shares)
}

/// Extended meaningful decryption
fn extended_meaningful_decrypt(shares: &[Share], config: &VCConfig) -> Result<DynamicImage> {
    basic_threshold_decrypt(shares, config)
}

/// Naor-Shamir original scheme encryption
fn naor_shamir_encrypt(image: &DynamicImage, config: &VCConfig) -> Result<Vec<Share>> {
    // The original Naor-Shamir is a (2,2) scheme with 2x2 pixel expansion
    if config.num_shares != 2 || config.threshold != 2 {
        return Err(VCError::InvalidConfiguration(
            "Naor-Shamir scheme requires exactly 2 shares with threshold 2".to_string(),
        ));
    }

    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());

    // Fixed 2x2 patterns for Naor-Shamir
    let patterns = vec![
        vec![1, 1, 0, 0],
        vec![1, 0, 1, 0],
        vec![1, 0, 0, 1],
        vec![0, 1, 1, 0],
        vec![0, 1, 0, 1],
        vec![0, 0, 1, 1],
    ];

    let share_width = width * 2;
    let share_height = height * 2;

    let mut share1 = ImageBuffer::new(share_width, share_height);
    let mut share2 = ImageBuffer::new(share_width, share_height);

    let mut rng = rand::thread_rng();

    for y in 0..height {
        for x in 0..width {
            let pixel = binary.get_pixel(x, y)[0];
            let pattern_idx = rng.gen_range(0..patterns.len());
            let pattern = &patterns[pattern_idx];

            // Apply pattern to share 1
            share1.put_pixel(x * 2, y * 2, Luma([if pattern[0] == 1 { 0 } else { 255 }]));
            share1.put_pixel(
                x * 2 + 1,
                y * 2,
                Luma([if pattern[1] == 1 { 0 } else { 255 }]),
            );
            share1.put_pixel(
                x * 2,
                y * 2 + 1,
                Luma([if pattern[2] == 1 { 0 } else { 255 }]),
            );
            share1.put_pixel(
                x * 2 + 1,
                y * 2 + 1,
                Luma([if pattern[3] == 1 { 0 } else { 255 }]),
            );

            // Apply pattern or complement to share 2
            if pixel == 0 {
                // Black: use complement pattern
                share2.put_pixel(x * 2, y * 2, Luma([if pattern[0] == 0 { 0 } else { 255 }]));
                share2.put_pixel(
                    x * 2 + 1,
                    y * 2,
                    Luma([if pattern[1] == 0 { 0 } else { 255 }]),
                );
                share2.put_pixel(
                    x * 2,
                    y * 2 + 1,
                    Luma([if pattern[2] == 0 { 0 } else { 255 }]),
                );
                share2.put_pixel(
                    x * 2 + 1,
                    y * 2 + 1,
                    Luma([if pattern[3] == 0 { 0 } else { 255 }]),
                );
            } else {
                // White: use same pattern
                share2.put_pixel(x * 2, y * 2, Luma([if pattern[0] == 1 { 0 } else { 255 }]));
                share2.put_pixel(
                    x * 2 + 1,
                    y * 2,
                    Luma([if pattern[1] == 1 { 0 } else { 255 }]),
                );
                share2.put_pixel(
                    x * 2,
                    y * 2 + 1,
                    Luma([if pattern[2] == 1 { 0 } else { 255 }]),
                );
                share2.put_pixel(
                    x * 2 + 1,
                    y * 2 + 1,
                    Luma([if pattern[3] == 1 { 0 } else { 255 }]),
                );
            }
        }
    }

    Ok(vec![
        Share::new(
            DynamicImage::ImageLuma8(share1),
            1,
            2,
            width,
            height,
            2,
            false,
        ),
        Share::new(
            DynamicImage::ImageLuma8(share2),
            2,
            2,
            width,
            height,
            2,
            false,
        ),
    ])
}

/// Naor-Shamir decryption
fn naor_shamir_decrypt(shares: &[Share], config: &VCConfig) -> Result<DynamicImage> {
    basic_threshold_decrypt(shares, config)
}

/// Improved Taghaddos-Latif grayscale scheme with proper bit-plane processing
fn taghaddos_latif_encrypt(image: &DynamicImage, config: &VCConfig) -> Result<Vec<Share>> {
    let gray = image.to_luma8();
    let (width, height) = (gray.width(), gray.height());

    // Use proper sharing matrices for each bit plane
    let (white_matrix, black_matrix) =
        generate_proper_sharing_matrices(config.threshold, config.num_shares)?;

    let mut shares: Vec<ImageBuffer<Luma<u8>, Vec<u8>>> = Vec::new();
    for _ in 0..config.num_shares {
        shares.push(ImageBuffer::new(width, height));
    }

    let mut rng = rand::thread_rng();

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let pixel_value = gray.get_pixel(x, y)[0];
            let mut reconstructed_shares = vec![0u8; config.num_shares];

            // Process each bit plane
            for bit_pos in 0..8 {
                let bit = (pixel_value >> bit_pos) & 1;
                let matrix = if bit == 1 {
                    &black_matrix
                } else {
                    &white_matrix
                };

                // Select random column
                let col = rng.gen_range(0..matrix.ncols());

                // Apply bit-plane sharing
                for share_idx in 0..config.num_shares {
                    let share_bit = matrix[(share_idx, col)];
                    if share_bit == 1 {
                        reconstructed_shares[share_idx] |= 1 << bit_pos;
                    }
                }
            }

            // Set pixel values in shares
            for share_idx in 0..config.num_shares {
                shares[share_idx].put_pixel(x, y, Luma([reconstructed_shares[share_idx]]));
            }
        }
    }

    // Convert to Share objects
    let result: Vec<Share> = shares
        .into_iter()
        .enumerate()
        .map(|(i, img)| {
            Share::new(
                DynamicImage::ImageLuma8(img),
                i + 1,
                config.num_shares,
                width,
                height,
                1,
                false,
            )
        })
        .collect();

    Ok(result)
}

/// Improved Taghaddos-Latif decryption with proper reconstruction
fn taghaddos_latif_decrypt(shares: &[Share], config: &VCConfig) -> Result<DynamicImage> {
    if shares.len() < config.threshold {
        return Err(VCError::InsufficientShares {
            required: config.threshold,
            provided: shares.len(),
        });
    }

    let (width, height) = shares[0].dimensions();
    let mut result = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let mut reconstructed_value = 0u8;

            // Reconstruct each bit plane
            for bit_pos in 0..8 {
                let mut bit_sum = 0;

                // Sum bits from threshold number of shares
                for i in 0..config.threshold {
                    if let DynamicImage::ImageLuma8(img) = &shares[i].image {
                        let share_value = img.get_pixel(x, y)[0];
                        let bit = (share_value >> bit_pos) & 1;
                        bit_sum += bit as u32;
                    }
                }

                // Majority voting for bit reconstruction
                let reconstructed_bit = if bit_sum >= (config.threshold as u32 + 1) / 2 {
                    1
                } else {
                    0
                };
                reconstructed_value |= (reconstructed_bit as u8) << bit_pos;
            }

            result.put_pixel(x, y, Luma([reconstructed_value]));
        }
    }

    Ok(DynamicImage::ImageLuma8(result))
}

/// Proper Dhiman-Kasana EVCT(3,3) color scheme
fn dhiman_kasana_encrypt(
    image: &DynamicImage,
    config: &VCConfig,
    cover_images: Option<Vec<DynamicImage>>,
) -> Result<Vec<Share>> {
    if config.num_shares != 3 {
        return Err(VCError::InvalidConfiguration(
            "Dhiman-Kasana EVCT(3,3) scheme requires exactly 3 shares".to_string(),
        ));
    }

    let rgb = image.to_rgb8();
    let (width, height) = (rgb.width(), rgb.height());

    // Generate color mixing matrices
    let color_matrices = generate_color_mixing_matrices();

    let mut shares = Vec::new();
    for _ in 0..3 {
        shares.push(ImageBuffer::new(width, height));
    }

    let mut rng = rand::thread_rng();

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let pixel = rgb.get_pixel(x, y);
            let [r, g, b] = pixel.0;

            // Convert RGB to binary representation for each channel
            let r_binary = convert_channel_to_binary(r);
            let g_binary = convert_channel_to_binary(g);
            let b_binary = convert_channel_to_binary(b);

            // Process each color channel separately
            let mut final_shares = [Rgb([0u8, 0u8, 0u8]); 3];

            for channel in 0..3 {
                let binary_value = match channel {
                    0 => r_binary,
                    1 => g_binary,
                    2 => b_binary,
                    _ => 0,
                };

                // Select appropriate basis matrix
                let matrix_idx = binary_value as usize % color_matrices.basis_matrices.len();
                let matrix = &color_matrices.basis_matrices[matrix_idx];

                // Select random column
                let col = rng.gen_range(0..matrix.ncols());

                // Apply color mixing to shares
                for share_idx in 0..3 {
                    let intensity = matrix[(share_idx, col)];
                    let color_value = if intensity == 1 {
                        match channel {
                            0 => r,
                            1 => g,
                            2 => b,
                            _ => 0,
                        }
                    } else {
                        0
                    };

                    match channel {
                        0 => {
                            final_shares[share_idx].0[0] =
                                final_shares[share_idx].0[0].saturating_add(color_value)
                        }
                        1 => {
                            final_shares[share_idx].0[1] =
                                final_shares[share_idx].0[1].saturating_add(color_value)
                        }
                        2 => {
                            final_shares[share_idx].0[2] =
                                final_shares[share_idx].0[2].saturating_add(color_value)
                        }
                        _ => {}
                    }
                }
            }

            // Set pixel values in shares
            for share_idx in 0..3 {
                shares[share_idx].put_pixel(x, y, final_shares[share_idx]);
            }
        }
    }

    // Convert to Share objects
    let result: Vec<Share> = shares
        .into_iter()
        .enumerate()
        .map(|(i, img)| {
            Share::new(
                DynamicImage::ImageRgb8(img),
                i + 1,
                3,
                width,
                height,
                1,
                false,
            )
        })
        .collect();

    Ok(result)
}

/// Convert color channel value to binary representation
fn convert_channel_to_binary(value: u8) -> u8 {
    if value > 127 {
        1
    } else {
        0
    }
}

/// Proper Dhiman-Kasana decryption
fn dhiman_kasana_decrypt(shares: &[Share], _config: &VCConfig) -> Result<DynamicImage> {
    if shares.len() < 3 {
        return Err(VCError::InsufficientShares {
            required: 3,
            provided: shares.len(),
        });
    }

    let (width, height) = shares[0].dimensions();
    let mut result = ImageBuffer::new(width, height);

    for y in 0..height {
        for x in 0..width {
            let mut final_pixel = [0u8; 3];

            // Reconstruct each color channel
            for channel in 0..3 {
                let mut channel_sum = 0u16;
                let mut count = 0;

                for share in shares {
                    if let DynamicImage::ImageRgb8(img) = &share.image {
                        let pixel = img.get_pixel(x, y);
                        channel_sum += pixel.0[channel] as u16;
                        count += 1;
                    }
                }

                // Average the channel values (could use other reconstruction methods)
                final_pixel[channel] = if count > 0 {
                    (channel_sum / count as u16).min(255) as u8
                } else {
                    0
                };
            }

            result.put_pixel(x, y, Rgb(final_pixel));
        }
    }

    Ok(DynamicImage::ImageRgb8(result))
}
