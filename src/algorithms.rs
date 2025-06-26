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
use rand::{seq::SliceRandom, Rng};

/// Available visual cryptography algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Basic (k,n) threshold scheme
    BasicThreshold,
    /// Progressive visual cryptography
    Progressive,
    /// Extended visual cryptography with meaningful shares
    ExtendedMeaningful,
    /// Naor-Shamir original scheme (1994)
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
            "Original Naor-Shamir scheme requires exactly 2 shares with threshold 2".to_string(),
        ));
    }

    let binary = convert_to_binary(image);
    let (width, height) = (binary.width(), binary.height());

    // Fixed matrices for Naor-Shamir as per the original paper
    // For white pixels: both shares get identical patterns
    let white_matrix = vec![vec![1, 1, 0, 0], vec![1, 1, 0, 0]];
    // For black pixels: shares get complementary patterns
    let black_matrix = vec![vec![1, 1, 0, 0], vec![0, 0, 1, 1]];

    let share_width = width * 2;
    let share_height = height * 2;

    let mut share1 = ImageBuffer::new(share_width, share_height);
    let mut share2 = ImageBuffer::new(share_width, share_height);

    let mut rng = rand::thread_rng();

    for y in 0..height {
        for x in 0..width {
            let pixel = binary.get_pixel(x, y)[0];

            // Select appropriate matrix based on pixel value
            let matrix = if pixel == 0 {
                // black pixel
                &black_matrix
            } else {
                // white pixel
                &white_matrix
            };

            // Randomly permute columns (this is the key step in Naor-Shamir)
            let mut columns: Vec<usize> = (0..4).collect();
            columns.as_mut_slice().shuffle(&mut rng);

            // Create permuted patterns for both shares
            let share1_pattern = vec![
                matrix[0][columns[0]],
                matrix[0][columns[1]],
                matrix[0][columns[2]],
                matrix[0][columns[3]],
            ];
            let share2_pattern = vec![
                matrix[1][columns[0]],
                matrix[1][columns[1]],
                matrix[1][columns[2]],
                matrix[1][columns[3]],
            ];

            // Apply 2x2 patterns to shares
            // Share 1
            share1.put_pixel(
                x * 2,
                y * 2,
                Luma([if share1_pattern[0] == 1 { 0 } else { 255 }]),
            );
            share1.put_pixel(
                x * 2 + 1,
                y * 2,
                Luma([if share1_pattern[1] == 1 { 0 } else { 255 }]),
            );
            share1.put_pixel(
                x * 2,
                y * 2 + 1,
                Luma([if share1_pattern[2] == 1 { 0 } else { 255 }]),
            );
            share1.put_pixel(
                x * 2 + 1,
                y * 2 + 1,
                Luma([if share1_pattern[3] == 1 { 0 } else { 255 }]),
            );

            // Share 2
            share2.put_pixel(
                x * 2,
                y * 2,
                Luma([if share2_pattern[0] == 1 { 0 } else { 255 }]),
            );
            share2.put_pixel(
                x * 2 + 1,
                y * 2,
                Luma([if share2_pattern[1] == 1 { 0 } else { 255 }]),
            );
            share2.put_pixel(
                x * 2,
                y * 2 + 1,
                Luma([if share2_pattern[2] == 1 { 0 } else { 255 }]),
            );
            share2.put_pixel(
                x * 2 + 1,
                y * 2 + 1,
                Luma([if share2_pattern[3] == 1 { 0 } else { 255 }]),
            );
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

/// Taghaddos-Latif grayscale scheme following the original paper exactly
fn taghaddos_latif_encrypt(image: &DynamicImage, config: &VCConfig) -> Result<Vec<Share>> {
    if config.num_shares != 2 {
        return Err(VCError::InvalidConfiguration(
            "Taghaddos-Latif scheme requires exactly 2 shares".to_string(),
        ));
    }

    let gray = image.to_luma8();
    let (width, height) = (gray.width(), gray.height());

    // The 6 specific patterns from the original paper
    let patterns = [
        [1u8, 1u8, 0u8, 0u8],
        [1u8, 0u8, 1u8, 0u8],
        [1u8, 0u8, 0u8, 1u8],
        [0u8, 1u8, 1u8, 0u8],
        [0u8, 1u8, 0u8, 1u8],
        [0u8, 0u8, 1u8, 1u8],
    ];

    // Pixel expansion by 2 (2x2 blocks)
    let share_width = width * 2;
    let share_height = height * 2;

    let mut share_a = ImageBuffer::new(share_width, share_height);
    let mut share_b = ImageBuffer::new(share_width, share_height);

    let mut rng = rand::thread_rng();

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let pixel_value = gray.get_pixel(x, y)[0];
            let mut share_a_colors = [0u8; 4];
            let mut share_b_colors = [0u8; 4];

            // Process each bit plane (0-7)
            for bit_pos in 0..8 {
                let bit = (pixel_value >> bit_pos) & 1;

                // Randomly select one of the 6 patterns
                let pattern = patterns[rng.gen_range(0..6)];

                if bit == 1 {
                    // White pixel (bit = 1): both shares get identical patterns
                    for i in 0..4 {
                        share_a_colors[i] |= (pattern[i] << bit_pos);
                        share_b_colors[i] = share_a_colors[i];
                    }
                } else {
                    // Black pixel (bit = 0): share B gets complement of share A
                    for i in 0..4 {
                        share_a_colors[i] |= (pattern[i] << bit_pos);
                        share_b_colors[i] |= ((1 - pattern[i]) << bit_pos);
                    }
                }
            }

            // Draw 2x2 blocks for each share
            let base_x = x * 2;
            let base_y = y * 2;

            // Share A 2x2 block
            share_a.put_pixel(base_x, base_y, Luma([share_a_colors[0]]));
            share_a.put_pixel(base_x + 1, base_y, Luma([share_a_colors[1]]));
            share_a.put_pixel(base_x, base_y + 1, Luma([share_a_colors[2]]));
            share_a.put_pixel(base_x + 1, base_y + 1, Luma([share_a_colors[3]]));

            // Share B 2x2 block
            share_b.put_pixel(base_x, base_y, Luma([share_b_colors[0]]));
            share_b.put_pixel(base_x + 1, base_y, Luma([share_b_colors[1]]));
            share_b.put_pixel(base_x, base_y + 1, Luma([share_b_colors[2]]));
            share_b.put_pixel(base_x + 1, base_y + 1, Luma([share_b_colors[3]]));
        }
    }

    Ok(vec![
        Share::new(
            DynamicImage::ImageLuma8(share_a),
            1,
            2,
            width,
            height,
            2, // pixel expansion = 2
            false,
        ),
        Share::new(
            DynamicImage::ImageLuma8(share_b),
            2,
            2,
            width,
            height,
            2, // pixel expansion = 2
            false,
        ),
    ])
}

/// Taghaddos-Latif decryption using AND operation as per original paper
fn taghaddos_latif_decrypt(shares: &[Share], _config: &VCConfig) -> Result<DynamicImage> {
    if shares.len() < 2 {
        return Err(VCError::InsufficientShares {
            required: 2,
            provided: shares.len(),
        });
    }

    let (expanded_width, expanded_height) = shares[0].dimensions();

    // Original dimensions (accounting for pixel expansion)
    let width = expanded_width / 2;
    let height = expanded_height / 2;

    let mut result = ImageBuffer::new(width, height);

    // Extract share images
    let share_a = if let DynamicImage::ImageLuma8(img) = &shares[0].image {
        img
    } else {
        return Err(VCError::DecryptionError(
            "Share A is not grayscale".to_string(),
        ));
    };

    let share_b = if let DynamicImage::ImageLuma8(img) = &shares[1].image {
        img
    } else {
        return Err(VCError::DecryptionError(
            "Share B is not grayscale".to_string(),
        ));
    };

    // Process each original pixel (reconstructing from 2x2 blocks)
    for y in 0..height {
        for x in 0..width {
            let base_x = x * 2;
            let base_y = y * 2;

            // Get the 2x2 block values from both shares
            let share_a_block = [
                share_a.get_pixel(base_x, base_y)[0],
                share_a.get_pixel(base_x + 1, base_y)[0],
                share_a.get_pixel(base_x, base_y + 1)[0],
                share_a.get_pixel(base_x + 1, base_y + 1)[0],
            ];

            let share_b_block = [
                share_b.get_pixel(base_x, base_y)[0],
                share_b.get_pixel(base_x + 1, base_y)[0],
                share_b.get_pixel(base_x, base_y + 1)[0],
                share_b.get_pixel(base_x + 1, base_y + 1)[0],
            ];

            // Reconstruct pixel value using AND operation
            let mut reconstructed_value = 0u8;

            for bit_pos in 0..8 {
                let mut reconstructed_bits = [0u8; 4];

                // Apply AND operation for each sub-pixel in the 2x2 block
                for i in 0..4 {
                    let bit_a = (share_a_block[i] >> bit_pos) & 1;
                    let bit_b = (share_b_block[i] >> bit_pos) & 1;
                    reconstructed_bits[i] = bit_a & bit_b;
                }

                // Average the 4 sub-pixels to get the final bit
                // (this follows the HVS perception model from the paper)
                let sum = reconstructed_bits.iter().map(|&x| x as u32).sum::<u32>();
                let average_bit = if sum >= 2 { 1 } else { 0 }; // majority voting for sub-pixels

                reconstructed_value |= (average_bit as u8) << bit_pos;
            }

            result.put_pixel(x, y, Luma([reconstructed_value]));
        }
    }

    Ok(DynamicImage::ImageLuma8(result))
}

/// Dhiman-Kasana EVCT(3,3) color scheme
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

    // Specific bit position coordinates for each RGB channel
    let components = [
        // R channel positions
        [
            (4, 4),
            (4, 2),
            (3, 1),
            (2, 3),
            (2, 0),
            (1, 4),
            (1, 2),
            (0, 1),
        ],
        // G channel positions
        [
            (4, 3),
            (3, 4),
            (3, 2),
            (2, 1),
            (1, 3),
            (1, 0),
            (0, 4),
            (0, 2),
        ],
        // B channel positions
        [
            (4, 1),
            (3, 3),
            (3, 0),
            (2, 4),
            (2, 2),
            (1, 1),
            (0, 3),
            (0, 0),
        ],
    ];

    // 5x5 pixel expansion
    let share_width = width * 5;
    let share_height = height * 5;

    let mut shares = Vec::new();
    for _ in 0..3 {
        shares.push(ImageBuffer::new(share_width, share_height));
    }

    // Check if cover images are provided before moving them
    let has_cover_images = cover_images.is_some();

    // Use cover images if provided, otherwise use default cover colors
    let covers = if let Some(covers) = cover_images {
        if covers.len() != 3 {
            return Err(VCError::CoverImageError(
                "Dhiman-Kasana requires exactly 3 cover images".to_string(),
            ));
        }
        covers.into_iter().map(|img| img.to_rgb8()).collect()
    } else {
        // Default cover colors (white background)
        vec![
            ImageBuffer::from_pixel(width, height, Rgb([255, 255, 255])),
            ImageBuffer::from_pixel(width, height, Rgb([255, 255, 255])),
            ImageBuffer::from_pixel(width, height, Rgb([255, 255, 255])),
        ]
    };

    // Process each pixel
    for y in 0..height {
        for x in 0..width {
            let secret_pixel = rgb.get_pixel(x, y);
            let [r, g, b] = secret_pixel.0;

            // Process each share
            for share_idx in 0..3 {
                let cover_pixel = covers[share_idx].get_pixel(x, y);

                // Create 5x5 block filled with cover pixel color
                let mut block = ImageBuffer::from_pixel(5, 5, *cover_pixel);

                // Process each color channel
                for (channel_idx, &channel_value) in [r, g, b].iter().enumerate() {
                    let bit_positions = &components[channel_idx];

                    // Process each bit of the channel (8 bits)
                    for (bit_idx, &(bit_y, bit_x)) in bit_positions.iter().enumerate() {
                        let bit = (channel_value >> bit_idx) & 1;

                        // Encode bit: 1 = black (0,0,0), 0 = dark grey (30,30,30)
                        let pixel_color = if bit == 1 {
                            Rgb([0, 0, 0]) // Black for bit 1
                        } else {
                            Rgb([30, 30, 30]) // Dark grey for bit 0
                        };

                        block.put_pixel(bit_x, bit_y, pixel_color);
                    }
                }

                // Paste the 5x5 block into the share
                let base_x = x * 5;
                let base_y = y * 5;
                for block_y in 0..5 {
                    for block_x in 0..5 {
                        let pixel = block.get_pixel(block_x, block_y);
                        shares[share_idx].put_pixel(base_x + block_x, base_y + block_y, *pixel);
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
                DynamicImage::ImageRgb8(img),
                i + 1,
                3,
                width,
                height,
                5, // 5x5 pixel expansion
                has_cover_images,
            )
        })
        .collect();

    Ok(result)
}

/// Dhiman-Kasana decryption using XOR operation
fn dhiman_kasana_decrypt(shares: &[Share], _config: &VCConfig) -> Result<DynamicImage> {
    if shares.len() < 3 {
        return Err(VCError::InsufficientShares {
            required: 3,
            provided: shares.len(),
        });
    }

    // Get dimensions from the first share (expanded)
    let (expanded_width, expanded_height) = shares[0].dimensions();

    // Original dimensions (accounting for 5x5 pixel expansion)
    let width = expanded_width / 5;
    let height = expanded_height / 5;

    let mut result = ImageBuffer::new(width, height);

    // Bit position coordinates for each RGB channel
    let components = [
        // R channel positions
        [
            (4, 4),
            (4, 2),
            (3, 1),
            (2, 3),
            (2, 0),
            (1, 4),
            (1, 2),
            (0, 1),
        ],
        // G channel positions
        [
            (4, 3),
            (3, 4),
            (3, 2),
            (2, 1),
            (1, 3),
            (1, 0),
            (0, 4),
            (0, 2),
        ],
        // B channel positions
        [
            (4, 1),
            (3, 3),
            (3, 0),
            (2, 4),
            (2, 2),
            (1, 1),
            (0, 3),
            (0, 0),
        ],
    ];

    // Extract RGB images from shares
    let share_images: Vec<&ImageBuffer<Rgb<u8>, Vec<u8>>> = shares
        .iter()
        .map(|share| {
            if let DynamicImage::ImageRgb8(img) = &share.image {
                img
            } else {
                panic!("Share is not RGB format");
            }
        })
        .collect();

    // Process each original pixel
    for y in 0..height {
        for x in 0..width {
            let mut reconstructed_pixel = [0u8; 3];

            // Process each color channel
            for channel_idx in 0..3 {
                let bit_positions = &components[channel_idx];
                let mut channel_value = 0u8;

                // Extract bits from each position
                for (bit_idx, &(bit_y, bit_x)) in bit_positions.iter().enumerate() {
                    let base_x = x * 5;
                    let base_y = y * 5;

                    // Get the pixel from the corresponding share at the bit position
                    let pixel = share_images[channel_idx].get_pixel(base_x + bit_x, base_y + bit_y);

                    // Decode bit: (0,0,0) = 1, anything else = 0
                    let bit = if pixel.0 == [0, 0, 0] { 1 } else { 0 };

                    channel_value |= bit << bit_idx;
                }

                reconstructed_pixel[channel_idx] = channel_value;
            }

            result.put_pixel(x, y, Rgb(reconstructed_pixel));
        }
    }

    Ok(DynamicImage::ImageRgb8(result))
}
