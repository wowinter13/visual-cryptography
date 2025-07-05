//! Matrix generation for visual cryptography schemes

use crate::error::{Result, VCError};
use nalgebra::DMatrix;
use rand::Rng;

/// Type alias for sharing matrices
pub type ShareMatrix = DMatrix<u8>;

/// Elementary matrices used in visual cryptography
#[derive(Debug, Clone)]
pub struct ElementaryMatrices {
    pub c0: ShareMatrix,
    pub c1: ShareMatrix,
    pub c2: ShareMatrix,
    pub c3: ShareMatrix,
}

/// Dispatching matrices for different pixel combinations
#[derive(Debug, Clone)]
pub struct DispatchingMatrices {
    pub m0: ShareMatrix, // (white secret, white cover)
    pub m1: ShareMatrix, // (white secret, black cover)
    pub m2: ShareMatrix, // (black secret, white cover)
    pub m3: ShareMatrix, // (black secret, black cover)
}

/// XOR-based matrices for better contrast
#[derive(Debug, Clone)]
pub struct XorMatrices {
    pub white_pixel: ShareMatrix,
    pub black_pixel: ShareMatrix,
}

/// Color mixing matrices for EVCT(3,3) scheme
#[derive(Debug, Clone)]
pub struct ColorMixingMatrices {
    pub basis_matrices: Vec<ShareMatrix>,
    pub complement_matrices: Vec<ShareMatrix>,
}

/// Generate elementary matrices for n participants
pub fn generate_elementary_matrices(n: usize) -> ElementaryMatrices {
    // C0: First row all 1s, rest all 0s
    let mut c0 = DMatrix::zeros(n, n);
    for j in 0..n {
        c0[(0, j)] = 1;
    }

    // C1: Identity matrix
    let c1 = DMatrix::identity(n, n);

    // C2: Similar to C1 but with grouped columns for progressive schemes
    let c2 = c1.clone();

    // C3: All 1s
    let c3 = DMatrix::from_element(n, n, 1);

    ElementaryMatrices { c0, c1, c2, c3 }
}

/// Generate proper (k,n) threshold sharing matrices based on visual cryptography theory
pub fn generate_proper_sharing_matrices(k: usize, n: usize) -> Result<(ShareMatrix, ShareMatrix)> {
    if k > n {
        return Err(VCError::InvalidConfiguration(
            "k cannot be greater than n".to_string(),
        ));
    }

    // Calculate the number of columns needed for proper contrast
    let m = binomial_coefficient(n - 1, k - 1);

    // Generate S0 (white pixel matrix)
    let mut s0 = DMatrix::zeros(n, m);
    // Generate all combinations of k-1 participants out of n-1 (excluding first participant)
    let combinations = generate_combinations(n - 1, k - 1);

    for (col, combo) in combinations.into_iter().enumerate() {
        // First participant always gets 1
        s0[(0, col)] = 1;

        // Selected participants get 1
        for &participant in &combo {
            s0[(participant + 1, col)] = 1;
        }
    }

    // Generate S1 (black pixel matrix) - complement of S0
    let mut s1 = DMatrix::zeros(n, m);
    for row in 0..n {
        for col in 0..m {
            s1[(row, col)] = 1 - s0[(row, col)];
        }
    }

    Ok((s0, s1))
}

/// Generate XOR-based matrices for better contrast
pub fn generate_xor_matrices(n: usize) -> Result<XorMatrices> {
    let m = 2_usize.pow((n - 1) as u32); // 2^(n-1) columns

    let mut white_matrix = DMatrix::zeros(n, m);
    let mut black_matrix = DMatrix::zeros(n, m);

    // Generate all possible bit patterns for n-1 participants
    for col in 0..m {
        // First participant gets random bit
        let first_bit = rand::rng().random_range(0..2);
        white_matrix[(0, col)] = first_bit;
        black_matrix[(0, col)] = first_bit;

        let mut xor_sum = first_bit;

        // Other participants get bits from the column index
        for row in 1..n {
            let bit = (col >> (row - 1)) & 1;
            white_matrix[(row, col)] = bit as u8;
            black_matrix[(row, col)] = bit as u8;
            xor_sum ^= bit as u8;
        }

        // Adjust last participant to ensure proper XOR properties
        if n > 1 {
            // For white pixels: XOR should result in 0 (even parity)
            if xor_sum == 1 {
                white_matrix[(n - 1, col)] = 1 - white_matrix[(n - 1, col)];
            }

            // For black pixels: XOR should result in 1 (odd parity)
            if xor_sum == 0 {
                black_matrix[(n - 1, col)] = 1 - black_matrix[(n - 1, col)];
            }
        }
    }

    Ok(XorMatrices {
        white_pixel: white_matrix,
        black_pixel: black_matrix,
    })
}

/// Generate color mixing matrices for EVCT(3,3) Dhiman-Kasana algorithm
pub fn generate_color_mixing_matrices() -> ColorMixingMatrices {
    // For EVCT(3,3), we need 8 basis matrices (2^3)
    let mut basis_matrices = Vec::new();
    let mut complement_matrices = Vec::new();

    // Generate all 8 possible combinations for 3 participants
    (0..8).for_each(|_| {
        let mut matrix = DMatrix::zeros(3, 8);
        let mut complement = DMatrix::zeros(3, 8);

        for col in 0..8 {
            for row in 0..3 {
                // Generate pattern based on bit positions
                let bit = (col >> row) & 1;
                matrix[(row, col)] = bit as u8;
                complement[(row, col)] = 1 - (bit as u8);
            }
        }

        basis_matrices.push(matrix);
        complement_matrices.push(complement);
    });

    ColorMixingMatrices {
        basis_matrices,
        complement_matrices,
    }
}

/// Generate dispatching matrices for meaningful shares
pub fn generate_dispatching_matrices(n: usize, i: usize) -> Result<DispatchingMatrices> {
    if i < 2 || i > n {
        return Err(VCError::InvalidConfiguration(format!(
            "i must be between 2 and {}, got {}",
            n, i
        )));
    }

    let elem = generate_elementary_matrices(n);
    let total_rows = i + n;

    // Generate C2' and C3' for the upper part
    let c2_prime = generate_c2_prime(i, n);
    let c3_prime = DMatrix::from_element(i, n, 1);

    // M0: (white, white) = [C2'; C0]
    let mut m0 = DMatrix::zeros(total_rows, n);
    for row in 0..i {
        for col in 0..n {
            m0[(row, col)] = c2_prime[(row, col)];
        }
    }
    for row in 0..n {
        for col in 0..n {
            m0[(i + row, col)] = elem.c0[(row, col)];
        }
    }

    // M1: (white, black) = [C3'; C0]
    let mut m1 = DMatrix::zeros(total_rows, n);
    for row in 0..i {
        for col in 0..n {
            m1[(row, col)] = c3_prime[(row, col)];
        }
    }
    for row in 0..n {
        for col in 0..n {
            m1[(i + row, col)] = elem.c0[(row, col)];
        }
    }

    // M2: (black, white) = [C2'; C1]
    let mut m2 = DMatrix::zeros(total_rows, n);
    for row in 0..i {
        for col in 0..n {
            m2[(row, col)] = c2_prime[(row, col)];
        }
    }
    for row in 0..n {
        for col in 0..n {
            m2[(i + row, col)] = elem.c1[(row, col)];
        }
    }

    // M3: (black, black) = [C3'; C1]
    let mut m3 = DMatrix::zeros(total_rows, n);
    for row in 0..i {
        for col in 0..n {
            m3[(row, col)] = c3_prime[(row, col)];
        }
    }
    for row in 0..n {
        for col in 0..n {
            m3[(i + row, col)] = elem.c1[(row, col)];
        }
    }

    Ok(DispatchingMatrices { m0, m1, m2, m3 })
}

/// Generate C2' matrix with grouped columns
fn generate_c2_prime(i: usize, n: usize) -> ShareMatrix {
    let mut matrix = DMatrix::zeros(i, n);
    let group_size = n / i;
    let remainder = n % i;

    let mut col = 0;
    for row in 0..i {
        let current_group_size = if row < remainder {
            group_size + 1
        } else {
            group_size
        };

        for _ in 0..current_group_size {
            if col < n {
                matrix[(row, col)] = 1;
                col += 1;
            }
        }
    }

    matrix
}

/// Generate basic sharing matrices for (k,n) threshold scheme
pub fn generate_basic_matrices(k: usize, n: usize, block_size: usize) -> Result<Vec<ShareMatrix>> {
    if k > n {
        return Err(VCError::InvalidConfiguration(
            "k cannot be greater than n".to_string(),
        ));
    }

    // Use proper sharing matrices if available
    if block_size == 1 && k <= n {
        let (s0, s1) = generate_proper_sharing_matrices(k, n)?;
        return Ok(vec![s0, s1]);
    }

    let mut matrices = Vec::new();
    let matrix_size = block_size * block_size;

    // Generate matrices for white pixels
    let white_matrix = generate_white_pixel_matrix(k, n, matrix_size);
    matrices.push(white_matrix);

    // Generate matrices for black pixels
    let black_matrix = generate_black_pixel_matrix(n, matrix_size);
    matrices.push(black_matrix);

    Ok(matrices)
}

/// Generate matrix for white pixels in basic scheme
fn generate_white_pixel_matrix(k: usize, n: usize, size: usize) -> ShareMatrix {
    let mut matrix = DMatrix::zeros(n, size);
    let mut rng = rand::rng();

    // For white pixels, ensure that any k shares will have some white subpixels
    for col in 0..size {
        // Randomly select k-1 shares to have black subpixels
        let mut indices: Vec<usize> = (0..n).collect();
        indices.sort_by_key(|_| rng.random::<u32>());

        let k_minus_1 = k.saturating_sub(1);
        for &row_idx in indices.iter().take(k_minus_1) {
            matrix[(row_idx, col)] = 1;
        }
    }

    matrix
}

/// Generate matrix for black pixels in basic scheme
fn generate_black_pixel_matrix(n: usize, size: usize) -> ShareMatrix {
    // For black pixels, ensure that any k shares will have all black subpixels
    DMatrix::from_element(n, size, 1)
}

/// Select a row from a dispatching matrix based on pixel values
pub fn select_dispatching_row(
    matrices: &DispatchingMatrices,
    secret_pixel: bool,
    cover_pixel: bool,
) -> Vec<u8> {
    let matrix = match (secret_pixel, cover_pixel) {
        (false, false) => &matrices.m0,
        (false, true) => &matrices.m1,
        (true, false) => &matrices.m2,
        (true, true) => &matrices.m3,
    };

    let mut rng = rand::rng();
    let row_index = rng.random_range(0..matrix.nrows());

    matrix.row(row_index).iter().cloned().collect()
}

/// Calculate binomial coefficient C(n, k)
fn binomial_coefficient(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }

    let k = if k > n - k { n - k } else { k };
    let mut result = 1;

    for i in 0..k {
        result = result * (n - i) / (i + 1);
    }

    result
}

/// Generate all combinations of k elements from n elements
fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut combinations = Vec::new();
    let mut current = Vec::new();
    generate_combinations_recursive(0, n, k, &mut current, &mut combinations);
    combinations
}

fn generate_combinations_recursive(
    start: usize,
    n: usize,
    k: usize,
    current: &mut Vec<usize>,
    combinations: &mut Vec<Vec<usize>>,
) {
    if current.len() == k {
        combinations.push(current.clone());
        return;
    }

    for i in start..n {
        current.push(i);
        generate_combinations_recursive(i + 1, n, k, current, combinations);
        current.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elementary_matrices() {
        let elem = generate_elementary_matrices(4);

        // Test C0: first row should be all 1s
        let first_row_sum: u8 = elem.c0.row(0).iter().sum();
        assert_eq!(first_row_sum, 4);

        // Check that other rows are all zeros
        let mut other_rows_sum = 0u8;
        for row in 1..4 {
            other_rows_sum += elem.c0.row(row).iter().sum::<u8>();
        }
        assert_eq!(other_rows_sum, 0);

        // Test C1: should be identity
        assert_eq!(elem.c1, DMatrix::identity(4, 4));

        // Test C3: should be all 1s
        let c3_sum: u8 = elem.c3.iter().sum();
        assert_eq!(c3_sum, 16);
    }

    #[test]
    fn test_dispatching_matrices() {
        let matrices = generate_dispatching_matrices(4, 2).unwrap();

        // Check dimensions
        assert_eq!(matrices.m0.nrows(), 6); // i + n = 2 + 4
        assert_eq!(matrices.m0.ncols(), 4);
    }

    #[test]
    fn test_proper_sharing_matrices() {
        let (s0, s1) = generate_proper_sharing_matrices(2, 3).unwrap();

        // Check dimensions
        assert_eq!(s0.nrows(), 3);
        assert_eq!(s1.nrows(), 3);

        // S1 should be complement of S0
        for row in 0..s0.nrows() {
            for col in 0..s0.ncols() {
                assert_eq!(s0[(row, col)] + s1[(row, col)], 1);
            }
        }
    }

    #[test]
    fn test_xor_matrices() {
        let xor_matrices = generate_xor_matrices(3).unwrap();

        // Check dimensions - should be 3x4 (n x 2^(n-1))
        assert_eq!(xor_matrices.white_pixel.nrows(), 3);
        assert_eq!(xor_matrices.white_pixel.ncols(), 4);
    }

    #[test]
    fn test_binomial_coefficient() {
        assert_eq!(binomial_coefficient(5, 2), 10);
        assert_eq!(binomial_coefficient(4, 0), 1);
        assert_eq!(binomial_coefficient(4, 4), 1);
        assert_eq!(binomial_coefficient(6, 3), 20);
    }
}
