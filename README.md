# Visual Cryptography

A Rust implementation of visual cryptography algorithms supporting multiple schemes and configurable block sizes.

## Overview

Visual cryptography is a technique that allows visual information (images) to be encrypted so that the decryption can be performed by the human visual system without any complex cryptographic computations. The basic principle involves splitting a secret image into multiple shares that appear as random noise but reveal the original secret when overlaid.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
visual-cryptography = "0.1.0"
```


## How to use

```rust
use visual_cryptography::{Algorithm, VCConfig, VisualCryptography};
use image::DynamicImage;

// Load your secret image
let secret_image = image::open("secret.png")?;

// Configure for Naor-Shamir (2,2) scheme
let config = VCConfig {
    num_shares: 2,
    threshold: 2,
    block_size: 2,
    algorithm: Algorithm::NaorShamir,
    use_meaningful_shares: false,
};

// Create visual cryptography instance
let vc = VisualCryptography::new(config)?;

// Encrypt into shares
let shares = vc.encrypt(&secret_image, None)?;

// Save shares
for (i, share) in shares.iter().enumerate() {
    share.save(&format!("share_{}.png", i + 1))?;
}

// Decrypt by stacking shares
let decrypted = vc.decrypt(&shares)?;
```


There is also an `/examples` directory with demonstration programs. You can run them with:
`cargo run --example <example_name>` (e.g. `cargo run --example xor_based_example`).


## Short API Reference

### Core Types

- `VCConfig` - Configuration for visual cryptography operations
- `VisualCryptography` - Main struct for encryption/decryption
- `Share` - Represents a single share
- `Algorithm` - Enum of available algorithms

### Main Functions

- `VisualCryptography::new(config)` - Create a new instance
- `encrypt(image, cover_images)` - Encrypt an image into shares
- `decrypt(shares)` - Decrypt shares back into an image

### Implemented schemes

- Naor & Shamir (1994) – the original visual cryptography scheme proposed by Naor and Shamir, specifically designed for (2,2) threshold with 2x2 pixel expansion.
- XOR-based scheme for better contrast without pixel expansion (Naor & Shamir uses AND operation and 2x2 pixel expansion)
- Nakajima & Yamaguchi (2002) – extended visual cryptography for natural images
- Taghaddos & Latif (2014) – extends visual cryptography to grayscale images using bit-level encoding.
- Dhiman & Kasana (2018) – supports color images by separating and encoding color channels.


### Schemes to be implemented

- Visual cryptography for color images by Young–Chang Hou (2003) (didn't manage to find a free paper)
- A QR code-based user-friendly visual cryptography scheme (QEVCS) by Lijing Ren & Denghui Zhang (2022)


### Schemes to be evaluated

- Extended Visual Cryptography for Natural Images (Nakajima & Yamaguchi, 2002) (don't like the current output, need thorough testing, smth is definitely wrong)


## Contributing

Contributions are very welcome! I don’t like that most Rust crates are maintained by a single person, so if you’d like to support this project, I can create a team and add you to it. In general, feel free to submit pull requests or open issues.


## License

This project is licensed under the MIT license.
