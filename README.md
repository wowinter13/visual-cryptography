# Visual Cryptography

A Rust implementation of visual cryptography algorithms supporting multiple schemes and configurable block sizes.


## Overview

Visual cryptography is a cryptographic technique that allows visual information (images) to be encrypted in such a way that the decryption can be performed by the human visual system without any complex cryptographic computations. The basic principle involves splitting a secret image into multiple shares that appear as random noise, but when overlaid, reveal the original secret.

### Implemented schemes

- Naor & Shamir (1994)
- XOR-based scheme for better contrast without pixel expansion (Naor & Shamir uses AND operation and 2x2 pixel expansion)
- Nakajima & Yamaguchi (2002)
- Taghaddos & Latif (2014)
- Dhiman & Kasana (2018)


### Schemes to be implemented

- Visual cryptography for color images by Young–Chang Hou (2003) (didn't manage to find a free paper)
- A QR code-based user-friendly visual cryptography scheme (QEVCS) by Lijing Ren & Denghui Zhang (2022)


### Schemes to be evaluated

- Extended Visual Cryptography for Natural Images (Nakajima & Yamaguchi, 2002) (don't like the current output, need thorough testing, smth is definitely wrong)