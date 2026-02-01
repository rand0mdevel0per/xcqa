# XCQA - XC Quick Algo

A novel dictionary-based cryptosystem with zero-knowledge proof signatures.

## Overview

XCQA (XC Quick Algo) is an experimental cryptographic library that implements:

- **Dictionary-Transform Encryption**: Multi-layer cascading dictionary encoding with expansion (8→12, 6→9, 4→6, 2→4 bits)
- **Zero-Knowledge Signatures**: Commitment-challenge-response protocol proving knowledge of private key without revealing it
- **Permutation-Based Security**: Uses bijective transformations to ensure collision-free encryption

## Features

✓ **Cascading Multi-Layer Encoding**: Four-layer dictionary structure with 55% ciphertext expansion
✓ **IND-CPA Security**: Randomized padding for semantic security
✓ **Zstd Compression**: Reduces expansion from 1.55x to 1.19x (23% improvement)
✓ **Unified Config API**: Flexible encryption options with sensible defaults
✓ **Zero-Knowledge Proof Signatures**: Sign messages without revealing private key
✓ **Collision Resistance**: Different plaintexts produce different ciphertexts
✓ **Comprehensive Test Suite**: 26 tests covering encryption, signatures, and cryptographic properties

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
xcqa = "0.1.0"
```

## Quick Start

### Recommended: Unified Config API (IND-CPA Secure)

```rust
use xcqa::{keygen, encrypt_with_config, decrypt_with_config, EncryptionConfig};

// Generate key pair
let (public_key, private_key) = keygen();

// Encrypt with default config (randomness + compression)
let plaintext = b"Hello, XCQA!";
let ciphertext = encrypt_with_config(plaintext, &public_key, &EncryptionConfig::default())?;

// Decrypt with same config
let decrypted = decrypt_with_config(&ciphertext, &private_key, &EncryptionConfig::default())?;
assert_eq!(plaintext, &decrypted[..]);
```

### Custom Configuration

```rust
// Only randomness (IND-CPA secure, no compression)
let config = EncryptionConfig::randomness_only();
let ciphertext = encrypt_with_config(plaintext, &public_key, &config)?;

// Only compression (not IND-CPA secure)
let config = EncryptionConfig::compression_only();

// Basic mode (no randomness, no compression)
let config = EncryptionConfig::basic();
```

### Basic Encryption/Decryption (Legacy)

```rust
use xcqa::{keygen, encrypt, decrypt};

// Generate key pair
let (public_key, private_key) = keygen();

// Encrypt data
let plaintext = b"Hello, XCQA!";
let ciphertext = encrypt(plaintext, &public_key);

// Decrypt data
let decrypted = decrypt(&ciphertext, &private_key);
assert_eq!(plaintext, &decrypted[..plaintext.len()]);
```

### Zero-Knowledge Signatures

```rust
use xcqa::{keygen, sign, verify};

let (pk, sk) = keygen();
let message = b"Sign this message";

// Create signature
let signature = sign(message, &sk, &pk);

// Verify signature
let is_valid = verify(message, &signature, &pk);
assert!(is_valid);
```

## Architecture

### Dictionary Structure

XCQA uses a four-layer cascading dictionary:

- **Layer 0**: 8 bits → 12 bits (256 entries)
- **Layer 1**: 6 bits → 9 bits (64 entries)
- **Layer 2**: 4 bits → 6 bits (16 entries)
- **Layer 3**: 2 bits → 4 bits (4 entries)

One complete cycle: 20 input bits → 31 output bits (55% expansion)

### Key Generation

1. Generate random encoding dictionary (Dict_A)
2. Create inverse dictionary (Dict_B)
3. Generate transformation parameters (shift, rotate, XOR mask)
4. Apply permutation-based transformation to create public key dictionary
5. Create inverse of public key dictionary for decryption

### Zero-Knowledge Signature Protocol

**Sign:**
1. Generate random nonce (5 bytes, aligned with encoding cycles)
2. Encrypt nonce with public key → commitment
3. Compute challenge: Hash(commitment || message)
4. Decrypt commitment and XOR with challenge → response
5. Signature = (commitment, response)

**Verify:**
1. Recompute challenge: Hash(commitment || message)
2. Recover nonce: response XOR challenge
3. Verify: Encrypt(recovered_nonce) == commitment

## Security Considerations

⚠️ **Experimental**: XCQA is an experimental cryptosystem and has not undergone formal security audits.

**Properties:**
- ✓ Deterministic encryption (same input + key = same output)
- ✓ Collision resistance (different inputs → different outputs)
- ✓ Zero-knowledge signatures (proves key knowledge without revealing it)
- ⚠️ Localized avalanche effect (dictionary-based encoding has limited diffusion)

**Not Recommended For:**
- Production systems requiring high security
- Applications needing strong avalanche properties
- Scenarios requiring probabilistic encryption

**Suitable For:**
- Research and educational purposes
- Prototyping novel cryptographic schemes
- Understanding dictionary-based cryptography

## Performance

Benchmarked on modern hardware:

| Operation | Message Size | Time |
|-----------|--------------|------|
| KeyGen | - | 86.5 µs |
| Encrypt | 16 bytes | 950 ns |
| Encrypt | 64 bytes | 3.5 µs |
| Encrypt | 256 bytes | 13.5 µs |
| Encrypt | 1024 bytes | 31.7 µs |
| Decrypt | 16 bytes | 1.1 µs |
| Decrypt | 64 bytes | 4.1 µs |
| Decrypt | 256 bytes | 15.8 µs |
| Decrypt | 1024 bytes | 62.5 µs |

**Ciphertext Expansion:**
- Without compression: 1.55x (55% overhead)
- With compression: 1.19x (19% overhead) - 23% improvement

See [docs/BENCHMARK.md](docs/BENCHMARK.md) for detailed performance analysis.

## Testing

Run the full test suite:

```bash
cargo test
```

Tests include:
- Encryption/decryption correctness
- Signature creation and verification
- Cryptographic properties (determinism, collision resistance, avalanche effect)
- Edge cases (empty data, single byte, long messages)

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or pull request.

## Author

Created as part of cryptographic research into dictionary-based encryption schemes.

## Acknowledgments

Built with Rust 🦀 using:
- `rand` for random number generation
- `sha2` for cryptographic hashing
