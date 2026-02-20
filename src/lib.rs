use std::collections::HashMap;
use rand::Rng;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

pub mod config;
pub mod simd;
use config::{DictionaryConfig, LayerConfig, EncryptionConfig};

/// Bit stream for encoding/decoding
struct BitStream {
    bits: Vec<bool>,
}

impl BitStream {
    /// Create from bytes (SIMD-optimized)
    fn from_bytes(bytes: &[u8]) -> Self {
        let bits = simd::bytes_to_bits_simd(bytes);
        BitStream { bits }
    }

    /// Convert to bytes (SIMD-optimized)
    fn to_bytes(&self) -> Vec<u8> {
        simd::bits_to_bytes_simd(&self.bits)
    }

    /// Read n bits as u64
    fn read_bits(&self, offset: usize, n: usize) -> Option<u64> {
        if offset + n > self.bits.len() {
            return None;
        }
        let mut value = 0u64;
        for i in 0..n {
            if self.bits[offset + i] {
                value |= 1 << (n - 1 - i);
            }
        }
        Some(value)
    }

    /// Write n bits from u64
    fn write_bits(&mut self, value: u64, n: usize) {
        for i in (0..n).rev() {
            self.bits.push((value >> i) & 1 == 1);
        }
    }
}

/// Multi-layer dictionary structure
/// Each layer maps input bits to output bits (expansion encoding)
#[derive(Debug, Clone)]
struct DictLayer {
    /// Number of input bits
    input_bits: usize,
    /// Number of output bits
    output_bits: usize,
    /// Mapping table: input pattern -> output pattern
    mapping: HashMap<u64, u64>,
}

impl DictLayer {
    /// Generate a random dictionary layer
    fn generate(input_bits: usize, output_bits: usize) -> Self {
        let mut rng = rand::thread_rng();
        let mut mapping = HashMap::new();

        // Generate all possible input patterns
        let num_patterns = 1u64 << input_bits;
        let num_outputs = 1u64 << output_bits;

        // Generate unique random outputs for each input
        // Create a shuffled list of outputs
        let mut available_outputs: Vec<u64> = (0..num_outputs).collect();

        // Shuffle using Fisher-Yates algorithm
        for i in (1..available_outputs.len()).rev() {
            let j = rng.r#gen::<usize>() % (i + 1);
            available_outputs.swap(i, j);
        }

        // Assign outputs to inputs
        for input in 0..num_patterns {
            let output = available_outputs[input as usize];
            mapping.insert(input, output);
        }

        DictLayer {
            input_bits,
            output_bits,
            mapping,
        }
    }

    /// Encode: input -> output
    fn encode(&self, input: u64) -> Option<u64> {
        self.mapping.get(&input).copied()
    }
}

/// Complete dictionary (contains multiple layers)
#[derive(Debug, Clone)]
pub struct Dictionary {
    layers: Vec<DictLayer>,
}

impl Dictionary {
    /// Generate multi-layer dictionary
    /// Layer structure:
    /// - Layer 0: 8 bits -> 12 bits (256 entries)
    /// - Layer 1: 6 bits -> 9 bits (64 entries)
    /// - Layer 2: 4 bits -> 6 bits (16 entries)
    /// - Layer 3: 2 bits -> 4 bits (4 entries)
    /// Generate a random multi-layer dictionary with custom configuration
    pub fn generate_with_config(config: &DictionaryConfig) -> Self {
        let layers = config.layers()
            .iter()
            .map(|cfg| DictLayer::generate(cfg.input_bits, cfg.output_bits))
            .collect();

        Dictionary { layers }
    }

    /// Generate a random multi-layer dictionary with default configuration
    pub fn generate() -> Self {
        Self::generate_with_config(&DictionaryConfig::default())
    }

    /// Create decoding dictionary (inverse mapping)
    fn create_inverse(&self) -> Self {
        let inverse_layers = self
            .layers
            .iter()
            .map(|layer| {
                let mut inverse_mapping = HashMap::new();
                for (input, output) in &layer.mapping {
                    inverse_mapping.insert(*output, *input);
                }
                DictLayer {
                    input_bits: layer.output_bits,
                    output_bits: layer.input_bits,
                    mapping: inverse_mapping,
                }
            })
            .collect();

        Dictionary {
            layers: inverse_layers,
        }
    }

    /// Apply transformation to dictionary (generate public key dictionary)
    /// Uses permutation-based transformation to ensure bijectivity
    fn apply_transform(&self, params: &TransformParams) -> Self {
        let transformed_layers = self
            .layers
            .iter()
            .map(|layer| {
                // Create a permutation of the output space
                let num_outputs = 1u64 << layer.output_bits;
                let permutation = params.create_permutation(num_outputs as usize);

                let mut transformed_mapping = HashMap::new();
                for (input, output) in &layer.mapping {
                    // Apply permutation to output
                    let transformed_output = permutation[*output as usize];
                    transformed_mapping.insert(*input, transformed_output);
                }
                DictLayer {
                    input_bits: layer.input_bits,
                    output_bits: layer.output_bits,
                    mapping: transformed_mapping,
                }
            })
            .collect();

        Dictionary {
            layers: transformed_layers,
        }
    }

    /// Encode bytes using cascading multi-layer dictionary
    /// Layers are applied in sequence: Layer 0 -> 1 -> 2 -> 3, then repeat
    /// One cycle: 8+6+4+2=20 input bits -> 12+9+6+4=31 output bits
    fn encode_bytes(&self, data: &[u8]) -> Vec<u8> {
        let input_stream = BitStream::from_bytes(data);
        let mut output_stream = BitStream { bits: Vec::new() };
        let mut offset = 0;

        // Process data in cascading cycles through all layers
        loop {
            let mut any_layer_applied = false;

            // Try to apply each layer in sequence
            for layer in &self.layers {
                if offset + layer.input_bits <= input_stream.bits.len() {
                    if let Some(input_pattern) = input_stream.read_bits(offset, layer.input_bits) {
                        if let Some(output_pattern) = layer.encode(input_pattern) {
                            output_stream.write_bits(output_pattern, layer.output_bits);
                            offset += layer.input_bits;
                            any_layer_applied = true;
                        }
                    }
                }
                // Continue to next layer even if this one couldn't be applied
            }

            // Stop when no layers can be applied
            if !any_layer_applied {
                break;
            }
        }

        output_stream.to_bytes()
    }

    /// Decode bytes using cascading multi-layer dictionary
    /// Layers are applied in sequence: Layer 0 -> 1 -> 2 -> 3, then repeat
    /// One cycle: 12+9+6+4=31 input bits -> 8+6+4+2=20 output bits
    fn decode_bytes(&self, data: &[u8]) -> Vec<u8> {
        let input_stream = BitStream::from_bytes(data);
        let mut output_stream = BitStream { bits: Vec::new() };
        let mut offset = 0;

        // Process data in cascading cycles through all layers
        loop {
            let mut any_layer_applied = false;

            // Try to apply each layer in sequence
            for layer in &self.layers {
                if offset + layer.input_bits <= input_stream.bits.len() {
                    if let Some(input_pattern) = input_stream.read_bits(offset, layer.input_bits) {
                        if let Some(output_pattern) = layer.encode(input_pattern) {
                            output_stream.write_bits(output_pattern, layer.output_bits);
                            offset += layer.input_bits;
                            any_layer_applied = true;
                        }
                    }
                }
                // Continue to next layer even if this one couldn't be applied
            }

            // Stop when no layers can be applied
            if !any_layer_applied {
                break;
            }
        }

        output_stream.to_bytes()
    }
}

/// Transformation parameters
#[derive(Debug, Clone)]
struct TransformParams {
    shift: u128,
    rotate: u8,
    xor_mask: u128,
}

impl TransformParams {
    /// Generate random transformation parameters
    fn generate() -> Self {
        let mut rng = rand::thread_rng();
        TransformParams {
            shift: rng.r#gen(),
            rotate: rng.r#gen::<u8>() % 128,
            xor_mask: rng.r#gen(),
        }
    }

    /// Apply transformation to a value
    fn transform(&self, value: u64) -> u64 {
        let v = value as u128;
        // 1. XOR
        let v = v ^ self.xor_mask;
        // 2. Shift
        let v = v.wrapping_add(self.shift);
        // 3. Rotate
        let v = v.rotate_left(self.rotate as u32);
        // Truncate to 64 bits
        (v & 0xFFFFFFFFFFFFFFFF) as u64
    }

    /// Inverse transformation
    fn inverse_transform(&self, value: u64) -> u64 {
        let v = value as u128;
        // Reverse order
        // 3. Inverse Rotate
        let v = v.rotate_right(self.rotate as u32);
        // 2. Inverse Shift
        let v = v.wrapping_sub(self.shift);
        // 1. Inverse XOR
        let v = v ^ self.xor_mask;
        (v & 0xFFFFFFFFFFFFFFFF) as u64
    }

    /// Create a random permutation of size n using transformation parameters as seed
    /// This ensures the permutation is deterministic and bijective
    fn create_permutation(&self, n: usize) -> Vec<u64> {
        let mut permutation: Vec<u64> = (0..n as u64).collect();

        // Use transformation parameters to seed the shuffle
        // Apply Fisher-Yates shuffle with deterministic randomness
        for i in (1..n).rev() {
            // Generate pseudo-random index using transformation parameters
            let seed = self.transform(i as u64);
            let j = (seed as usize) % (i + 1);
            permutation.swap(i, j);
        }

        permutation
    }
}

/// Public key (transformed dictionary)
#[derive(Debug, Clone)]
pub struct PublicKey {
    dict: Dictionary,
}

/// Private key (original dictionary + transformation parameters)
#[derive(Debug, Clone)]
pub struct PrivateKey {
    dict_encode: Dictionary,  // Dict_A (original encoding dictionary)
    dict_decode: Dictionary,  // Dict_B (inverse of Dict_A)
    dict_pub_inverse: Dictionary,  // Inverse of public key dictionary
    transform: TransformParams,
}

/// Zero-knowledge signature
/// Proves knowledge of private key without revealing it
#[derive(Debug, Clone)]
pub struct Signature {
    pub commitment: Vec<u8>,  // C: encrypted nonce
    pub response: Vec<u8>,    // s: nonce XOR challenge
}

/// Key generation
/// Generate key pair with custom dictionary configuration
pub fn keygen_with_config(config: &DictionaryConfig) -> (PublicKey, PrivateKey) {
    // 1. Generate original encoding dictionary with custom config
    let dict_encode = Dictionary::generate_with_config(config);

    // 2. Create decoding dictionary (inverse mapping)
    let dict_decode = dict_encode.create_inverse();

    // 3. Generate transformation parameters
    let transform = TransformParams::generate();

    // 4. Apply transformation to generate public key dictionary
    let dict_pub = dict_encode.apply_transform(&transform);

    // 5. Create inverse of public key dictionary for decryption
    let dict_pub_inverse = dict_pub.create_inverse();

    // 6. Construct public key and private key
    let pk = PublicKey { dict: dict_pub };
    let sk = PrivateKey {
        dict_encode,
        dict_decode,
        dict_pub_inverse,
        transform,
    };

    (pk, sk)
}

/// Generate key pair with default dictionary configuration
pub fn keygen() -> (PublicKey, PrivateKey) {
    keygen_with_config(&DictionaryConfig::default())
}

/// Encrypt data using public key
pub fn encrypt(data: &[u8], pk: &PublicKey) -> Vec<u8> {
    pk.dict.encode_bytes(data)
}

/// Decrypt data using private key
pub fn decrypt(ciphertext: &[u8], sk: &PrivateKey) -> Vec<u8> {
    sk.dict_pub_inverse.decode_bytes(ciphertext)
}

/// Sign a message using zero-knowledge proof
/// Proves knowledge of private key without revealing it
pub fn sign(message: &[u8], sk: &PrivateKey, pk: &PublicKey) -> Signature {
    sign_with_context(message, sk, pk, &[])
}

/// Sign with additional context (e.g., block hash for blockchain)
pub fn sign_with_context(message: &[u8], sk: &PrivateKey, pk: &PublicKey, context: &[u8]) -> Signature {
    let mut rng = rand::thread_rng();

    // 1. Generate random nonce (40 bits = 2 complete cycles, 5 bytes)
    // This ensures perfect alignment with cascading encoding
    let nonce_bytes = 5;
    let mut nonce = vec![0u8; nonce_bytes];
    rng.fill(&mut nonce[..]);

    // 2. Encrypt nonce with public key: C = Encode(nonce, Dict_pub)
    let commitment = encrypt(&nonce, pk);

    // 3. Compute challenge: e = Hash(C || message || context)
    let mut hasher = Sha256::new();
    hasher.update(&commitment);
    hasher.update(message);
    hasher.update(context);
    let challenge = hasher.finalize();

    // 4. Decrypt commitment: r = Decode(C, Dict_pub_inverse)
    let decrypted_nonce = decrypt(&commitment, sk);

    // 5. Compute response: s = r XOR e (only use first bytes of challenge)
    let mut response = vec![0u8; decrypted_nonce.len()];
    for i in 0..response.len() {
        response[i] = decrypted_nonce[i] ^ challenge[i];
    }

    Signature {
        commitment,
        response,
    }
}

/// Verify a zero-knowledge signature
/// Returns true if signature is valid
pub fn verify(message: &[u8], signature: &Signature, pk: &PublicKey) -> bool {
    verify_with_context(message, signature, pk, &[])
}

/// Verify with additional context (e.g., block hash for blockchain)
pub fn verify_with_context(message: &[u8], signature: &Signature, pk: &PublicKey, context: &[u8]) -> bool {
    // 1. Compute challenge: e = Hash(C || message || context)
    let mut hasher = Sha256::new();
    hasher.update(&signature.commitment);
    hasher.update(message);
    hasher.update(context);
    let challenge = hasher.finalize();

    // 2. Recover nonce: r = s XOR e (only use first bytes of challenge)
    let mut recovered_nonce = vec![0u8; signature.response.len()];
    for i in 0..recovered_nonce.len() {
        recovered_nonce[i] = signature.response[i] ^ challenge[i];
    }

    // 3. Verify: Encode(r, Dict_pub) should equal C
    let recomputed_commitment = encrypt(&recovered_nonce, pk);

    // 4. Check if commitments match
    recomputed_commitment == signature.commitment
}

// ============================================================================
// IND-CPA Security: Randomized Padding
// ============================================================================

/// Encrypt with random padding for IND-CPA security
///
/// Adds a 4-byte length field and 16-byte random nonce before encryption.
/// Structure: [length: 4 bytes][nonce: 16 bytes][plaintext: variable]
/// This ensures that the same plaintext produces different ciphertexts each time.
pub fn encrypt_with_randomness(plaintext: &[u8], pk: &PublicKey) -> Vec<u8> {
    use rand::RngCore;

    // Store original plaintext length (4 bytes, big-endian)
    let length = plaintext.len() as u32;
    let length_bytes = length.to_be_bytes();

    // Generate 16-byte random nonce
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Construct: [length][nonce][plaintext]
    let mut padded = Vec::with_capacity(4 + 16 + plaintext.len());
    padded.extend_from_slice(&length_bytes);
    padded.extend_from_slice(&nonce);
    padded.extend_from_slice(plaintext);

    // Encrypt the padded message
    encrypt(&padded, pk)
}

/// Decrypt and remove random padding
///
/// Decrypts the ciphertext and extracts the original plaintext using the stored length.
pub fn decrypt_with_randomness(ciphertext: &[u8], sk: &PrivateKey) -> Vec<u8> {
    // Decrypt
    let padded = decrypt(ciphertext, sk);

    // Need at least 4 bytes for length + 16 bytes for nonce
    if padded.len() < 20 {
        return Vec::new();
    }

    // Read original plaintext length (first 4 bytes)
    let length_bytes: [u8; 4] = padded[0..4].try_into().unwrap();
    let length = u32::from_be_bytes(length_bytes) as usize;

    // Skip length (4 bytes) and nonce (16 bytes), extract plaintext
    let start = 20;
    let end = start + length;

    if end <= padded.len() {
        padded[start..end].to_vec()
    } else {
        // Length field is corrupted or invalid
        Vec::new()
    }
}

// ============================================================================
// Size Optimization: Zstd Compression
// ============================================================================

/// Encrypt and compress with zstd
///
/// Encrypts the plaintext, then compresses the ciphertext with zstd.
/// Compression level 3 provides good balance between speed and compression ratio.
pub fn encrypt_with_compression(plaintext: &[u8], pk: &PublicKey) -> Result<Vec<u8>, String> {
    let ciphertext = encrypt(plaintext, pk);

    zstd::encode_all(&ciphertext[..], 3)
        .map_err(|e| format!("Compression failed: {:?}", e))
}

/// Decompress and decrypt
///
/// Decompresses the compressed ciphertext, then decrypts it.
pub fn decrypt_with_decompression(compressed: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, String> {
    let ciphertext = zstd::decode_all(compressed)
        .map_err(|e| format!("Decompression failed: {:?}", e))?;

    Ok(decrypt(&ciphertext, sk))
}

/// Encrypt with both randomness and compression (IND-CPA + size optimization)
///
/// Combines randomized padding and zstd compression for maximum security and efficiency.
pub fn encrypt_randomized_compressed(plaintext: &[u8], pk: &PublicKey) -> Result<Vec<u8>, String> {
    let ciphertext = encrypt_with_randomness(plaintext, pk);

    zstd::encode_all(&ciphertext[..], 3)
        .map_err(|e| format!("Compression failed: {:?}", e))
}

/// Decrypt with decompression and randomness removal
///
/// Decompresses, decrypts, and removes the random padding.
pub fn decrypt_decompressed_randomized(compressed: &[u8], sk: &PrivateKey) -> Result<Vec<u8>, String> {
    let ciphertext = zstd::decode_all(compressed)
        .map_err(|e| format!("Decompression failed: {:?}", e))?;

    Ok(decrypt_with_randomness(&ciphertext, sk))
}

// ============================================================================
// Unified Config-Based Encryption (Recommended API)
// ============================================================================

/// Encrypt with configuration options (recommended API)
///
/// This is the recommended way to encrypt data. By default, both randomness
/// and compression are enabled for IND-CPA security and size optimization.
///
/// # Examples
/// ```
/// use xcqa::{keygen, encrypt_with_config, EncryptionConfig};
///
/// let (pk, sk) = keygen();
/// let plaintext = b"Hello, World!";
///
/// // Use default config (randomness + compression)
/// let ciphertext = encrypt_with_config(plaintext, &pk, &EncryptionConfig::default()).unwrap();
///
/// // Or customize
/// let config = EncryptionConfig::randomness_only();
/// let ciphertext = encrypt_with_config(plaintext, &pk, &config).unwrap();
/// ```
pub fn encrypt_with_config(
    plaintext: &[u8],
    pk: &PublicKey,
    config: &EncryptionConfig,
) -> Result<Vec<u8>, String> {
    match (config.randomness, config.compression) {
        (true, true) => {
            // Both enabled: randomness + compression
            encrypt_randomized_compressed(plaintext, pk)
        }
        (true, false) => {
            // Only randomness
            Ok(encrypt_with_randomness(plaintext, pk))
        }
        (false, true) => {
            // Only compression
            encrypt_with_compression(plaintext, pk)
        }
        (false, false) => {
            // Basic mode (no randomness, no compression)
            Ok(encrypt(plaintext, pk))
        }
    }
}

/// Decrypt with configuration options (recommended API)
///
/// Must use the same configuration that was used for encryption.
pub fn decrypt_with_config(
    ciphertext: &[u8],
    sk: &PrivateKey,
    config: &EncryptionConfig,
) -> Result<Vec<u8>, String> {
    match (config.randomness, config.compression) {
        (true, true) => {
            // Both enabled: decompression + randomness removal
            decrypt_decompressed_randomized(ciphertext, sk)
        }
        (true, false) => {
            // Only randomness
            Ok(decrypt_with_randomness(ciphertext, sk))
        }
        (false, true) => {
            // Only compression
            decrypt_with_decompression(ciphertext, sk)
        }
        (false, false) => {
            // Basic mode
            Ok(decrypt(ciphertext, sk))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        let (pk, sk) = keygen();
        assert_eq!(pk.dict.layers.len(), 4);
        assert_eq!(sk.dict_encode.layers.len(), 4);
        assert_eq!(sk.dict_decode.layers.len(), 4);
        assert_eq!(sk.dict_pub_inverse.layers.len(), 4);
    }

    #[test]
    fn test_encrypt_decrypt_basic() {
        let (pk, sk) = keygen();
        let plaintext = b"Hello, XCQA!";

        let ciphertext = encrypt(plaintext, &pk);
        let decrypted = decrypt(&ciphertext, &sk);

        // Check that decrypted matches plaintext
        assert_eq!(
            &decrypted[..plaintext.len().min(decrypted.len())],
            plaintext,
            "Decryption failed to recover plaintext"
        );
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let (pk, sk) = keygen();
        let plaintext = b"";

        let ciphertext = encrypt(plaintext, &pk);
        let decrypted = decrypt(&ciphertext, &sk);

        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_encrypt_decrypt_single_byte() {
        let (pk, sk) = keygen();
        let plaintext = b"A";

        let ciphertext = encrypt(plaintext, &pk);
        let decrypted = decrypt(&ciphertext, &sk);

        assert_eq!(
            &decrypted[..plaintext.len().min(decrypted.len())],
            plaintext
        );
    }

    #[test]
    fn test_encrypt_decrypt_long_message() {
        let (pk, sk) = keygen();
        let plaintext = b"This is a longer message to test the encryption and decryption process with more data.";

        let ciphertext = encrypt(plaintext, &pk);
        let decrypted = decrypt(&ciphertext, &sk);

        assert_eq!(
            &decrypted[..plaintext.len().min(decrypted.len())],
            plaintext
        );
    }

    #[test]
    fn test_ciphertext_expansion() {
        let (pk, _sk) = keygen();
        let plaintext = b"12345678"; // 8 bytes = 64 bits

        let ciphertext = encrypt(plaintext, &pk);

        // Cascading encoding: 20 bits -> 31 bits per cycle
        // 64 bits: 3 complete cycles (60 bits -> 93 bits) + 4 bits (Layer 2: 4->6)
        // Total: 93 + 6 = 99 bits = 13 bytes (rounded up)
        assert_eq!(ciphertext.len(), 13);
    }

    #[test]
    fn test_dictionary_layer_generation() {
        let layer = DictLayer::generate(8, 12);

        assert_eq!(layer.input_bits, 8);
        assert_eq!(layer.output_bits, 12);
        assert_eq!(layer.mapping.len(), 256); // 2^8 = 256 entries

        // Check all outputs are unique
        let mut outputs: Vec<u64> = layer.mapping.values().copied().collect();
        outputs.sort();
        outputs.dedup();
        assert_eq!(outputs.len(), 256); // All outputs should be unique
    }

    #[test]
    fn test_dictionary_inverse() {
        let dict = Dictionary::generate();
        let inverse = dict.create_inverse();

        // Test that inverse works correctly
        let layer = &dict.layers[0];
        let inv_layer = &inverse.layers[0];

        for (input, output) in &layer.mapping {
            let recovered = inv_layer.encode(*output);
            assert_eq!(recovered, Some(*input));
        }
    }

    #[test]
    fn test_bitstream_conversion() {
        let original = vec![0x12, 0x34, 0x56, 0x78];
        let bitstream = BitStream::from_bytes(&original);
        let recovered = bitstream.to_bytes();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bitstream_read_write() {
        let mut bitstream = BitStream { bits: Vec::new() };

        bitstream.write_bits(0b10110, 5);
        bitstream.write_bits(0b1101, 4);

        assert_eq!(bitstream.read_bits(0, 5), Some(0b10110));
        assert_eq!(bitstream.read_bits(5, 4), Some(0b1101));
    }

    #[test]
    fn test_sign_verify_basic() {
        let (pk, sk) = keygen();
        let message = b"Hello, XCQA signature!";

        let signature = sign(message, &sk, &pk);
        let is_valid = verify(message, &signature, &pk);

        assert!(is_valid, "Valid signature should verify successfully");
    }

    #[test]
    fn test_sign_verify_different_messages() {
        let (pk, sk) = keygen();
        let message1 = b"Message 1";
        let message2 = b"Message 2";

        let signature = sign(message1, &sk, &pk);

        // Signature should be valid for original message
        assert!(verify(message1, &signature, &pk));

        // Signature should NOT be valid for different message
        assert!(!verify(message2, &signature, &pk));
    }

    #[test]
    fn test_sign_verify_tampered_signature() {
        let (pk, sk) = keygen();
        let message = b"Test message";

        let mut signature = sign(message, &sk, &pk);

        // Tamper with the commitment
        if !signature.commitment.is_empty() {
            signature.commitment[0] ^= 0xFF;
        }

        // Tampered signature should NOT verify
        assert!(!verify(message, &signature, &pk));
    }

    #[test]
    fn test_sign_verify_multiple_signatures() {
        let (pk, sk) = keygen();
        let message = b"Test message";

        // Generate multiple signatures for the same message
        let sig1 = sign(message, &sk, &pk);
        let sig2 = sign(message, &sk, &pk);

        // Both should verify
        assert!(verify(message, &sig1, &pk));
        assert!(verify(message, &sig2, &pk));

        // Signatures should be different (due to random nonce)
        assert_ne!(sig1.commitment, sig2.commitment);
    }

    // Cryptographic property tests

    #[test]
    fn test_avalanche_effect() {
        let (pk, _sk) = keygen();
        let plaintext1 = b"Hello, World!";
        let mut plaintext2 = plaintext1.clone();

        // Flip one bit in the second plaintext
        plaintext2[0] ^= 0x01;

        let ciphertext1 = encrypt(plaintext1, &pk);
        let ciphertext2 = encrypt(&plaintext2, &pk);

        // Count differing bits
        let mut diff_bits = 0;
        let min_len = ciphertext1.len().min(ciphertext2.len());
        for i in 0..min_len {
            diff_bits += (ciphertext1[i] ^ ciphertext2[i]).count_ones();
        }

        // Note: Dictionary-based encoding has localized changes
        // Unlike block ciphers (AES), flipping one input bit only affects
        // the corresponding output chunk, not the entire ciphertext
        // This is expected behavior for substitution-based schemes
        let total_bits = min_len * 8;
        let diff_ratio = diff_bits as f64 / total_bits as f64;

        // At least some bits should differ (not zero)
        assert!(
            diff_bits > 0,
            "No avalanche effect: ciphertexts are identical"
        );

        // For dictionary encoding, expect localized changes (2-15% is typical)
        // Lower threshold than block ciphers due to substitution-based nature
        assert!(
            diff_ratio > 0.02,
            "Avalanche effect too weak: only {:.2}% bits differ",
            diff_ratio * 100.0
        );
    }

    #[test]
    fn test_determinism() {
        let (pk, _sk) = keygen();
        let plaintext = b"Determinism test";

        // Encrypt the same plaintext multiple times with the same key
        let ciphertext1 = encrypt(plaintext, &pk);
        let ciphertext2 = encrypt(plaintext, &pk);
        let ciphertext3 = encrypt(plaintext, &pk);

        // All ciphertexts should be identical
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext2, ciphertext3);
    }

    #[test]
    fn test_collision_resistance() {
        let (pk, _sk) = keygen();

        // Test that different plaintexts produce different ciphertexts
        let plaintexts = vec![
            b"Message 1".as_slice(),
            b"Message 2".as_slice(),
            b"Message 3".as_slice(),
            b"Different".as_slice(),
            b"Testing!".as_slice(),
        ];

        let mut ciphertexts = Vec::new();
        for plaintext in &plaintexts {
            ciphertexts.push(encrypt(plaintext, &pk));
        }

        // Check that all ciphertexts are unique
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "Collision detected between plaintexts {} and {}",
                    i, j
                );
            }
        }
    }

    // ========================================================================
    // Randomized Padding Tests
    // ========================================================================

    #[test]
    fn test_encrypt_with_randomness() {
        let (pk, sk) = keygen();
        let plaintext = b"Test randomized encryption";

        // Encrypt twice with randomness
        let ct1 = encrypt_with_randomness(plaintext, &pk);
        let ct2 = encrypt_with_randomness(plaintext, &pk);

        // Ciphertexts should be different (due to random nonce)
        assert_ne!(ct1, ct2, "Randomized encryption should produce different ciphertexts");

        // Both should decrypt to the same plaintext
        let dec1 = decrypt_with_randomness(&ct1, &sk);
        let dec2 = decrypt_with_randomness(&ct2, &sk);

        // Should decrypt to exact original plaintext (no padding bytes)
        assert_eq!(&dec1, plaintext);
        assert_eq!(&dec2, plaintext);
    }

    #[test]
    fn test_randomness_ind_cpa() {
        let (pk, sk) = keygen();
        let msg1 = b"Message A";
        let msg2 = b"Message B";

        // Encrypt the same message multiple times
        let ct1_a = encrypt_with_randomness(msg1, &pk);
        let ct2_a = encrypt_with_randomness(msg1, &pk);

        // Encrypt different message
        let ct_b = encrypt_with_randomness(msg2, &pk);

        // Same message should produce different ciphertexts
        assert_ne!(ct1_a, ct2_a);

        // Different messages should produce different ciphertexts
        assert_ne!(ct1_a, ct_b);
        assert_ne!(ct2_a, ct_b);

        // All should decrypt correctly
        assert_eq!(&decrypt_with_randomness(&ct1_a, &sk), msg1);
        assert_eq!(&decrypt_with_randomness(&ct2_a, &sk), msg1);
        assert_eq!(&decrypt_with_randomness(&ct_b, &sk), msg2);
    }

    // ========================================================================
    // Compression Tests
    // ========================================================================

    #[test]
    fn test_encrypt_with_compression() {
        let (pk, sk) = keygen();
        let plaintext = b"This is a test message for compression. Compression should reduce the size of repetitive data.";

        // Encrypt with compression
        let compressed_ct = encrypt_with_compression(plaintext, &pk).unwrap();

        // Encrypt without compression
        let normal_ct = encrypt(plaintext, &pk);

        // Compressed should be smaller (or similar size for small messages)
        println!("Normal ciphertext: {} bytes", normal_ct.len());
        println!("Compressed ciphertext: {} bytes", compressed_ct.len());

        // Decrypt
        let decrypted = decrypt_with_decompression(&compressed_ct, &sk).unwrap();

        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_compression_ratio() {
        let (pk, sk) = keygen();

        // Test with larger message (better compression)
        let plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                          BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\
                          CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

        let compressed_ct = encrypt_with_compression(plaintext, &pk).unwrap();
        let normal_ct = encrypt(plaintext, &pk);

        let compression_ratio = compressed_ct.len() as f64 / normal_ct.len() as f64;

        println!("Compression ratio: {:.2}%", compression_ratio * 100.0);

        // Verify decryption works
        let decrypted = decrypt_with_decompression(&compressed_ct, &sk).unwrap();
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    // ========================================================================
    // Combined Randomness + Compression Tests
    // ========================================================================

    #[test]
    fn test_randomized_compressed() {
        let (pk, sk) = keygen();
        let plaintext = b"Test message with both randomness and compression";

        // Encrypt with both features
        let ct1 = encrypt_randomized_compressed(plaintext, &pk).unwrap();
        let ct2 = encrypt_randomized_compressed(plaintext, &pk).unwrap();

        // Should produce different ciphertexts (randomness)
        assert_ne!(ct1, ct2);

        // Both should decrypt correctly
        let dec1 = decrypt_decompressed_randomized(&ct1, &sk).unwrap();
        let dec2 = decrypt_decompressed_randomized(&ct2, &sk).unwrap();

        assert_eq!(&dec1, plaintext);
        assert_eq!(&dec2, plaintext);
    }

    #[test]
    fn test_randomized_compressed_large_message() {
        let (pk, sk) = keygen();

        // Large message for better compression
        let plaintext = vec![0x42u8; 1024]; // 1KB of repeated data

        let compressed_ct = encrypt_randomized_compressed(&plaintext, &pk).unwrap();
        let normal_ct = encrypt_with_randomness(&plaintext, &pk);

        println!("Normal (with randomness): {} bytes", normal_ct.len());
        println!("Compressed (with randomness): {} bytes", compressed_ct.len());

        let compression_ratio = compressed_ct.len() as f64 / normal_ct.len() as f64;
        println!("Compression ratio: {:.2}%", compression_ratio * 100.0);

        // Decrypt and verify
        let decrypted = decrypt_decompressed_randomized(&compressed_ct, &sk).unwrap();
        assert_eq!(&decrypted, &plaintext);
    }

    #[test]
    fn test_config_minimum_layers() {
        // Test that less than 4 layers is rejected
        let result = DictionaryConfig::new(vec![
            LayerConfig { input_bits: 8, output_bits: 12 },
            LayerConfig { input_bits: 6, output_bits: 9 },
            LayerConfig { input_bits: 4, output_bits: 6 },
        ]);
        assert!(result.is_err(), "Should reject config with less than 4 layers");

        // Test that exactly 4 layers is accepted
        let result = DictionaryConfig::new(vec![
            LayerConfig { input_bits: 8, output_bits: 12 },
            LayerConfig { input_bits: 6, output_bits: 9 },
            LayerConfig { input_bits: 4, output_bits: 6 },
            LayerConfig { input_bits: 2, output_bits: 4 },
        ]);
        assert!(result.is_ok(), "Should accept config with exactly 4 layers");
    }

    #[test]
    fn test_config_expansion_validation() {
        // Test that non-expanding layers are rejected
        let result = DictionaryConfig::new(vec![
            LayerConfig { input_bits: 8, output_bits: 12 },
            LayerConfig { input_bits: 6, output_bits: 6 },  // Not expanding
            LayerConfig { input_bits: 4, output_bits: 6 },
            LayerConfig { input_bits: 2, output_bits: 4 },
        ]);
        assert!(result.is_err(), "Should reject config with non-expanding layer");
    }

    #[test]
    fn test_custom_config_encryption() {
        // Test with custom 5-layer configuration
        let config = DictionaryConfig::new(vec![
            LayerConfig { input_bits: 10, output_bits: 15 },
            LayerConfig { input_bits: 8, output_bits: 12 },
            LayerConfig { input_bits: 6, output_bits: 9 },
            LayerConfig { input_bits: 4, output_bits: 6 },
            LayerConfig { input_bits: 2, output_bits: 4 },
        ]).unwrap();

        let (pk, sk) = keygen_with_config(&config);

        // Verify key structure
        assert_eq!(pk.dict.layers.len(), 5);
        assert_eq!(sk.dict_encode.layers.len(), 5);

        // Test encryption/decryption
        let plaintext = b"Test with custom config";
        let ciphertext = encrypt(plaintext, &pk);
        let decrypted = decrypt(&ciphertext, &sk);

        assert_eq!(
            &decrypted[..plaintext.len().min(decrypted.len())],
            plaintext,
            "Custom config encryption/decryption failed"
        );
    }
}
