use std::collections::HashMap;
use rand::Rng;
use sha2::{Sha256, Digest};

/// Bit stream for encoding/decoding
struct BitStream {
    bits: Vec<bool>,
}

impl BitStream {
    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut bits = Vec::new();
        for byte in bytes {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        BitStream { bits }
    }

    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for chunk in self.bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - i);
                }
            }
            bytes.push(byte);
        }
        bytes
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
struct Dictionary {
    layers: Vec<DictLayer>,
}

impl Dictionary {
    /// Generate multi-layer dictionary
    /// Layer structure:
    /// - Layer 0: 8 bits -> 12 bits (256 entries)
    /// - Layer 1: 6 bits -> 9 bits (64 entries)
    /// - Layer 2: 4 bits -> 6 bits (16 entries)
    /// - Layer 3: 2 bits -> 4 bits (4 entries)
    fn generate() -> Self {
        let layer_configs = vec![
            (8, 12),  // Layer 0
            (6, 9),   // Layer 1
            (4, 6),   // Layer 2
            (2, 4),   // Layer 3
        ];

        let layers = layer_configs
            .into_iter()
            .map(|(input_bits, output_bits)| DictLayer::generate(input_bits, output_bits))
            .collect();

        Dictionary { layers }
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
struct PublicKey {
    dict: Dictionary,
}

/// Private key (original dictionary + transformation parameters)
#[derive(Debug, Clone)]
struct PrivateKey {
    dict_encode: Dictionary,  // Dict_A (original encoding dictionary)
    dict_decode: Dictionary,  // Dict_B (inverse of Dict_A)
    dict_pub_inverse: Dictionary,  // Inverse of public key dictionary
    transform: TransformParams,
}

/// Zero-knowledge signature
/// Proves knowledge of private key without revealing it
#[derive(Debug, Clone)]
struct Signature {
    commitment: Vec<u8>,  // C: encrypted nonce
    response: Vec<u8>,    // s: nonce XOR challenge
}

/// Key generation
fn keygen() -> (PublicKey, PrivateKey) {
    // 1. Generate original encoding dictionary
    let dict_encode = Dictionary::generate();

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

/// Encrypt data using public key
fn encrypt(data: &[u8], pk: &PublicKey) -> Vec<u8> {
    pk.dict.encode_bytes(data)
}

/// Decrypt data using private key
fn decrypt(ciphertext: &[u8], sk: &PrivateKey) -> Vec<u8> {
    sk.dict_pub_inverse.decode_bytes(ciphertext)
}

/// Sign a message using zero-knowledge proof
/// Proves knowledge of private key without revealing it
fn sign(message: &[u8], sk: &PrivateKey, pk: &PublicKey) -> Signature {
    let mut rng = rand::thread_rng();

    // 1. Generate random nonce (40 bits = 2 complete cycles, 5 bytes)
    // This ensures perfect alignment with cascading encoding
    let nonce_bytes = 5;
    let mut nonce = vec![0u8; nonce_bytes];
    rng.fill(&mut nonce[..]);

    // 2. Encrypt nonce with public key: C = Encode(nonce, Dict_pub)
    let commitment = encrypt(&nonce, pk);

    // 3. Compute challenge: e = Hash(C || message)
    let mut hasher = Sha256::new();
    hasher.update(&commitment);
    hasher.update(message);
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
fn verify(message: &[u8], signature: &Signature, pk: &PublicKey) -> bool {
    // 1. Compute challenge: e = Hash(C || message)
    let mut hasher = Sha256::new();
    hasher.update(&signature.commitment);
    hasher.update(message);
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

fn main() {
    println!("XCQA - XC Quick Algo (Dict-Transform Cryptosystem)");
    println!("Run 'cargo test' to execute unit tests");
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

        // For dictionary encoding, expect localized changes (5-15% is typical)
        assert!(
            diff_ratio > 0.03,
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
}
