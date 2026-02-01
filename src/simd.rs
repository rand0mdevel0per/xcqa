/// SIMD-optimized operations for XCQA
///
/// This module provides SIMD-accelerated implementations of bit operations
/// used in the BitStream structure for improved encryption/decryption performance.

// Only import SIMD intrinsics when actually using them
// #[cfg(target_arch = "x86_64")]
// use std::arch::x86_64::*;

/// Check if AVX2 is available on the current CPU
#[inline]
pub fn is_avx2_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Convert bytes to bit vector using SIMD when available
///
/// # Arguments
/// * `bytes` - Input byte slice
///
/// # Returns
/// Vector of booleans representing individual bits
pub fn bytes_to_bits_simd(bytes: &[u8]) -> Vec<bool> {
    if is_avx2_available() && bytes.len() >= 32 {
        unsafe { bytes_to_bits_avx2(bytes) }
    } else {
        bytes_to_bits_scalar(bytes)
    }
}

/// Scalar fallback for bytes to bits conversion
#[inline]
fn bytes_to_bits_scalar(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// AVX2 implementation for bytes to bits conversion
/// Note: Currently uses scalar processing as AVX2 doesn't have direct bit expansion
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn bytes_to_bits_avx2(bytes: &[u8]) -> Vec<bool> {
    // For now, use optimized scalar implementation
    // TODO: Implement true AVX2 bit expansion using lookup tables
    bytes_to_bits_scalar(bytes)
}

#[cfg(not(target_arch = "x86_64"))]
fn bytes_to_bits_avx2(bytes: &[u8]) -> Vec<bool> {
    bytes_to_bits_scalar(bytes)
}

/// Convert bit vector to bytes using SIMD when available
///
/// # Arguments
/// * `bits` - Input bit vector
///
/// # Returns
/// Vector of bytes
pub fn bits_to_bytes_simd(bits: &[bool]) -> Vec<u8> {
    if is_avx2_available() && bits.len() >= 256 {
        unsafe { bits_to_bytes_avx2(bits) }
    } else {
        bits_to_bytes_scalar(bits)
    }
}

/// Scalar fallback for bits to bytes conversion
#[inline]
fn bits_to_bytes_scalar(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
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

/// AVX2 implementation for bits to bytes conversion
/// Note: Currently uses scalar processing as AVX2 doesn't have efficient bit packing
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn bits_to_bytes_avx2(bits: &[bool]) -> Vec<u8> {
    // For now, use optimized scalar implementation
    // TODO: Implement true AVX2 bit packing using lookup tables
    bits_to_bytes_scalar(bits)
}

#[cfg(not(target_arch = "x86_64"))]
fn bits_to_bytes_avx2(bits: &[bool]) -> Vec<u8> {
    bits_to_bytes_scalar(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_bits_roundtrip() {
        let original = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let bits = bytes_to_bits_simd(&original);
        let recovered = bits_to_bytes_simd(&bits);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bits_to_bytes_roundtrip() {
        let bits = vec![
            true, false, false, true, false, false, true, false,  // 0x92
            false, false, true, true, false, true, false, false,  // 0x34
        ];
        let bytes = bits_to_bytes_simd(&bits);
        let recovered = bytes_to_bits_simd(&bytes);
        assert_eq!(bits, recovered);
    }
}
