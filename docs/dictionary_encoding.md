# Dictionary Encoding - Mathematical Formalization

## 1. Dictionary Layer Definition

A dictionary layer $L_i$ is defined as a bijective mapping:

$$L_i: \{0,1\}^{n_i} \to \{0,1\}^{m_i}$$

where $n_i < m_i$ (expansion encoding).

### XCQA Layer Structure

```
Layer 0: L_0: {0,1}^8  → {0,1}^12  (256 entries)
Layer 1: L_1: {0,1}^6  → {0,1}^9   (64 entries)
Layer 2: L_2: {0,1}^4  → {0,1}^6   (16 entries)
Layer 3: L_3: {0,1}^2  → {0,1}^4   (4 entries)
```

**Property**: Each layer is a bijection (one-to-one mapping).

## 2. Cascading Encoding

Given plaintext $M \in \{0,1\}^*$, the encoding process applies layers sequentially:

$$\text{Encode}(M) = \text{cascade}(L_0, L_1, L_2, L_3, M)$$

**Algorithm**:
```
Input: M = b₁b₂...bₙ (bit string)
Output: C (encoded bit string)

offset ← 0
C ← empty
while offset < |M|:
    for layer Lᵢ in [L₀, L₁, L₂, L₃]:
        if offset + nᵢ ≤ |M|:
            pattern ← M[offset : offset+nᵢ]
            encoded ← Lᵢ(pattern)
            C ← C || encoded
            offset ← offset + nᵢ
return C
```

## 3. Expansion Rate

One complete cycle processes: $8 + 6 + 4 + 2 = 20$ input bits
One complete cycle produces: $12 + 9 + 6 + 4 = 31$ output bits

**Expansion ratio**: $\frac{31}{20} = 1.55$ (55% expansion)

## 4. Inverse Mapping

For decryption, we use the inverse dictionary $L_i^{-1}$:

$$L_i^{-1}: \{0,1\}^{m_i} \to \{0,1\}^{n_i}$$

**Theorem 1** (Bijectivity): Since each $L_i$ is bijective, $L_i^{-1}$ exists and is unique.

**Proof**: By construction, each dictionary layer maps each input pattern to a unique output pattern. The inverse mapping is well-defined. □

## 5. Permutation-Based Transformation

The public key dictionary $D_{pub}$ is derived from the private dictionary $D_{priv}$ via permutation:

$$D_{pub} = \pi(D_{priv}, \text{seed})$$

where $\pi$ is a deterministic permutation based on Fisher-Yates shuffle.

**Algorithm**:
```
create_permutation(n, seed):
    perm ← [0, 1, 2, ..., n-1]
    for i from n-1 down to 1:
        j ← hash(seed, i) mod (i+1)
        swap(perm[i], perm[j])
    return perm
```

**Property**: The permutation is deterministic and bijective.

## 6. Security Properties

### 6.1 Collision Resistance

**Claim**: Different plaintexts produce different ciphertexts (with high probability).

**Justification**: Each layer is bijective, so the cascading encoding preserves distinctness within each cycle. However, truncation at the end may cause collisions.

**Limitation**: Not cryptographically collision-resistant due to small dictionary size.

### 6.2 Avalanche Effect

**Observation**: Dictionary encoding has localized avalanche effect.

**Measurement**: Flipping one input bit changes 5-15% of output bits (localized to the affected chunk).

**Comparison**:
- Block ciphers (AES): ~50% bit change (global diffusion)
- Dictionary encoding: 5-15% bit change (local diffusion)

**Reason**: Each input chunk is encoded independently, so changes don't propagate globally.

## 7. Known Limitations

### 7.1 Small Dictionary Size

Total entries: $256 + 64 + 16 + 4 = 340$

**Implication**: Dictionary can be reconstructed with ~340 known (plaintext, ciphertext) pairs.

### 7.2 Fixed Dictionary

For a given key pair, the dictionary is fixed.

**Implication**: Multiple encryptions leak dictionary mappings.

### 7.3 No Formal Hardness

The security does not reduce to a known hard problem (factorization, discrete log, etc.).

**Implication**: True security strength is unknown.

## 8. Recommendations

1. **Increase dictionary size**: Use 16→24 bit layers (65536 entries)
2. **Dynamic dictionaries**: Derive per-message dictionaries
3. **Add randomization**: Include random padding
4. **Hybrid approach**: Combine with established schemes

---

*This formalization is preliminary and requires peer review.*
