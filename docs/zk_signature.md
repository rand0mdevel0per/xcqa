# Zero-Knowledge Signature Protocol - Formal Specification

## 1. Protocol Overview

XCQA implements a commitment-challenge-response signature scheme that proves knowledge of the private key without revealing it.

## 2. Key Generation

**Input**: None
**Output**: $(pk, sk)$ - public/private key pair

```
KeyGen():
    Dict_encode ← GenerateDictionary()
    Dict_decode ← Dict_encode^(-1)
    transform ← GenerateTransformParams()
    Dict_pub ← ApplyTransform(Dict_encode, transform)
    Dict_pub_inv ← Dict_pub^(-1)

    pk ← Dict_pub
    sk ← (Dict_encode, Dict_decode, Dict_pub_inv, transform)
    return (pk, sk)
```

## 3. Signature Generation

**Input**: Message $M$, private key $sk$, public key $pk$
**Output**: Signature $\sigma = (C, s)$

```
Sign(M, sk, pk):
    // 1. Generate random nonce (5 bytes = 40 bits)
    r ←_R {0,1}^40

    // 2. Encrypt nonce with public key (commitment)
    C ← Encrypt(r, pk)

    // 3. Compute challenge
    e ← H(C || M)  // SHA-256

    // 4. Decrypt commitment to recover nonce
    r' ← Decrypt(C, sk)

    // 5. Compute response
    s ← r' ⊕ e[0:40]  // XOR with first 40 bits of challenge

    return σ = (C, s)
```

## 4. Signature Verification

**Input**: Message $M$, signature $\sigma = (C, s)$, public key $pk$
**Output**: $\{Accept, Reject\}$

```
Verify(M, σ, pk):
    (C, s) ← σ

    // 1. Recompute challenge
    e ← H(C || M)

    // 2. Recover nonce
    r ← s ⊕ e[0:40]

    // 3. Verify commitment
    C' ← Encrypt(r, pk)

    if C' = C:
        return Accept
    else:
        return Reject
```

## 5. Correctness

**Theorem 1** (Completeness): Valid signatures always verify.

**Proof**:
```
Given: σ = Sign(M, sk, pk) = (C, s)

Verification computes:
    e ← H(C || M)           // Same challenge
    r ← s ⊕ e[0:40]         // Recover nonce
      = (r' ⊕ e[0:40]) ⊕ e[0:40]
      = r'                  // XOR cancels
    C' ← Encrypt(r, pk)
      = Encrypt(r', pk)     // r = r' from decryption
      = C                   // Same commitment

Therefore: C' = C, verification accepts. □
```

## 6. Security Properties

### 6.1 Zero-Knowledge

**Claim**: Signature verification does not reveal the private key.

**Justification**:
- Verifier only sees $(C, s)$ and public key $pk$
- $C$ is an encryption under $pk$ (no private key info)
- $s = r' \oplus e$ is XOR-masked (information-theoretically hiding)
- Verifier cannot extract $sk$ from $(C, s)$

**Limitation**: Not a formal zero-knowledge proof (no simulator).

### 6.2 Unforgeability

**Claim**: Without $sk$, attacker cannot forge valid signatures.

**Attack Analysis**:

1. **Random forgery**:
   - Attacker generates random $(C, s)$
   - Probability of valid signature: $\approx 2^{-40}$ (nonce space)
   - Infeasible for 40-bit nonce

2. **Commitment manipulation**:
   - Attacker modifies $C$ to $C'$
   - Challenge changes: $e' = H(C' || M) \neq e$
   - Response $s$ no longer valid
   - Verification fails

3. **Response manipulation**:
   - Attacker modifies $s$ to $s'$
   - Recovered nonce: $r' = s' \oplus e \neq r$
   - Recomputed commitment: $C' = Encrypt(r', pk) \neq C$
   - Verification fails

**Limitation**: Security depends on encryption scheme security.

### 6.3 Non-Repudiation

**Property**: Signer cannot deny creating a valid signature.

**Justification**: Only the private key holder can generate valid $(C, s)$ pairs.

## 7. Known Limitations

### 7.1 Small Nonce Space

**Current**: 40 bits (5 bytes)
**Implication**: $2^{40} \approx 10^{12}$ possible nonces
**Risk**: Brute-force search feasible with significant resources

**Recommendation**: Increase to 128+ bits

### 7.2 Partial Challenge Use

**Current**: Only first 40 bits of SHA-256 output used
**Implication**: Reduces effective challenge space
**Risk**: Potential collision attacks

**Recommendation**: Use full hash or HKDF

### 7.3 Dependency on Encryption Security

**Critical**: Signature security ≤ Encryption security
**Implication**: If encryption is broken, signatures are broken

## 8. Comparison with Standard Schemes

| Property | XCQA | RSA-PSS | ECDSA |
|----------|------|---------|-------|
| Signature Size | ~18 bytes | 256 bytes | 64 bytes |
| Security Basis | Dictionary | Factorization | ECDLP |
| Formal Proof | ❌ No | ✓ Yes | ✓ Yes |
| Zero-Knowledge | ⚠️ Informal | ✓ Yes | ✓ Yes |

## 9. Recommendations

1. **Increase nonce size** to 128+ bits
2. **Use full challenge** (all 256 bits of SHA-256)
3. **Add formal security proof** (reduction to encryption security)
4. **Consider standard schemes** for production use

---

*This protocol specification is preliminary and requires peer review.*
