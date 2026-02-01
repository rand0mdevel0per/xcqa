# XCQA Formal Documentation

This directory contains formal mathematical proofs and analysis for the XCQA cryptosystem.

## Contents

1. **[Dictionary Encoding](dictionary_encoding.md)** - Mathematical formalization of the multi-layer dictionary encoding scheme
2. **[Zero-Knowledge Signature](zk_signature.md)** - Formal protocol specification and security proofs
3. **[Security Analysis](security_analysis.md)** - Threat model and security properties
4. **[Cryptographic Properties](crypto_properties.md)** - Avalanche effect, collision resistance, and other properties

## Notation

Throughout these documents, we use the following notation:

- $\mathbb{Z}_n$ - Integers modulo n
- $\{0,1\}^n$ - Binary strings of length n
- $H: \{0,1\}^* \to \{0,1\}^{256}$ - SHA-256 hash function
- $\oplus$ - XOR operation
- $||$ - Concatenation
- $\leftarrow_R$ - Random sampling

## Status

⚠️ **Experimental Research** - These proofs are preliminary and have not been peer-reviewed.
