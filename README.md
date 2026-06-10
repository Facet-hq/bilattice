# bilattice

Hybrid post-quantum crypto primitives. `bi` (two algorithms per operation) + `lattice` (ML-KEM/ML-DSA are lattice-based).

## Algorithms

| Operation | Classical | Post-quantum |
|-----------|-----------|--------------|
| KEM | X25519 | ML-KEM-768 |
| Sign | Ed25519 | ML-DSA-65 |

## Design notes (for the real README)

### KEM combiner — aligned with X-Wing

Combiner follows [X-Wing](https://doi.org/10.62056/a3qj89n4e) (Barbosa et al., IACR CiC 2024).
IETF draft: `draft-connolly-cfrg-xwing-kem`.

Same algorithm pair: ML-KEM-768 + X25519.

**Input order:**
```
ss_mlkem || ss_x25519 || ct_x25519_eph || pk_x25519_recipient
```

**Difference from X-Wing:** X-Wing uses bare SHA3-256. bilattice uses HKDF-SHA3-256
with domain label `"bilattice-hybrid-v1"` for context binding and future versioning.

X-Wing omits the ML-KEM ciphertext from the combiner (justified by the FO transform in ML-KEM).
bilattice may include it as a conservative option — TBD.

### Signatures

Hybrid: ML-DSA-65 + Ed25519 in parallel. `verify` requires **both** to pass (AND, not OR).
Reference: NIST FIPS 205 (ML-DSA).
