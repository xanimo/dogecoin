# Falcon-512 Post-Quantum Cryptography

## Overview

Dogecoin Core includes a Falcon-512 implementation, a lattice-based digital
signature scheme selected by NIST for standardization as part of the
Post-Quantum Cryptography (PQC) project (also known as FN-DSA).

Falcon-512 provides **NIST Security Level 1** (equivalent to AES-128 security),
offering protection against both classical and quantum computing attacks on
digital signatures.

## Parameters

| Parameter | Value |
|-----------|-------|
| Polynomial degree (n) | 512 |
| Log degree (logn) | 9 |
| Modulus (q) | 12289 |
| Public key size | 897 bytes |
| Secret key size | 1281 bytes |
| Max signature size | 752 bytes |
| Nonce size | 40 bytes |
| NIST security level | 1 |

## Architecture

The implementation is based on the **PQClean reference implementation**
(Thomas Pornin, Falcon Project) and consists of the following components:

### Core Modules (`src/crypto/falcon/`)

- **fips202.c/h** — SHAKE256 (Keccak-based XOF) used for hashing
- **fpr.c/h** — Custom floating-point arithmetic using integer operations
  (IEEE-754 binary64 format, constant-time)
- **fft.c** — Fast Fourier Transform over complex numbers for lattice operations
- **codec.c** — Encoding/decoding of keys and signatures (modq, trim, compressed)
- **common.c** — Hash-to-point and signature norm checking
- **keygen.c** — NTRU key generation with polynomial constraint solving
- **sign.c** — Signature generation using Fast Fourier Sampling
- **vrfy.c** — Signature verification with NTT-based polynomial arithmetic
- **rng.c** — ChaCha20-based PRNG for internal randomness expansion
- **pqclean.c** — Top-level API wrapper (keygen, sign, verify)
- **randombytes.c** — System RNG adapter (getrandom/urandom)
- **inner.h** — Internal declarations and data structures
- **api.h** — PQClean-compatible API definitions

### Public Interface (`src/crypto/falcon.h`)

C++ wrapper providing:
- `CFalcon512KeyPair` — Key pair container with generation, signing, export/import
- `CFalcon512Verify()` — Standalone signature verification
- `CFalcon512Open()` — Signed message verification and extraction

## Algorithm Description

### Key Generation
1. Generate small polynomials f, g using discrete Gaussian sampling
2. Solve the NTRU equation: fG − gF = q (mod x^n + 1)
3. Public key: h = g/f mod q (encoded as NTT coefficients)
4. Private key: (f, g, F) encoded with trim encoding

### Signing
1. Hash nonce||message to polynomial c using SHAKE256
2. Use Fast Fourier Sampling to find short vector (s1, s2) such that
   s1 + s2·h ≡ c (mod q)
3. Signature: nonce || compressed(s2)

### Verification
1. Decode signature to recover s2
2. Hash nonce||message to recover c
3. Compute s1 = c − s2·h mod q
4. Check ‖(s1, s2)‖² ≤ bound

## NIST KAT Validation

Reference checksums for NIST Known Answer Tests:

```
nistkat-sha256:     da27fe8a462de7307ddf1f9b00072a457d9c5b14e838c148fbe2662094b9a2ca
testvectors-sha256: e6d6d5b0ee34ccdeabfc9d7e5487adafedec13b425f2fe991a1fa6efff3be68a
```

These checksums correspond to the PQClean v20211101 reference implementation.

## Usage Example

```cpp
#include "crypto/falcon.h"

// Generate key pair
CFalcon512KeyPair kp;
if (!kp.Generate()) { /* error */ }

// Sign a message
const unsigned char msg[] = "Hello, post-quantum world!";
std::vector<unsigned char> sig;
if (!kp.Sign(msg, sizeof(msg) - 1, sig)) { /* error */ }

// Verify signature
std::vector<unsigned char> pk = kp.GetPubKey();
if (!CFalcon512Verify(pk, msg, sizeof(msg) - 1, sig)) {
    // Invalid signature
}
```

## License

The Falcon-512 implementation is derived from the PQClean project and is
distributed under the MIT License. See `src/crypto/falcon/LICENSE` for details.

Original authors: Thomas Pornin (thomas.pornin@nccgroup.com), Falcon Project.
