/*
 * Random byte generation adapter for Dogecoin Core.
 * Wraps system RNG for use by the SPHINCS+ PQC implementation.
 */

#ifndef PQCLEAN_RANDOMBYTES_H
#define PQCLEAN_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Write `n` bytes of cryptographically secure random bytes to `output`.
 * Returns 0 on success.
 */
#define randombytes     PQCLEAN_randombytes
int randombytes(uint8_t *output, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* PQCLEAN_RANDOMBYTES_H */
