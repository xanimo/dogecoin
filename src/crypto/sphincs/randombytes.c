/*
 * Random byte generation for SPHINCS+ PQC implementation.
 * Uses getrandom() on Linux, CryptGenRandom on Windows,
 * arc4random_buf on BSD/macOS, /dev/urandom as fallback.
 *
 * This provides a self-contained random byte source suitable
 * for cryptographic key generation and nonce generation.
 */

#include "randombytes.h"

#include <string.h>

#if defined(_WIN32)
/* Windows implementation using CryptGenRandom */
#include <windows.h>
#include <wincrypt.h>

int randombytes(uint8_t *output, size_t n) {
    HCRYPTPROV ctx;
    BOOL tmp;

    tmp = CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT);
    if (tmp == FALSE) {
        return -1;
    }

    tmp = CryptGenRandom(ctx, (DWORD)n, output);
    if (tmp == FALSE) {
        CryptReleaseContext(ctx, 0);
        return -1;
    }

    CryptReleaseContext(ctx, 0);
    return 0;
}

#elif defined(__linux__)
/* Linux implementation using getrandom() syscall */
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#if defined(SYS_getrandom)
static int _randombytes_linux(uint8_t *output, size_t n) {
    long ret;
    size_t total = 0;

    while (total < n) {
        ret = syscall(SYS_getrandom, output + total, n - total, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total += (size_t)ret;
    }
    return 0;
}
#endif

/* Fallback: read from /dev/urandom */
#include <fcntl.h>

static int _randombytes_urandom(uint8_t *output, size_t n) {
    int fd;
    ssize_t ret;
    size_t total = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    while (total < n) {
        ret = read(fd, output + total, n - total);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        total += (size_t)ret;
    }

    close(fd);
    return 0;
}

int randombytes(uint8_t *output, size_t n) {
#if defined(SYS_getrandom)
    if (_randombytes_linux(output, n) == 0) {
        return 0;
    }
#endif
    return _randombytes_urandom(output, n);
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
/* BSD/macOS implementation using arc4random_buf */
#include <stdlib.h>

int randombytes(uint8_t *output, size_t n) {
    arc4random_buf(output, n);
    return 0;
}

#else
/* Generic POSIX fallback using /dev/urandom */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int randombytes(uint8_t *output, size_t n) {
    int fd;
    ssize_t ret;
    size_t total = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    while (total < n) {
        ret = read(fd, output + total, n - total);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        total += (size_t)ret;
    }

    close(fd);
    return 0;
}

#endif
