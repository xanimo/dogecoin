// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <cstdlib>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <time.h>
#include <fcntl.h>
#include <stdarg.h>

#if defined(HAVE_SYS_SELECT_H)
#include <sys/select.h>
#endif

// Prior to GLIBC_2.14, memcpy was aliased to memmove.
extern "C" void* memmove(void* a, const void* b, size_t c);
extern "C" void* memcpy(void* a, const void* b, size_t c)
{
    return memmove(a, b, c);
}

extern "C" void __chk_fail(void) __attribute__((__noreturn__));
extern "C" FDELT_TYPE __fdelt_warn(FDELT_TYPE a)
{
    if (a >= FD_SETSIZE)
        __chk_fail();
    return a / __NFDBITS;
}
extern "C" FDELT_TYPE __fdelt_chk(FDELT_TYPE) __attribute__((weak, alias("__fdelt_warn")));

#if defined(__i386__) || defined(__arm__)

extern "C" int64_t __udivmoddi4(uint64_t u, uint64_t v, uint64_t* rp);

extern "C" int64_t __wrap___divmoddi4(int64_t u, int64_t v, int64_t* rp)
{
    int32_t c1 = 0, c2 = 0;
    int64_t uu = u, vv = v;
    int64_t w;
    int64_t r;

    if (uu < 0) {
        c1 = ~c1, c2 = ~c2, uu = -uu;
    }
    if (vv < 0) {
        c1 = ~c1, vv = -vv;
    }

    w = __udivmoddi4(uu, vv, (uint64_t*)&r);
    if (c1)
        w = -w;
    if (c2)
        r = -r;

    *rp = r;
    return w;
}
#endif

extern "C" float log2f_old(float x);
extern "C" int clock_gettime_old (clockid_t clock_id, struct timespec *tp);
extern "C" double exp_old(double x);
extern "C" double log_old(double x);
extern "C" double pow_old(double x, double y);
extern "C" double fcntl_old(int fd, int cmd, ...);
extern "C" int fcntl64(int fd, int cmd, ...);
#ifdef __i386__
__asm(".symver log2f_old,log2f@GLIBC_2.1");
__asm(".symver clock_gettime_old,clock_gettime@GLIBC_2.2");
__asm(".symver exp_old,exp@GLIBC_2.0");
__asm(".symver log_old,log@GLIBC_2.0");
__asm(".symver pow_old,pow@GLIBC_2.0");
__asm(".symver fcntl_old,fcntl@GLIBC_2.0");
__asm(".symver fcntl64,fcntl@GLIBC_2.0");
#elif defined(__amd64__)
__asm(".symver log2f_old,log2f@GLIBC_2.2.5");
__asm(".symver clock_gettime_old,clock_gettime@GLIBC_2.2.5");
__asm(".symver exp_old,exp@GLIBC_2.2.5");
__asm(".symver log_old,log@GLIBC_2.2.5");
__asm(".symver pow_old,pow@GLIBC_2.2.5");
__asm(".symver fcntl_old,fcntl@GLIBC_2.2.5");
__asm(".symver fcntl64,fcntl64@GLIBC_2.2.5");
#elif defined(__arm__)
__asm(".symver log2f_old,log2f@GLIBC_2.4");
__asm(".symver clock_gettime_old,clock_gettime@GLIBC_2.4");
__asm(".symver exp_old,exp@GLIBC_2.4");
__asm(".symver log_old,log@GLIBC_2.4");
__asm(".symver pow_old,pow@GLIBC_2.4");
__asm(".symver fcntl_old,fcntl@GLIBC_2.4");
__asm(".symver fcntl64,fcntl64@GLIBC_2.4");
#elif defined(__aarch64__)
__asm(".symver log2f_old,log2f@GLIBC_2.17");
__asm(".symver clock_gettime_old,clock_gettime@GLIBC_2.17");
__asm(".symver exp_old,exp@GLIBC_2.17");
__asm(".symver log_old,log@GLIBC_2.17");
__asm(".symver pow_old,pow@GLIBC_2.17");
__asm(".symver fcntl_old,fcntl@GLIBC_2.17");
__asm(".symver fcntl64,fcntl64@GLIBC_2.17");
#endif
extern "C" float __wrap_log2f(float x) {
    return log2f_old(x);
}
extern "C" int __wrap_clock_gettime (clockid_t clock_id, struct timespec *tp) {
    return clock_gettime_old(clock_id, tp);
}
extern "C" double __wrap_exp(double x) {
    return exp_old(x);
}
extern "C" double __wrap_log(double x) {
    return log_old(x);
}
extern "C" double __wrap_pow(double x, double y) {
    return pow_old(x, y);
}
extern "C" double __wrap_fcntl(int fd, int cmd, ...) {
    return fcntl_old(fd, cmd);
}
extern "C" int __wrap_fcntl64(int fd, int cmd, ...)
{
    int result;
    va_list va;
    va_start(va, cmd);

    switch (cmd) {
      //
      // File descriptor flags
      //
      case F_GETFD: goto takes_void;
      case F_SETFD: goto takes_int;

      // File status flags
      //
      case F_GETFL: goto takes_void;
      case F_SETFL: goto takes_int;

      // File byte range locking, not held across fork() or clone()
      //
      case F_SETLK: goto takes_flock_ptr_INCOMPATIBLE;
      case F_SETLKW: goto takes_flock_ptr_INCOMPATIBLE;
      case F_GETLK: goto takes_flock_ptr_INCOMPATIBLE;

      // File byte range locking, held across fork()/clone() -- Not POSIX
      //
      case F_OFD_SETLK: goto takes_flock_ptr_INCOMPATIBLE;
      case F_OFD_SETLKW: goto takes_flock_ptr_INCOMPATIBLE;
      case F_OFD_GETLK: goto takes_flock_ptr_INCOMPATIBLE;

      // Managing I/O availability signals
      //
      case F_GETOWN: goto takes_void;
      case F_SETOWN: goto takes_int;
      case F_GETOWN_EX: goto takes_f_owner_ex_ptr;
      case F_SETOWN_EX: goto takes_f_owner_ex_ptr;
      case F_GETSIG: goto takes_void;
      case F_SETSIG: goto takes_int;

      // Notified when process tries to open or truncate file (Linux 2.4+)
      //
      case F_SETLEASE: goto takes_int;
      case F_GETLEASE: goto takes_void;

      // File and directory change notification
      //
      case F_NOTIFY: goto takes_int;

      // Changing pipe capacity (Linux 2.6.35+)
      //
      case F_SETPIPE_SZ: goto takes_int;
      case F_GETPIPE_SZ: goto takes_void;

      // File sealing (Linux 3.17+)
      //
      case F_ADD_SEALS: goto takes_int;
      case F_GET_SEALS: goto takes_void;

      // File read/write hints (Linux 4.13+)
      //
      case F_GET_RW_HINT: goto takes_uint64_t_ptr;
      case F_SET_RW_HINT: goto takes_uint64_t_ptr;
      case F_GET_FILE_RW_HINT: goto takes_uint64_t_ptr;
      case F_SET_FILE_RW_HINT: goto takes_uint64_t_ptr;

      default:
        fprintf(stderr, "fcntl64 workaround got unknown F_XXX constant");
    }

  takes_void:
    va_end(va);
    return fcntl64(fd, cmd);

  takes_int:
    result = fcntl64(fd, cmd, va_arg(va, int));
    va_end(va);
    return result;

  takes_flock_ptr_INCOMPATIBLE:
    //
    // !!! This is the breaking case: the size of the flock
    // structure changed to accommodate larger files.  If you
    // need this, you'll have to define a compatibility struct
    // with the older glibc and make your own entry point using it,
    // then call fcntl64() with it directly (bear in mind that has
    // been remapped to the old fcntl())
    // 
    fprintf(stderr, "fcntl64 hack can't use glibc flock directly");
    exit(1);

  takes_f_owner_ex_ptr:
    result = fcntl64(fd, cmd, va_arg(va, struct f_owner_ex*));
    va_end(va);
    return result;

  takes_uint64_t_ptr:
    result = fcntl64(fd, cmd, va_arg(va, uint64_t*));
    va_end(va);
    return result;
}
