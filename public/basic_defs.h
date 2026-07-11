#ifndef __BASIC_DEFS_H__

#ifdef linux
#include <stdio.h>
#else
#include <stddef.h>
#endif

#ifdef __OpenBSD__
#include <sys/param.h>
#endif

#define __BASIC_DEFS_H__

typedef unsigned long long uint64;
typedef unsigned int       uint32;
typedef unsigned short     uint16;
typedef unsigned char      uint8;
typedef long long int64;
typedef int       int32;
typedef short     int16;
typedef char      int8;
#ifndef bool
typedef char      bool;
#endif
typedef uint64 mtime_t;

#ifndef __APPLE__
#ifdef __x86_64__
//typedef uint64 uintptr_t;
#else
typedef uint32 uintptr_t;
#endif
#endif

#define FALSE   0
#define TRUE    1

#define likely(_e)       __builtin_expect(!!(_e), 1)
#define unlikely(_e)     __builtin_expect((_e),   0)

#define ROUNDUP(_a, _b)  (((_a) + (_b) - 1) / (_b) * (_b))
#define CEILING(_a, _b)  (((_a) + (_b) - 1) / (_b))
#define ARRAYSIZE(array) (sizeof(array) / sizeof((array)[0]))

#ifndef MAX
#define MAX(_a, _b)      ((_a) > (_b) ? (_a) : (_b))
#define MIN(_a, _b)      ((_a) < (_b) ? (_a) : (_b))
#endif

#define DWORD(hi, lo)   ((((uint32)(hi)) << 16) | ((uint16)(lo)))
#define QWORD(hi, lo)   ((((uint64)(hi)) << 32) | ((uint32)(lo)))

#define STRINGIFY(_x)   #_x
#define STR(_x)         STRINGIFY(_x)

#ifndef offsetof
#define offsetof(_t, _m) ((size_t) &((_t *)0)->_m)
#endif

#define PRINTF_GCC_DECL(_f, _v) __attribute__((__format__(__printf__, _f, _v)))
#define NORETURN                __attribute__((noreturn))

/*
 * Compile-time assertion. Previously a no-op on GCC/clang; use C11's
 * _Static_assert so the checks are actually enforced by the build.
 */
#define ASSERT_ON_COMPILE(_x)     _Static_assert((_x), #_x)

/*
 *---------------------------------------------------------------------------
 *
 * minimum --
 *
 *      Like the macro MIN except that a & b are only evaluated once.
 *
 *---------------------------------------------------------------------------
 */

static inline uint32
minimum(uint32 a, uint32 b)
{
   return MIN(a, b);
}


/*
 *---------------------------------------------------------------------------
 *
 * maximum --
 *
 *      Like the macro MAX except that a & b are only evaluated once.
 *
 *---------------------------------------------------------------------------
 */

static inline uint32
maximum(uint32 a, uint32 b)
{
   return MAX(a, b);
}

#endif
