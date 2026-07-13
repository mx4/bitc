#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdnoreturn.h>

#define __BASIC_DEFS_H__

typedef uint64_t  uint64;
typedef uint32_t  uint32;
typedef uint16_t  uint16;
typedef uint8_t   uint8;
typedef int64_t   int64;
typedef int32_t   int32;
typedef int16_t   int16;
typedef int8_t    int8;

typedef uint64 mtime_t;

#ifndef FALSE
#define FALSE   false
#endif
#ifndef TRUE
#define TRUE    true
#endif

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

#define PRINTF_GCC_DECL(_f, _v) __attribute__((__format__(__printf__, _f, _v)))
#define NORETURN                __attribute__((__noreturn__))

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