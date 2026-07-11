#pragma once

#include "basic_defs.h"

/*
 * Built-in atomics support started with gcc 4.1.0.
 *
 * http://gcc.gnu.org/onlinedocs/gcc/Atomic-Builtins.html
 */


typedef struct {
   volatile uint32 value;
} atomic_uint32;


typedef struct {
   volatile uint64 value;
} atomic_uint64  __attribute__((__aligned__(8)));


/*
 *---------------------------------------------------------------------------
 *
 * atomic_read --
 *
 *---------------------------------------------------------------------------
 */

static inline uint32
atomic_read(const atomic_uint32 *var)
{
   return var->value;
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_write --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic_write(atomic_uint32 *var,
             uint32 val)
{
   var->value = val;
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_sub --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic_sub(atomic_uint32 *var,
           uint32 val)
{
   (void)__sync_sub_and_fetch(&var->value, val);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_add --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic_add(atomic_uint32 *var,
           uint32 val)
{
   (void)__sync_add_and_fetch(&var->value, val);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_dec --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic_dec(atomic_uint32 *var)
{
   (void)__sync_sub_and_fetch(&var->value, 1);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_dec_and_test --
 *
 *---------------------------------------------------------------------------
 */

static inline bool
atomic_dec_and_test(atomic_uint32 *var)
{
   return __sync_sub_and_fetch(&var->value, 1) == 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_inc --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic_inc(atomic_uint32 *var)
{
   (void)__sync_add_and_fetch(&var->value, 1);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic_cmpxchg --
 *
 *---------------------------------------------------------------------------
 */

static inline uint32
atomic_cmpxchg(atomic_uint32 *var,
               uint32 old,
               uint32 new)
{
   return __sync_val_compare_and_swap(&var->value, old, new);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_inc --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic64_inc(atomic_uint64 *var)
{
   (void)__sync_add_and_fetch(&var->value, 1);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_dec --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic64_dec(atomic_uint64 *var)
{
   (void)__sync_sub_and_fetch(&var->value, 1);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_write --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic64_write(atomic_uint64 *var, uint64 val)
{
   var->value = val;
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_read --
 *
 *---------------------------------------------------------------------------
 */

static inline uint64
atomic64_read(const atomic_uint64 *var)
{
   return var->value;
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_sub --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic64_sub(atomic_uint64 *var,
             uint64 val)
{
   (void)__sync_sub_and_fetch(&var->value, val);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_add --
 *
 *---------------------------------------------------------------------------
 */

static inline void
atomic64_add(atomic_uint64 *var,
             uint64 val)
{
   (void)__sync_add_and_fetch(&var->value, val);
}


/*
 *---------------------------------------------------------------------------
 *
 * atomic64_cmpxchg --
 *
 *---------------------------------------------------------------------------
 */

static inline uint64
atomic64_cmpxchg(atomic_uint64 *var,
                 uint64 old,
                 uint64 new)
{
   return __sync_val_compare_and_swap(&var->value, old, new);
}

