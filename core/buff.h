#pragma once

#include <string.h>
#include <stdlib.h>

#include "util.h"

struct buff {
   uint8     *base;
   size_t     len;
   ssize_t    idx;
   bool       grow;
};


/*
 *------------------------------------------------------------------------
 *
 * buff_resize --
 *
 *------------------------------------------------------------------------
 */

static inline void
buff_resize(struct buff *buf,
            size_t sz)
{
   size_t newlen;

   ASSERT(buf->grow);

   /*
    * Grow by at least sz bytes.
    */
   newlen = MAX(buf->len * 2, buf->len + sz);

   buf->base = safe_realloc(buf->base, newlen);
   buf->len = newlen;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_curptr --
 *
 *------------------------------------------------------------------------
 */

static inline uint8 *
buff_curptr(const struct buff *buf)
{
   ASSERT(buf->idx < buf->len);
   return buf->base + buf->idx;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_check_overflow --
 *
 *------------------------------------------------------------------------
 */

static inline int
buff_check_overflow(const struct buff *buf,
                    size_t sz)
{
   return buf->idx + sz > buf->len;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_base --
 *
 *------------------------------------------------------------------------
 */

static inline void *
buff_base(const struct buff *buf)
{
   if (buf == NULL) {
      return NULL;
   }
   return buf->base;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_maxlen --
 *
 *------------------------------------------------------------------------
 */

static inline size_t
buff_maxlen(const struct buff *buf)
{
   if (buf == NULL) {
      return 0;
   }
   return buf->len;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_curlen --
 *
 *------------------------------------------------------------------------
 */

static inline size_t
buff_curlen(const struct buff *buf)
{
   if (buf == NULL) {
      return 0;
   }
   return buf->idx;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_space_left --
 *
 *------------------------------------------------------------------------
 */

static inline size_t
buff_space_left(const struct buff *buf)
{
   ASSERT(buf->idx <= buf->len);

   return buf->len - buf->idx;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_skip --
 *
 *------------------------------------------------------------------------
 */

static inline int
buff_skip(struct buff *buf,
          size_t len)
{
   ASSERT(buf);

   if (buff_check_overflow(buf, len)) {
      if (!buf->grow) {
         return 1;
      }
      buff_resize(buf, len);
   }
   buf->idx += len;

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_set_idx --
 *
 *------------------------------------------------------------------------
 */

static inline void
buff_set_idx(struct buff *buf,
             size_t idx)
{
   ASSERT(buf);
   ASSERT(idx <= buf->len);

   buf->idx = idx;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_init --
 *
 *------------------------------------------------------------------------
 */

static inline void
buff_init(struct buff *buf,
          void *base,
          size_t len)
{
   ASSERT(buf);

   buf->base = base;
   buf->len  = len;
   buf->idx  = 0;
   buf->grow = 0;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_copy_to --
 *
 *------------------------------------------------------------------------
 */

static inline int
buff_copy_to(struct buff *dst,
             const void *src,
             size_t len)
{
   if (buff_check_overflow(dst, len)) {
      if (!dst->grow) {
         return 1;
      }
      buff_resize(dst, len);
   }
   if (len > 0) {
      memcpy(buff_curptr(dst), src, len);
      dst->idx += len;
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_copy_from --
 *
 *------------------------------------------------------------------------
 */

static inline int
buff_copy_from(struct buff *src,
               void *dst,
               size_t len)
{
   /*
    * Reading past the end of the buffer is an error, not something to grow
    * into: the bytes simply are not there. This is the guard that keeps a
    * truncated or internally-inconsistent peer message from reading out of
    * bounds (and previously tripping buff_resize's ASSERT(grow)).
    */
   if (buff_check_overflow(src, len)) {
      return 1;
   }
   if (len > 0) {
      memcpy(dst, buff_curptr(src), len);
      src->idx += len;
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_append --
 *
 *------------------------------------------------------------------------
 */

static inline int
buff_append(struct buff *dst,
            const struct buff *src)
{
   if (src == NULL) {
      return 0;
   }
   return buff_copy_to(dst, src->base, src->idx);
}


/*
 *------------------------------------------------------------------------
 *
 * buff_free_base --
 *
 *------------------------------------------------------------------------
 */

static inline void
buff_free_base(struct buff *buf)
{
   ASSERT(buf);

   free(buf->base);
   buf->base = NULL;
   buf->len = 0;
   buf->idx = 0;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_free --
 *
 *------------------------------------------------------------------------
 */

static inline void
buff_free(struct buff *buf)
{
   if (buf == NULL) {
      return;
   }

   buff_free_base(buf);
   free(buf);
}


/*
 *------------------------------------------------------------------------
 *
 * buff_alloc_base --
 *
 *------------------------------------------------------------------------
 */

static inline void
buff_alloc_base(struct buff *buf,
                size_t len)
{
   ASSERT(buf);
   ASSERT(buf->base == NULL);

   buf->base = safe_malloc(len);
   buf->len = len;
   buf->idx = 0;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_alloc --
 *
 *------------------------------------------------------------------------
 */

static inline struct buff *
buff_alloc(void)
{
   struct buff *buf;

   buf = safe_malloc(sizeof *buf);
   buf->idx  = 0;
   buf->len  = 64;
   buf->grow = 1;
   buf->base = safe_malloc(buf->len);

   return buf;
}


/*
 *------------------------------------------------------------------------
 *
 * buff_dup --
 *
 *------------------------------------------------------------------------
 */

static inline struct buff *
buff_dup(const struct buff *buf)
{
   struct buff *buf2;

   buf2 = buff_alloc();
   buff_append(buf2, buf);

   return buf2;
}


