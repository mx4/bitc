#pragma once

#include "basic_defs.h"

void Panic(const char *format, ...) PRINTF_GCC_DECL(1, 2) NORETURN;
void log_warn(const char *format, ...) PRINTF_GCC_DECL(1, 2);

typedef void (LogCB)(const char *ts, const char *str, void *clientData);
void log_set_cb(LogCB *logCB, void *clientData);
void log_info(const char *format, ...) PRINTF_GCC_DECL(1, 2);
void log_set_level(int level);
void log_init(const char *filename);
void log_exit(void);
void log_bytes(const char *pfx, const void *data, size_t len);

mtime_t time_get(void);

char *print_time_utc(uint32 t);
char *print_time_local(uint32 t, const char *fmt);
char *print_time_local_short(uint32 time);
char *print_size(uint64 size);
char *print_latency(mtime_t latency);
void  print_backtrace(void);

typedef void (OnPanicCB)(void *data);
void panic_register_cb(OnPanicCB *callback, void  *clientData);

bool  util_throttle(uint32 count);
void  util_bumpnofds(void);
void  util_bumpcoresize(void);
uint8 util_log2(uint32 val);
char *util_gethomedir(void);
char *util_getusername(void);

void str_trim(char *s, size_t len);
void str_reverse(void *buf, size_t len);
void str_copyreverse(void *dst, const void *src, size_t len);
void str_printf_bytes(const char *pfx, const void *data, size_t len);
void str_snprintf_bytes(char *str, size_t len, const char *pfx,
                        const uint8 *buf, size_t buflen);
void str_to_bytes(const char *str, uint8 **bytes, size_t *len);

void *safe_malloc(size_t size);
void *safe_calloc(size_t nmemb, size_t size);
void *safe_realloc(void *buf, size_t size);
char *safe_strdup(const char *str);
char *safe_asprintf(const char *fmt, ...) PRINTF_GCC_DECL(1, 2);

bool util_memunlock(const void *ptr, size_t len);
bool util_memlock(const void *ptr, size_t len);

struct mutex;

struct mutex *mutex_alloc(void);
void mutex_free(struct mutex *lock);
void mutex_destroy(struct mutex *lock);
void mutex_lock(struct mutex *lock);
void mutex_unlock(struct mutex *lock);
bool mutex_islocked(struct mutex *lock);

struct condvar;

struct condvar * condvar_alloc(void);
void condvar_wait(struct condvar *cv, struct mutex *lock);
void condvar_signal(struct condvar *cv);
void condvar_free(struct condvar *cv);

/*
 * Log, ASSERTs and NOT_TESTED.
 */

#define NOT_TESTED() \
     log_warn("NOT_TESTED -- %s:%s:%u\n", __FILE__, __func__, __LINE__)

#define NOT_TESTED_ONCE()       \
      do {                      \
         static bool _done;     \
         if (!_done) {          \
            _done = 1;          \
            NOT_TESTED();       \
         }                      \
      } while (0)

#define DOLOG(_lvl)  (verbose >= _lvl)

#define LOG(_lvl, _fmt)                      \
   do {                                      \
      if (DOLOG(_lvl)) {                     \
         log_info _fmt;                      \
      }                                      \
   } while (0)

#define NOT_IMPLEMENTED()                       \
   do {                                         \
      Panic("NOT_IMPLEMENTED: %s:%s:%u\n",      \
            __FILE__, __func__, __LINE__);      \
   } while (0)

#define NOT_REACHED()                           \
   do {                                         \
      Panic("NOT_REACHED: %s:%s:%u\n",          \
            __FILE__, __func__, __LINE__);      \
   } while (0)

#define ASSERT_MEMALLOC(_x)                               \
   do {                                                   \
      if (unlikely((_x) == NULL)) {                       \
         Panic("Failed to allocate memory at %s:%s:%u\n", \
               __FILE__, __func__, __LINE__);             \
      }                                                   \
   } while (0)

#define ASSERT_NOT_TESTED(_x)                           \
   if (unlikely(!(_x))) {                               \
      log_warn("ASSERT_NOT_TESTED failed at %s:%s:%u\n"  \
              "--- Expression '%s' is false.\n",        \
              __FILE__, __func__, __LINE__,             \
              STR(_x));                                 \
   }
#define ASSERT(_x)                                      \
   if (unlikely(!(_x))) {                               \
      Panic("ASSERT failed at %s:%s:%u\n"               \
            "PANIC: Expression '%s' not TRUE.\n",       \
            __FILE__, __func__, __LINE__,               \
            STR(_x));                                   \
   }

