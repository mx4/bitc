#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>

#include <sys/types.h>
#include <pwd.h>

#ifdef linux
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

#include "basic_defs.h"
#include "util.h"
#include "file.h"

#define LGPFX   "UTIL:"

struct mutex {
   pthread_mutex_t  lck;
};

struct condvar {
   pthread_cond_t   condvar;
};

static struct {
   struct mutex *lock;
   int           verboseLog;
   char          filePath[PATH_MAX];
   FILE         *f;
   LogCB        *logCB;
   void         *logCBData;
} logState;


static struct {
   OnPanicCB    *callback;
   void         *clientData;
} onPanicCBs[16];

static int numPanicCBs = 0;


/*
 *------------------------------------------------------------------------
 *
 * mutex_free --
 *
 *------------------------------------------------------------------------
 */

void
mutex_free(struct mutex *lock)
{
   pthread_mutex_destroy(&lock->lck);
   free(lock);
}


/*
 *------------------------------------------------------------------------
 *
 * mutex_islocked --
 *
 *------------------------------------------------------------------------
 */

bool
mutex_islocked(struct mutex *lock)
{
   int res;

   res = pthread_mutex_trylock(&lock->lck);
   if (res != 0) {
      ASSERT(res == EBUSY);
      return 0;
   }
   pthread_mutex_unlock(&lock->lck);
   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * mutex_init --
 *
 *------------------------------------------------------------------------
 */

static void
mutex_init(struct mutex *lock)
{
   pthread_mutexattr_t attr;

   pthread_mutexattr_init(&attr);
   pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

   pthread_mutex_init(&lock->lck, &attr);
}


/*
 *------------------------------------------------------------------------
 *
 * mutex_alloc --
 *
 *------------------------------------------------------------------------
 */

struct mutex *
mutex_alloc(void)
{
   struct mutex *lock;

   lock = safe_malloc(sizeof(struct mutex));
   mutex_init(lock);

   return lock;
}


/*
 *------------------------------------------------------------------------
 *
 * condvar_alloc --
 *
 *------------------------------------------------------------------------
 */

struct condvar *
condvar_alloc(void)
{
   struct condvar *cv = safe_malloc(sizeof *cv);
   pthread_cond_init(&cv->condvar, NULL);
   return cv;
}


/*
 *------------------------------------------------------------------------
 *
 * condvar_wait --
 *
 *------------------------------------------------------------------------
 */

void
condvar_wait(struct condvar *cv,
             struct mutex *lock)
{
   ASSERT(mutex_islocked(lock));

   pthread_cond_wait(&cv->condvar, &lock->lck);
}


/*
 *------------------------------------------------------------------------
 *
 * condvar_free --
 *
 *------------------------------------------------------------------------
 */

void
condvar_free(struct condvar *cv)
{
   pthread_cond_destroy(&cv->condvar);
   free(cv);
}


/*
 *------------------------------------------------------------------------
 *
 * condvar_signal --
 *
 *------------------------------------------------------------------------
 */

void
condvar_signal(struct condvar *cv)
{
   pthread_cond_signal(&cv->condvar);
}


/*
 *------------------------------------------------------------------------
 *
 * mutex_destroy --
 *
 *------------------------------------------------------------------------
 */

void
mutex_destroy(struct mutex *lock)
{
   pthread_mutex_destroy(&lock->lck);
}


/*
 *------------------------------------------------------------------------
 *
 * mutex_lock --
 *
 *------------------------------------------------------------------------
 */

void
mutex_lock(struct mutex *lock)
{
   int res;

   if (lock == NULL) {
      return;
   }

   res = pthread_mutex_lock(&lock->lck);
   ASSERT(res == 0);
}


/*
 *------------------------------------------------------------------------
 *
 * mutex_unlock --
 *
 *------------------------------------------------------------------------
 */

void
mutex_unlock(struct mutex *lock)
{
   int res;

   if (lock == NULL) {
      return;
   }
   res = pthread_mutex_unlock(&lock->lck);
   ASSERT(res == 0);
}


/*
 *---------------------------------------------------------------------
 *
 * Log_SetCB --
 *
 *---------------------------------------------------------------------
 */

void
Log_SetCB(LogCB *logCB,
          void *clientData)
{
   logState.logCB = logCB;
   logState.logCBData = clientData;
}


/*
 *---------------------------------------------------------------------
 *
 * LogPrintf --
 *
 *---------------------------------------------------------------------
 */

static void
LogPrintf(bool warning,
          const char *msgPfx,
          const char *format,
          va_list args)
{
   char logLine[4096];
   char tsPfx0[1024];
   char tsPfx[1024];
   char msg[4096];
   struct timeval tv;
   struct tm *tmp;

   gettimeofday(&tv, NULL);
   tmp = localtime(&tv.tv_sec);

   strftime(tsPfx0, sizeof tsPfx0, "%T", tmp);
   snprintf(tsPfx, sizeof tsPfx, "%s.%06llu", tsPfx0, (uint64)tv.tv_usec);

   vsnprintf(msg, sizeof msg, format, args);

   snprintf(logLine, sizeof logLine, "%s| %s%s", tsPfx, msgPfx, msg);
   if (logState.logCB) {
      logState.logCB(tsPfx, msg, logState.logCBData);
      mutex_lock(logState.lock);
   } else if (warning) {
      mutex_lock(logState.lock);
      fprintf(stderr, "%s%s", msgPfx, msg);
      fflush(stdout);
   } else {
      mutex_lock(logState.lock);
   }

   if (logState.f) {
      fprintf(logState.f, "%s", logLine);
      fflush(logState.f);
   }
   mutex_unlock(logState.lock);
}


/*
 *---------------------------------------------------------------------
 *
 * print_backtrace --
 *
 *---------------------------------------------------------------------
 */

void
print_backtrace(void)
{
   void *buf[32];
   int bufSize;
   char **btStr;
   int i;

   bufSize = backtrace(buf, ARRAYSIZE(buf));
   btStr = backtrace_symbols(buf, bufSize);
   if (btStr == NULL) {
      return;
   }
   for (i = 0; i < bufSize; i++) {
      log_warn(LGPFX" [%d] = %s\n", i, btStr[i]);
   }
   free(btStr);
}


/*
 *---------------------------------------------------------------------
 *
 * panic_register_cb --
 *
 *---------------------------------------------------------------------
 */

void
panic_register_cb(OnPanicCB *callback,
                  void      *clientData)
{
   ASSERT(callback);

   onPanicCBs[numPanicCBs].callback   = callback;
   onPanicCBs[numPanicCBs].clientData = clientData;

   numPanicCBs++;
   ASSERT(numPanicCBs < ARRAYSIZE(onPanicCBs));
}


/*
 *---------------------------------------------------------------------
 *
 * Panic --
 *
 *---------------------------------------------------------------------
 */

void
Panic(const char *format, ...)
{
   static bool in_panic;
   va_list args2;
   va_list args;
   int i;

   if (in_panic) {
      fprintf(stderr, "Panic loop.\n");
      goto dump;
   }
   in_panic = 1;

   for (i = 0; i < numPanicCBs; i++) {
      if (onPanicCBs[i].callback) {
         onPanicCBs[i].callback(onPanicCBs[i].clientData);
      }
   }

   va_start(args, format);
   va_copy(args2, args);
   vfprintf(stderr, format, args);
   va_end(args);

   LogPrintf(TRUE, "\nPANIC: ", format, args2);
   va_end(args2);

   print_backtrace();

dump:
   /*
    * Generate a core-dump.
    */
   kill(getpid(), SIGABRT);
   _exit(1); /* should not be required */
}


/*
 *---------------------------------------------------------------------
 *
 * Warning --
 *
 *---------------------------------------------------------------------
 */

void
log_warn(const char *format, ...)
{
   va_list args;

   va_start(args, format);
   LogPrintf(TRUE, "", format, args);
   va_end(args);
}


/*
 *---------------------------------------------------------------------
 *
 * LogAlways --
 *
 *---------------------------------------------------------------------
 */

static void
LogAlways(const char *format, ...)
{
   va_list args;

   va_start(args, format);
   LogPrintf(FALSE, "", format, args);
   va_end(args);
}


/*
 *---------------------------------------------------------------------
 *
 * Log --
 *
 *---------------------------------------------------------------------
 */

void
log_info(const char *format, ...)
{
   va_list args;

   if (logState.verboseLog == 0) {
      return;
   }

   va_start(args, format);
   LogPrintf(FALSE, "", format, args);
   va_end(args);
}


/*
 *---------------------------------------------------------------------
 *
 * Log_Exit --
 *
 *---------------------------------------------------------------------
 */

void
Log_Exit(void)
{
   if (logState.f) {
      mutex_destroy(logState.lock);
      mutex_free(logState.lock);
      fclose(logState.f);
      logState.f = NULL;
      logState.filePath[0] = '\0';
   }
}


/*
 *---------------------------------------------------------------------
 *
 * Log_Init --
 *
 *---------------------------------------------------------------------
 */

void
Log_Init(const char *filename)
{
   time_t ltime;

   if (!filename) {
      return;
   }

   if (file_exists(filename)) {
      file_rotate(filename, 10);
   }

   logState.lock = mutex_alloc();
   logState.f = fopen(filename, "a");
   if (logState.f == NULL) {
      printf(LGPFX" Failed to create log file '%s'\n", filename);
   }
   file_chmod(filename, 0600);
   strncpy(logState.filePath, filename, sizeof logState.filePath);

   ltime = time(NULL);

   LogAlways(LGPFX" new log session: %s", asctime(localtime(&ltime)));
}


/*
 *---------------------------------------------------------------------
 *
 * Log_SetLevel --
 *
 *---------------------------------------------------------------------
 */

void
Log_SetLevel(int level)
{
   logState.verboseLog = level;
}


/*
 *---------------------------------------------------------------------
 *
 * time_get --
 *
 *---------------------------------------------------------------------
 */

mtime_t
time_get(void)
{
   struct timeval t;
   int s;

   s = gettimeofday(&t, NULL);
   if (s != 0) {
      log_warn(LGPFX" Failed to gettimeofday(): %d\n", s);
      return 0;
   }
   return (mtime_t)t.tv_sec * 1000 * 1000 + t.tv_usec;
}


/*
 *---------------------------------------------------------------------
 *
 * util_getusername --
 *
 *---------------------------------------------------------------------
 */

char *
util_getusername(void)
{
   struct passwd *pw;

   pw = getpwuid(geteuid());
   if (pw == NULL) {
      int res = errno;
      printf(LGPFX" failed to getpwuid() : %s (%d)\n",
             strerror(res), res);
      return NULL;
   }
   return safe_strdup(pw->pw_name);
}


/*
 *---------------------------------------------------------------------
 *
 * util_throttle --
 *
 *---------------------------------------------------------------------
 */

bool
util_throttle(uint32 count)
{
   if (count < 100) {
      return TRUE;
   } else if (count <   10000 && (count %   100) == 0) {
      return TRUE;
   } else if (count < 1000000 && (count % 10000) == 0) {
      return TRUE;
   } else if ((count % 1000000) == 0) {
      return TRUE;
   }
   return FALSE;
}


/*
 *---------------------------------------------------------------------
 *
 * safe_asprintf --
 *
 *---------------------------------------------------------------------
 */

char *
safe_asprintf(const char *fmt, ...)
{
   va_list args;
   char *ptr;
   int n;

   ptr = NULL;
   va_start(args, fmt);
   n = vasprintf(&ptr, fmt, args);
   va_end(args);

   ASSERT(n != -1);
   ASSERT_MEMALLOC(ptr);
   return ptr;
}


/*
 *---------------------------------------------------------------------
 *
 * safe_strdup --
 *
 *---------------------------------------------------------------------
 */

char *
safe_strdup(const char *str)
{
   void *ptr = strdup(str);
   ASSERT_MEMALLOC(ptr);
   return ptr;
}


/*
 *---------------------------------------------------------------------
 *
 * safe_calloc --
 *
 *---------------------------------------------------------------------
 */

void *
safe_calloc(size_t nmemb, size_t size)
{
   void *ptr = calloc(nmemb, size);
   ASSERT_MEMALLOC(ptr);
   return ptr;
}


/*
 *---------------------------------------------------------------------
 *
 * safe_realloc --
 *
 *---------------------------------------------------------------------
 */

void *
safe_realloc(void *buf, size_t size)
{
   void *ptr = realloc(buf, size);
   ASSERT_MEMALLOC(ptr);
   return ptr;
}


/*
 *---------------------------------------------------------------------
 *
 * safe_malloc --
 *
 *---------------------------------------------------------------------
 */

void *
safe_malloc(size_t size)
{
   void *ptr = malloc(size);
   ASSERT_MEMALLOC(ptr);
   return ptr;
}


/*
 *---------------------------------------------------------------------
 *
 * util_memunlock --
 *
 *---------------------------------------------------------------------
 */

bool
util_memunlock(const void *ptr,
               size_t len)
{
   int err;

   err = munlock(ptr, len);
   if (err == 0) {
      return 1;
   }

   err = errno;
   log_info(LGPFX" failed to munlock: %s (%d)\n",
       strerror(err), err);

   return 0;
}


/*
 *---------------------------------------------------------------------
 *
 * util_memlock --
 *
 *---------------------------------------------------------------------
 */

bool
util_memlock(const void *ptr,
             size_t len)
{
   int err;

   err = mlock(ptr, len);
   if (err == 0) {
      return 1;
   }

   err = errno;
   log_info(LGPFX" failed to mlock: %s (%d)\n",
       strerror(err), err);

   return 0;
}


/*
 *---------------------------------------------------------------------
 *
 * util_gethomedir --
 *
 *---------------------------------------------------------------------
 */

char *
util_gethomedir(void)
{
   struct passwd* pwd;

   pwd = getpwuid(getuid());
   if (pwd == NULL) {
      return NULL;
   }
   return safe_strdup(pwd->pw_dir);
}


/*
 *------------------------------------------------------------------------
 *
 * print_latency --
 *
 *------------------------------------------------------------------------
 */

char *
print_latency(mtime_t latency)
{
#define ONE_MSEC  (1000ULL)
#define ONE_SEC   (1000 * ONE_MSEC)
#define ONE_MIN   (  60 * ONE_SEC)
#define ONE_HOUR  (  60 * ONE_MIN)
#define ONE_DAY   (  24 * ONE_HOUR)
#define ONE_YEAR  ( 365 * ONE_DAY)

   if (latency > ONE_YEAR) {
      uint64 year =  latency / ONE_YEAR;
      uint64 day  = (latency % ONE_YEAR) / ONE_DAY;
      return safe_asprintf("%llu year%s %llu day%s",
                           year, year > 1 ? "s" : "",
                           day,  day  > 1 ? "s" : "");
   } else if (latency > ONE_DAY) {
      uint64 day  =  latency / ONE_DAY;
      uint64 hour = (latency % ONE_DAY) / ONE_HOUR;
      return safe_asprintf("%llu day%s %llu hour%s",
                           day,  day  > 1 ? "s" : "",
                           hour, hour > 1 ? "s" : "");
   } else if (latency > ONE_HOUR) {
      uint64 hour = latency / ONE_HOUR;
      return safe_asprintf("%llu hour%s %llu min",
                           hour, hour > 1 ? "s" : "",
                           (latency % ONE_HOUR) / ONE_MIN);
   } else if (latency > ONE_MIN) {
      return safe_asprintf("%llu min %.1f sec",
                            latency / ONE_MIN,
                           (latency % ONE_MIN) / (ONE_SEC * 1.0));
   } else if (latency > ONE_SEC) {
      return safe_asprintf("%.1f sec", latency / (ONE_SEC * 1.0));
   } else if (latency > ONE_MSEC) {
      return safe_asprintf("%.1f msec", latency / (ONE_MSEC * 1.0));
   } else {
      return safe_asprintf("%llu usec", latency);
   }
#undef ONE_MSEC
#undef ONE_SEC
#undef ONE_MIN
#undef ONE_HOUR
#undef ONE_DAY
#undef ONE_WEEK
}


/*
 *------------------------------------------------------------------------
 *
 * print_size --
 *
 *------------------------------------------------------------------------
 */

char *
print_size(uint64 size)
{
   if (size < 1024) {
      return safe_asprintf("%llu bytes", size);
   } else if (size < 1024 * 1024) {
      return safe_asprintf("%.1f KB", size / 1024.0);
   } else if (size < 1024 * 1024 * 1024) {
      return safe_asprintf("%.1f MB", size / (1024 * 1024.0));
   } else {
      return safe_asprintf("%.1f GB", size / (1024 * 1024 * 1024.0));
   }
}


/*
 *------------------------------------------------------------------------
 *
 * print_time_utc --
 *
 *------------------------------------------------------------------------
 */

char *
print_time_utc(uint32 time)
{
   char str[128];
   struct tm *ts;
   time_t t = time;

   ASSERT_ON_COMPILE(sizeof t == sizeof(time_t));

   memset(str, 0, sizeof str);
   ts = gmtime(&t);
   if (ts) {
      strftime(str, sizeof str, "%c", ts);
   }
   return safe_strdup(str);
}


/*
 *------------------------------------------------------------------------
 *
 * print_time_local_short --
 *
 *------------------------------------------------------------------------
 */

char *
print_time_local_short(uint32 time)
{
   char str[128];
   struct tm *ts;
   time_t t = time;

   ASSERT_ON_COMPILE(sizeof t == sizeof(time_t));

   memset(str, 0, sizeof str);
   ts = localtime(&t);
   if (ts) {
      strftime(str, sizeof str, "%d %b %T", ts);
   }
   return safe_strdup(str);
}


/*
 *------------------------------------------------------------------------
 *
 * print_time_local --
 *
 *------------------------------------------------------------------------
 */

char *
print_time_local(uint32 time,
                 const char *fmt)
{
   char str[128];
   struct tm *ts;
   time_t t = time;

   ASSERT_ON_COMPILE(sizeof t == sizeof(time_t));

   memset(str, 0, sizeof str);
   ts = localtime(&t);
   if (ts) {
      strftime(str, sizeof str, fmt, ts);
   }
   return safe_strdup(str);
}


/*
 *------------------------------------------------------------------------
 *
 * util_bumpcoresize
 *
 *------------------------------------------------------------------------
 */

void
util_bumpcoresize(void)
{
   struct rlimit lim;
   int res;

   res = getrlimit(RLIMIT_CORE, &lim);
   if (res) {
      log_warn(LGPFX" getrlimit failed: %s\n", strerror(errno));
      return;
   }
   if (lim.rlim_cur == lim.rlim_max) {
      return;
   }

   log_info(LGPFX" changing rlimit core-size: %llx -> %llx\n",
       (uint64)lim.rlim_cur, (uint64)lim.rlim_max);
   lim.rlim_cur = lim.rlim_max;

   res = setrlimit(RLIMIT_CORE, &lim);
   if (res) {
      log_warn(LGPFX" setrlimit failed: %s\n", strerror(errno));
      return;
   }
}


/*
 *------------------------------------------------------------------------
 *
 * util_bumpnofds --
 *
 *------------------------------------------------------------------------
 */

void
util_bumpnofds(void)
{
   struct rlimit lim;
   int res;

   res = getrlimit(RLIMIT_NOFILE, &lim);
   if (res) {
      log_warn(LGPFX" getrlimit failed: %s\n", strerror(errno));
      return;
   }
   if (lim.rlim_cur == lim.rlim_max) {
      return;
   }
   log_info(LGPFX" changing rlimit max fds: %llu -> %llu\n",
       (uint64)lim.rlim_cur, (uint64)lim.rlim_max);
   if (lim.rlim_max > 100000) {
      lim.rlim_max = 10000;
   }
   lim.rlim_cur = lim.rlim_max;

   res = setrlimit(RLIMIT_NOFILE, &lim);
   if (res) {
      log_warn(LGPFX" setrlimit failed: %s\n", strerror(errno));
   }
}


/*
 *---------------------------------------------------------------------
 *
 * util_log2 --
 *
 *---------------------------------------------------------------------
 */

uint8
util_log2(uint32 v)
{
   uint32 i = 0;

   while (v) {
      i++;
      v >>= 1;
   }
   return i ? i - 1 : i;
}


/*
 *---------------------------------------------------
 *
 * str_snprintf_bytes --
 *
 *---------------------------------------------------
 */

void
str_snprintf_bytes(char        *str,
                   size_t       len,
                   const char  *pfx,
                   const uint8 *buf,
                   size_t       buflen)
{
   int idx = 0;
   size_t i;

   str[0] = '\0';
   if (pfx) {
      idx += snprintf(str, len, "%-8s", pfx);
   }
   for (i = 0; i < buflen; i++) {
      ASSERT(idx <= len);
      idx += snprintf(str + idx, len - idx, "%02x", buf[i]);
   }
}


/*
 *---------------------------------------------------
 *
 * str_printf_bytes --
 *
 *---------------------------------------------------
 */

void
str_printf_bytes(const char *pfx,
                 const void *data,
                 size_t len)
{
   char str[16384];

   str_snprintf_bytes(str, sizeof str, pfx, data, len);

   printf("%s\n", str);
}


/*
 *---------------------------------------------------
 *
 * Log_Bytes --
 *
 *---------------------------------------------------
 */

void
Log_Bytes(const char *pfx,
          const void *data,
          size_t      len)
{
   char str[16384];

   str_snprintf_bytes(str, sizeof str, pfx, data, len);

   log_info("%s\n", str);
}


/*
 *------------------------------------------------------------------------
 *
 * str_copyreverse --
 *
 *------------------------------------------------------------------------
 */

void
str_copyreverse(void *dest,
                const void *source,
                size_t len)
{
   const uint8 *src = (uint8 *)source;
   uint8 *dst = (uint8 *)dest;
   size_t i;

   for (i = 0; i < len; i++) {
      dst[i] = src[len - 1 - i];
   }
}


/*
 *------------------------------------------------------------------------
 *
 * str_reverse --
 *
 *------------------------------------------------------------------------
 */

void
str_reverse(void *buf,
            size_t len)
{
   uint8 *bs = (uint8 *)buf;
   uint8 *be = (uint8 *)buf + len - 1;

   while (bs < be) {
      uint8 tmp = *be;

      *be = *bs;
      *bs = tmp;
      bs++;
      be--;
   }
}


/*
 *---------------------------------------------------------------------
 *
 * str_trim --
 *
 *---------------------------------------------------------------------
 */

void
str_trim(char *s,
         size_t len)
{
   ssize_t i = len - 1;

   while (i >= 0 && (s[i] == ' ' || s[i] == '\0')) {
      s[i] = '\0';
      i--;
   }
}


/*
 *---------------------------------------------------------------------
 *
 * str_to_bytes --
 *
 *---------------------------------------------------------------------
 */

void
str_to_bytes(const char *str,
             uint8     **bytes,
             size_t     *bytes_len)
{
   uint8 *buf;
   size_t len;
   size_t i;

   *bytes = NULL;
   *bytes_len = 0;

   if (str == NULL) {
      return;
   }

   len = strlen(str);
   buf = safe_calloc(1, len / 2 + 1);

   for (i = 0; i < len / 2; i++) {
      uint32 x;
      sscanf(str + i * 2, "%02x", &x);
      ASSERT(x <= 255);
      buf[i] = x;
   }

   *bytes = buf;
   *bytes_len = len / 2;
}

