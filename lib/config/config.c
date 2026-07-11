#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "util.h"
#include "file.h"

#include "config.h"

#define LGPFX "CONFIG:"


enum ConfigKVType {
   CONFIG_KV_UNKNOWN,
   CONFIG_KV_STRING,
   CONFIG_KV_INT64,
   CONFIG_KV_BOOL,
};


struct KeyValuePair {
   char                *key;
   bool                 save;
   struct KeyValuePair *next;
   enum ConfigKVType    type;
   union {
      int64  val;
      bool   trueOrFalse;
      char  *str;
   } u;
};

struct config {
   char                *fileName;
   struct KeyValuePair *list;
};


/*
 *-----------------------------------------------------------------------
 *
 * config_create --
 *
 *-----------------------------------------------------------------------
 */

struct config*
config_create(void)
{
   return safe_calloc(1, sizeof(struct config));
}

/*
 *-----------------------------------------------------------------------
 *
 * config_insert --
 *
 *      Insert items on the sorted linked list.
 *
 *-----------------------------------------------------------------------
 */

static void
config_insert(struct config *config,
              struct KeyValuePair *e)
{
   struct KeyValuePair *prev = NULL;
   struct KeyValuePair *item;

   item = config->list;

   while (item && strcmp(item->key, e->key) < 0) {
      prev = item;
      item = item->next;
   }
   if (prev) {
      e->next = prev->next;
      prev->next = e;
   } else {
      e->next = config->list;
      config->list = e;
   }
}


/*
 *-----------------------------------------------------------------------
 *
 * config_get --
 *
 *-----------------------------------------------------------------------
 */

static struct KeyValuePair *
config_get(const struct config *config,
           const char *key)
{
   struct KeyValuePair *e;

   ASSERT(config);

   e = config->list;
   while (e) {
      if (strcasecmp(e->key, key) == 0) {
         return e;
      }
      e = e->next;
   }
   return NULL;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_freekvlist --
 *
 *-----------------------------------------------------------------------
 */

static void
config_freekvlist(struct KeyValuePair *list)
{
   struct KeyValuePair *e;

   e = list;
   while (e) {
      struct KeyValuePair *next;

      next = e->next;
      if (e->type == CONFIG_KV_UNKNOWN || e->type == CONFIG_KV_STRING) {
         free(e->u.str);
      }
      free(e->key);
      free(e);
      e = next;
   }
}


/*
 *-----------------------------------------------------------------------
 *
 * config_setint64 --
 *
 *-----------------------------------------------------------------------
 */

void
config_setint64(struct config *config,
                int64          val,
                const char    *fmt,
                ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(key, sizeof key, fmt, ap);
   va_end(ap);

   e = config_get(config, key);

   if (e) {
      if (e->type == CONFIG_KV_UNKNOWN) {
         free(e->u.str);
         e->u.str = NULL;
      } else {
         ASSERT(e->type == CONFIG_KV_INT64);
      }
   } else {
      e = safe_malloc(sizeof *e);
      e->key  = safe_strdup(key);
      e->type = CONFIG_KV_INT64;
      config_insert(config, e);
   }
   e->save = 1;
   e->u.val = val;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_setbool --
 *
 *-----------------------------------------------------------------------
 */

void
config_setbool(struct config *config,
               bool           s,
               const char    *fmt,
               ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(key, sizeof key, fmt, ap);
   va_end(ap);

   e = config_get(config, key);

   if (e) {
      if (e->type == CONFIG_KV_UNKNOWN) {
         free(e->u.str);
         e->u.str = NULL;
      } else {
         ASSERT(e->type == CONFIG_KV_BOOL);
      }
   } else {
      e = safe_malloc(sizeof *e);
      e->key  = safe_strdup(key);
      e->type = CONFIG_KV_BOOL;
      config_insert(config, e);
   }
   e->save = 1;
   e->u.trueOrFalse = s;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_isset --
 *
 *-----------------------------------------------------------------------
 */

bool
config_isset(struct config *config,
             const char    *fmt,
             ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(key, sizeof key, fmt, ap);
   va_end(ap);

   e = config_get(config, key);

   return e != NULL;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_setstring --
 *
 *-----------------------------------------------------------------------
 */

void
config_setstring(struct config *config,
                 const char    *str,
                 const char    *fmt,
                 ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(key, sizeof key, fmt, ap);
   va_end(ap);

   e = config_get(config, key);

   if (e) {
      ASSERT(e->type == CONFIG_KV_STRING || e->type == CONFIG_KV_UNKNOWN);
      free(e->u.str);
      e->u.str = NULL;
   } else {
      e = safe_malloc(sizeof *e);
      e->key  = safe_strdup(key);
      e->type = CONFIG_KV_STRING;
      config_insert(config, e);
   }
   e->save = 1;
   e->u.str = str ? safe_strdup(str) : NULL;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_setunknownkv --
 *
 *-----------------------------------------------------------------------
 */

static void
config_setunknownkv(struct config *config,
                    const char    *key,
                    const char    *val)
{
   struct KeyValuePair *e;

   e = safe_malloc(sizeof *e);
   e->key   = safe_strdup(key);
   e->u.str = safe_strdup(val);
   e->type  = CONFIG_KV_UNKNOWN;
   e->save  = 1;

   config_insert(config, e);
}


/*
 *-----------------------------------------------------------------------
 *
 * config_chomp --
 *
 *-----------------------------------------------------------------------
 */

static void
config_chomp(char *str)
{
   ssize_t i = strlen(str) - 1;

   ASSERT(i >= 0);

   while (i > 0 && str[i] == ' ') {
      str[i] = '\0';
      i--;
   }
}


/*
 *-----------------------------------------------------------------------
 *
 * config_parseline --
 *
 *-----------------------------------------------------------------------
 */

static bool
config_parseline(char *line,
                 char **key,
                 char **val)
{
   size_t len;
   char *ptr;
   char *k;
   char *v;
   char *v0;
   int res;

   *key = NULL;
   *val = NULL;

   len = strlen(line);
   if (line[len - 1] == '\n' || line[len - 1] == '\r') {
      line[len - 1] = '\0';
   }

   ptr = line;
   while (*ptr != '\0' && *ptr == ' ') {
      ptr++;
   }
   if (*ptr == '\n' || *ptr == '\0') {
      return TRUE;
   }
   if (*ptr == '#') {
      return TRUE;
   }

   k = safe_malloc(len + 1);
   v = safe_malloc(len + 1);

   res = sscanf(ptr, "%[^=]=%[^\n]", k, v);
   if (res != 2) {
      Log(LGPFX" Failed to parse '%s'\n", ptr);
      free(k);
      free(v);
      return FALSE;
   }

   config_chomp(k);
   config_chomp(v);

   v0 = v;
   while (*v != '\0' && *v == ' ') {
      v++;
   }
   if (v[0] == '\"') {
      char *l;
      v++;
      l = strrchr(v, '\"');
      if (l == v) {
         Log(LGPFX" Failed to parse string: '%s'\n", v);
         free(k);
         free(v0);
         return FALSE;
      }
      *l = '\0';
   }
   v = safe_strdup(v);
   free(v0);

   *key = k;
   *val = v;
   return TRUE;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_getint64 --
 *
 *-----------------------------------------------------------------------
 */

int64
config_getint64(struct config *config,
                int64          defaultValue,
                const char    *format,
                ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   ASSERT(config);
   ASSERT(format);

   va_start(ap, format);
   vsnprintf(key, sizeof key, format, ap);
   va_end(ap);

   e = config_get(config, key);

   if (e) {
      if (e->type == CONFIG_KV_UNKNOWN) {
         int64 v = atoll(e->u.str);
         free(e->u.str);
         e->u.val = v;
         e->type = CONFIG_KV_INT64;
      } else {
         ASSERT(e->type == CONFIG_KV_INT64);
      }
      return e->u.val;
   } else {
      config_setint64(config, defaultValue, "%s", key);
      e = config_get(config, key);
      e->save = 0;
      return defaultValue;
   }
}


/*
 *-----------------------------------------------------------------------
 *
 * config_getbool --
 *
 *-----------------------------------------------------------------------
 */

bool
config_getbool(struct config *config,
               bool           defaultValue,
               const char    *fmt,
               ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   ASSERT(config);
   ASSERT(fmt);

   va_start(ap, fmt);
   vsnprintf(key, sizeof key, fmt, ap);
   va_end(ap);

   e = config_get(config, key);

   if (e) {
      if (e->type == CONFIG_KV_UNKNOWN) {
         bool s;
         if (strcasecmp(e->u.str, "true") == 0) {
            s = TRUE;
         } else {
            ASSERT(strcasecmp(e->u.str, "false") == 0);
            s = FALSE;
         }
         free(e->u.str);
         e->u.str = NULL;
         e->u.trueOrFalse = s;
         e->type = CONFIG_KV_BOOL;
      } else {
         ASSERT(e->type == CONFIG_KV_BOOL);
      }
      return e->u.trueOrFalse;
   } else {
      config_setbool(config, defaultValue, "%s", key);
      e = config_get(config, key);
      e->save = 0;
      return defaultValue;
   }
}


/*
 *-----------------------------------------------------------------------
 *
 * config_getstring --
 *
 *-----------------------------------------------------------------------
 */

char *
config_getstring(struct config *config,
                 const char    *defaultStr,
                 const char    *format,
                 ...)
{
   struct KeyValuePair *e;
   char key[1024];
   va_list ap;

   ASSERT(config);
   ASSERT(format);

   va_start(ap, format);
   vsnprintf(key, sizeof key, format, ap);
   va_end(ap);

   e = config_get(config, key);

   if (e) {
      if (e->type == CONFIG_KV_UNKNOWN) {
         e->type = CONFIG_KV_STRING;
      } else {
         ASSERT(e->type == CONFIG_KV_STRING);
      }
      return e->u.str ? safe_strdup(e->u.str) : NULL;
   } else {
      config_setstring(config, defaultStr, "%s", key);
      e = config_get(config, key);
      e->save = 0;
      return defaultStr ? safe_strdup(defaultStr) : NULL;
   }
}


/*
 *-----------------------------------------------------------------------
 *
 * config_load --
 *
 *-----------------------------------------------------------------------
 */

int
config_load(const char *fileName,
            struct config **confOut)
{
   struct file_descriptor *fd;
   struct config *config;
   struct KeyValuePair *list;
   int res;

   *confOut = NULL;
   list = NULL;

   Log(LGPFX" Loading config '%s'\n", fileName);

   res = file_open(fileName, TRUE, FALSE, &fd);
   if (res != 0) {
      Log(LGPFX" Failed to open config '%s': %d\n", fileName, res);
      return res;
   }

   config = config_create();
   config->fileName = safe_strdup(fileName);
   config->list = list;

   while (TRUE) {
      char *line = NULL;
      char *key;
      char *val;
      bool s;

      res = file_getline(fd, &line);
      if (res != 0) {
         Log(LGPFX" Failed to getline: %d\n", res);
         goto fail;
      }
      if (line == NULL) {
         break;
      }

      s = config_parseline(line, &key, &val);
      free(line);
      if (!s) {
         Log(LGPFX" Failed to parseline: '%s'\n", line);
         res = -1;
         goto fail;
      }
      if (key == NULL) {
         /* comment in the config file */
         continue;
      }

      config_setunknownkv(config, key, val);
      free(key);
      free(val);
   }

   file_close(fd);

   *confOut = config;

   return res;

fail:
   config_freekvlist(list);
   file_close(fd);
   return res;
}


/*
 *-----------------------------------------------------------------------
 *
 * config_free --
 *
 *-----------------------------------------------------------------------
 */

void
config_free(struct config *conf)
{
   if (conf == NULL) {
      return;
   }
   config_freekvlist(conf->list);
   free(conf->fileName);
   free(conf);
}


/*
 *-----------------------------------------------------------------------
 *
 * config_save --
 *
 *-----------------------------------------------------------------------
 */

int
config_save(struct config *conf)
{
   return config_write(conf, NULL);
}


/*
 *-----------------------------------------------------------------------
 *
 * config_write --
 *
 *-----------------------------------------------------------------------
 */

int
config_write(struct config *conf,
             const char    *filename)
{
   struct file_descriptor *fd;
   struct KeyValuePair *e;
   uint64 offset;
   int res;

   res = 0;
   fd = NULL;
   ASSERT(conf);
   if (filename == NULL) {
      ASSERT(conf->fileName);
   } else {
      free(conf->fileName);
      conf->fileName = safe_strdup(filename);
   }
   res = file_open(conf->fileName, FALSE, FALSE, &fd);
   if (res != 0) {
      Log(LGPFX" Failed to open config '%s': %s (%d)\n",
          filename, strerror(res), res);
      return res;
   }

   res = file_truncate(fd, 0);
   if (res != 0) {
      Log(LGPFX" Failed to truncate '%s': %s (%d)\n",
          filename, strerror(res), res);
      goto exit;
   }

   e = conf->list;
   offset = 0;

   while (e) {
      size_t numBytes;
      char *s = NULL;

      if (e->save == 0) {
         Log(LGPFX" not writing key '%s'\n", e->key);
         e = e->next;
         continue;
      }

      switch (e->type) {
      case CONFIG_KV_INT64:
         s = safe_asprintf("%s = \"%lld\"\n", e->key, e->u.val);
         break;
      case CONFIG_KV_BOOL:
         s = safe_asprintf("%s = \"%s\"\n", e->key, e->u.trueOrFalse ? "TRUE" : "FALSE");
         break;
      default:
         ASSERT(e->type == CONFIG_KV_UNKNOWN || e->type == CONFIG_KV_STRING);
         if (e->u.str) {
            s = safe_asprintf("%s = \"%s\"\n", e->key, e->u.str);
         }
      }

      if (s) {
         numBytes = 0;
         res = file_pwrite(fd, offset, s, strlen(s), &numBytes);
         if (res != 0 || numBytes != strlen(s)) {
            Log(LGPFX" Failed to pwrite %zd bytes: %s (%d)\n",
                strlen(s), strerror(res), res);
            free(s);
            goto exit;
         }
         offset += numBytes;
         free(s);
      }
      e = e->next;
   }

exit:
   if (res != 0) {
      // XXX: consider cleaning-up.
   }
   if (fd) {
      file_close(fd);
   }
   return res;
}
