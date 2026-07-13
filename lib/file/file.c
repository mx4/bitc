#ifdef linux
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif
// for O_DIRECT
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "basic_defs.h"
#include "util.h"

#include "file.h"

#define LGPFX   "FILE:"


struct file_descriptor {
   char *name;
   int   fd;
   FILE *f;
};


/*
 *---------------------------------------------------------------------------
 *
 * file_chmod --
 *
 *---------------------------------------------------------------------------
 */

int
file_chmod(const char *filename,
           uint32 mode)
{
   int res;

   res = chmod(filename, mode);
   if (res == 0) {
      return 0;
   }
   res = errno;
   ASSERT(res == -1);

   log_info(LGPFX" failed to chmod %s to 0x%x: %s\n",
       filename, mode, strerror(res));

   return res;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_valid --
 *
 *---------------------------------------------------------------------------
 */

bool
file_valid(const struct file_descriptor *desc)
{
   return desc && desc->name && desc->fd >= 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_glob --
 *
 *---------------------------------------------------------------------------
 */

int
file_glob(const char *path,
          const char *pattern,
          char ***list)
{
   glob_t g = { 0 };
   size_t i;
   char **l;
   char *s;
   int res;

   *list = NULL;

   s = safe_asprintf("%s/%s", path, pattern);

   res = glob(s, 0, NULL, &g);
#ifndef GLOB_NOMATCH
   NOT_TESTED();
   if (res == GLOB_ABEND) {
#else
   if (res == GLOB_NOMATCH) {
#endif
      res = 0;
      goto exit;
   }
   if (res != 0) {
      res = errno;
      log_info(LGPFX" failed to glob(2) on '%s': %d\n", s, res);
      goto exit;
   }

   l = safe_malloc((g.gl_pathc + 1) * sizeof *l);
   for (i = 0; i < g.gl_pathc; i++) {
      l[i] = file_fullpath(g.gl_pathv[i]);
   }
   l[i] = NULL;

   *list = l;

   globfree(&g);
exit:
   free(s);
   return res;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_rmdir --
 *
 *---------------------------------------------------------------------------
 */

int
file_rmdir(const char *path)
{
   int err;

   log_info(LGPFX" rmdir of '%s'.\n", path);

   err = rmdir(path);
   if (err != 0) {
      err = errno;
      log_info(LGPFX" failed to rmdir '%s': %s (%d)\n",
          path, strerror(err), err);
      return err;
   }
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_unlink --
 *
 *---------------------------------------------------------------------------
 */

int
file_unlink(const char *filename)
{
   int err;

   log_info(LGPFX" unlinking '%s'.\n", filename);

   err = unlink(filename);
   if (err != 0 && errno != ENOENT) {
      err = errno;
      log_info(LGPFX" failed to unlink '%s': %s (%d)\n",
          filename, strerror(err), err);
      return err;
   }
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_freedirlist --
 *
 *---------------------------------------------------------------------------
 */

void
file_freedirlist(char **names)
{
   char **n = names;

   if (names == NULL) {
      return;
   }

   while (*n != NULL) {
      free(*n);
      n++;
   }
   free(names);
}


/*
 *---------------------------------------------------------------------------
 *
 * file_listdirectory --
 *
 *---------------------------------------------------------------------------
 */

int
file_listdirectory(const char *directory,
                   char ***namesOut)
{
   char **names;
   size_t nameLen;
   size_t i;
   DIR *dir;
   int res = 0;

   *namesOut = NULL;
   nameLen = 2;

   names = malloc(nameLen * sizeof *names);
   if (names == NULL) {
      return ENOMEM;
   }

   dir = opendir(directory);
   if (dir == NULL) {
      res = errno;
      free(names);
      return res;
   }

   i = 0;
   while (TRUE) {
      struct dirent *ent;

      errno = 0;
      ent = readdir(dir);
      if (errno != 0) {
         log_info(LGPFX" readdir failed: %s (%d)\n",
             strerror(errno), errno);
         break;
      }
      if (ent == NULL) {
         break;
      }
      if (i == nameLen - 2) {
         char **ptr;

         nameLen <<= 1;
         ptr = realloc(names, nameLen * sizeof *names);
         if (ptr == NULL) {
            res = ENOMEM;
            break;
         }
         names = ptr;
      }
      names[i] = strdup(ent->d_name);
      if (names[i] == NULL) {
         res = ENOMEM;
         break;
      }
      names[i + 1] = NULL;
      i++;
   }
   if (res != 0) {
      file_freedirlist(names);
   } else {
      *namesOut = names;
   }
   closedir(dir);
   return res;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_getcwd --
 *
 *---------------------------------------------------------------------------
 */

char *
file_getcwd(void)
{
   return getcwd(NULL, 0);
}


/*
 *---------------------------------------------------------------------------
 *
 * file_rename --
 *
 *---------------------------------------------------------------------------
 */

int
file_rename(const char *src,
            const char *dst)
{
   int res;

   res = rename(src, dst);

   if (res < 0) {
      return errno;
   }

   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_rotate --
 *
 *---------------------------------------------------------------------------
 */

int
file_rotate(const char *filename,
            uint32 n)
{
   char file0[PATH_MAX];
   char file1[PATH_MAX];
   int i;

   ASSERT(n > 0);

   for (i = n - 1; i >= 0; i--) {
      int res;

      snprintf(file0, sizeof file1, "%s.%u", filename, i);
      snprintf(file1, sizeof file1, "%s.%u", filename, i + 1);

      if (!file_exists(file0)) {
         continue;
      }

      if (i == n - 1) {
         res = file_unlink(file0);
      } else {
         res = file_rename(file0, file1);
      }
      if (res != 0) {
         NOT_TESTED();
         return res;
      }
   }
   return file_rename(filename, file0);
}


/*
 *---------------------------------------------------------------------------
 *
 * file_exists --
 *
 *---------------------------------------------------------------------------
 */

bool
file_exists(const char *filename)
{
   struct stat s;

   return stat(filename, &s) != -1;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_pwrite --
 *
 *---------------------------------------------------------------------------
 */

int
file_pwrite(const struct file_descriptor *desc,
            uint64 offset,
            const void *buf,
            size_t len,
            size_t *numWritten)
{
   ssize_t res;

   if (numWritten) {
      *numWritten = 0;
   }

   do {
      res = pwrite(desc->fd, buf, len, offset);
   } while (res == -1 && (errno == EAGAIN || errno == EINTR));

   if (res == -1) {
      int err = errno;
      log_info(LGPFX" failed to pwrite %zu bytes from '%s' at off=%" PRIu64 ": %s (%d)\n",
          len, desc->name, offset, strerror(err), err);
      return err;
   }
   if (numWritten) {
      *numWritten = res;
   }
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_pread --
 *
 *---------------------------------------------------------------------------
 */

int
file_pread(const struct file_descriptor *desc,
           uint64 offset,
           void *buf,
           size_t len,
           size_t *numRead)
{
   ssize_t res;

   if (numRead) {
      *numRead = 0;
   }

   do {
      res = pread(desc->fd, buf, len, offset);
   } while (res == -1 && (errno == EAGAIN || errno == EINTR));

   if (res == -1) {
      int err = errno;
      log_info(LGPFX" failed to pread %zu bytes from '%s' at off=%" PRIu64 ": %s (%d)\n",
          len, desc->name, offset, strerror(err), err);
      return err;
   }
   if (numRead) {
      *numRead = res;
   }
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_getsize --
 *
 *---------------------------------------------------------------------------
 */

int64
file_getsize(const struct file_descriptor *desc)
{
   struct stat s;
   int err;

   err = fstat(desc->fd, &s);
   if (err == -1) {
      err = errno;
      log_info(LGPFX" failed to call fstat() on '%s': %s (%d)\n",
          desc->name, strerror(err), err);
      errno = err;
      return -1;
   }

   return s.st_size;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_open --
 *
 *---------------------------------------------------------------------------
 */

int
file_open(const char *name,
          bool ro,
          bool unbuf,
          struct file_descriptor **descOut)
{
   struct file_descriptor *desc;
   int flags = 0;
   int err;

   log_info(LGPFX" opening  '%s' ro=%u unbuf=%u\n", name, ro, unbuf);

   *descOut = NULL;
   desc = safe_malloc(sizeof *desc);
   desc->fd   = -1;
   desc->name = safe_strdup(name);
   desc->f = NULL;

   if (ro) {
      flags |= O_RDONLY;
   } else {
      flags |= O_RDWR;
   }
#ifdef linux
   if (unbuf) {
      flags |= O_DIRECT;
   }
#endif

   desc->fd = open(name, flags);

   if (desc->fd < 0) {
      err = errno;
      log_info(LGPFX" failed to open: '%s': %s (%d)\n",
          name, strerror(err), err);
      goto exit;
   }

#ifdef __APPLE__
   if (unbuf) {
      err = fcntl(desc->fd, F_NOCACHE, 1);
      if (err == -1) {
         err = errno;
         log_info(LGPFX" failed to fcntl(F_NOCACHE): '%s': %s (%d)\n",
             name, strerror(err), err);
         close(desc->fd);
         goto exit;
      }
   }
#endif

   *descOut = desc;

   return 0;

exit:
   free(desc->name);
   free(desc);
   return err;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_getline --
 *
 *---------------------------------------------------------------------------
 */

int
file_getline(struct file_descriptor *desc,
             char **line)
{
   char str[1024];
   char *s;

   *line = NULL;

   if (desc->f == NULL) {
      desc->f = fdopen(desc->fd, "ro");
   }

   s = fgets(str, sizeof str, desc->f);
   if (s == NULL) {
      return 0;
   }

   *line = strdup(str);
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_mkdir --
 *
 *---------------------------------------------------------------------------
 */

int
file_mkdir(const char *pathname)
{
   int res;

   log_info(LGPFX" creating directory '%s'\n", pathname);

   res = mkdir(pathname, S_IRWXU | S_IRGRP | S_IROTH);

   if (res < 0) {
      int err = errno;
      log_info(LGPFX" failed to create directory: '%s': %s (%d)\n",
          pathname, strerror(err), err);
      return err;
   }
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_create --
 *
 *---------------------------------------------------------------------------
 */

int
file_create(const char *filename)
{
   int fd;

   log_info(LGPFX" creating file '%s'\n", filename);

   fd = open(filename, O_CREAT, S_IRWXU|S_IRGRP|S_IROTH);

   if (fd < 0) {
      int err = errno;
      log_info(LGPFX" failed to create file: '%s': %s (%d)\n",
          filename, strerror(err), err);
      return err;
   }
   close(fd);
   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_truncate --
 *
 *---------------------------------------------------------------------------
 */

int
file_truncate(const struct file_descriptor *desc,
              uint64 offset)
{
   int res;

   log_info(LGPFX" truncating '%s' to size %" PRIu64 "\n", desc->name, offset);

   res = ftruncate(desc->fd, offset);
   if (res != 0) {
      res = errno;
      log_info(LGPFX" failed to truncate: %s (%d)\n", strerror(res), res);
   }

   return res;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_fullpath --
 *
 *---------------------------------------------------------------------------
 */

char *
file_fullpath(const char *path)
{
   return realpath(path, NULL);
}


/*
 *---------------------------------------------------------------------------
 *
 * file_sync --
 *
 *---------------------------------------------------------------------------
 */

int
file_sync(const struct file_descriptor *desc)
{
   int err;

   ASSERT(file_valid(desc));

   err = fsync(desc->fd);
   if (err != 0) {
      err = errno;
      log_warn(LGPFX" Failed to fsync: %s\n", strerror(err));
   }
   return err;
}


/*
 *---------------------------------------------------------------------------
 *
 * file_getname --
 *
 *---------------------------------------------------------------------------
 */

char *
file_getname(const char *path)
{
   char *f;

   f = strrchr(path, '/');

   if (f == NULL) {
      NOT_TESTED();
      return safe_strdup(path);
   } else {
      return safe_strdup(f + 1);
   }
}


/*
 *---------------------------------------------------------------------------
 *
 * file_close --
 *
 *---------------------------------------------------------------------------
 */

int
file_close(struct file_descriptor *desc)
{
   int err;

   ASSERT(file_valid(desc));

   err = close(desc->fd);
   if (err != 0) {
      err = errno;
      log_info(LGPFX" failed to close '%s': %s (%d)\n",
          desc->name, strerror(err), err);
   }
   if (desc->f) {
      fclose(desc->f);
   }
   free(desc->name);
   free(desc);
   return err;
}
